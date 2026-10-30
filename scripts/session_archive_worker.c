#define _POSIX_C_SOURCE 200809L
/* Offline RDB session extractor. This file is not wired into deployment.
 * stdout is a binary private pipe, never a terminal or a log sink. Caller MUST
 * authenticate the complete input before supplying it and encrypt stdout.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "librdb-api.h"

#define MAX_BULK (16U * 1024U * 1024U)

typedef struct {
    int db;
    int selected;
    uint64_t keys;
} Context;

typedef struct {
    unsigned char tail[8];
    uint64_t count;
} Reader;

static void silent_logger(RdbLogLevel level, const char *message) {
    (void) level;
    (void) message;
}

static RdbStatus read_stdin(void *data, void *buffer, size_t size) {
    Reader *reader = data;
    if (fread(buffer, 1, size, stdin) != size) return RDB_STATUS_ERROR;
    const unsigned char *bytes = buffer;
    for (size_t i = 0; i < size; ++i) {
        reader->tail[reader->count % 8] = bytes[i];
        reader->count++;
    }
    return RDB_STATUS_OK;
}

static int write_bytes(const void *data, size_t length) {
    return fwrite(data, 1, length, stdout) == length;
}

static int write_u64(uint64_t value) {
    unsigned char bytes[8];
    for (int i = 7; i >= 0; i--) {
        bytes[i] = (unsigned char) (value & 0xffU);
        value >>= 8;
    }
    return write_bytes(bytes, sizeof(bytes));
}

static RdbRes on_db(RdbParser *parser, void *data, int db) {
    (void) parser;
    if (db < 0) return RDB_ERR_CANCEL_PARSING;
    ((Context *) data)->db = db;
    return RDB_OK;
}

static RdbRes on_key(RdbParser *parser, void *data, RdbBulk key, RdbKeyInfo *info) {
    Context *ctx = data;
    size_t length = RDB_bulkLen(parser, key);
    ctx->selected = length >= 5 && memcmp(key, "sess:", 5) == 0;
    if (!ctx->selected) return RDB_OK;
    if (ctx->db < 0 || length > MAX_BULK || info->dataType != RDB_DATA_TYPE_LIST ||
        info->expiretime < -1 || ctx->keys == UINT64_MAX)
        return RDB_ERR_CANCEL_PARSING;
    ctx->keys++;
    if (!write_bytes("K", 1) || !write_u64((uint64_t) ctx->db) ||
        !write_u64((uint64_t) info->expiretime) || !write_u64(length) ||
        !write_bytes(key, length)) return RDB_ERR_CANCEL_PARSING;
    return RDB_OK;
}

static RdbRes on_item(RdbParser *parser, void *data, RdbBulk item) {
    Context *ctx = data;
    if (!ctx->selected) return RDB_OK;
    size_t length = RDB_bulkLen(parser, item);
    if (length > MAX_BULK || !write_bytes("V", 1) || !write_u64(length) ||
        !write_bytes(item, length)) return RDB_ERR_CANCEL_PARSING;
    return RDB_OK;
}

static RdbRes on_end(RdbParser *parser, void *data) {
    (void) parser;
    Context *ctx = data;
    if (ctx->selected && !write_bytes("E", 1)) return RDB_ERR_CANCEL_PARSING;
    ctx->selected = 0;
    return RDB_OK;
}

int main(void) {
    if (isatty(STDIN_FILENO) || isatty(STDOUT_FILENO) ||
        unsetenv("LIBRDB_DEBUG_DATA") != 0 || unsetenv("LIBRDB_SIM_WAIT_MORE_DATA") != 0)
        return 2;
    Context ctx = {.db = -1};
    Reader reader = {0};
    RdbParser *parser = RDB_createParserRdb(NULL);
    if (!parser) return 2;
    RDB_setLogger(parser, silent_logger);
    RDB_setDeepIntegCheck(parser, 1);
    RdbHandlersDataCallbacks cb = {.handleNewDb = on_db, .handleNewKey = on_key,
                                   .handleListItem = on_item, .handleEndKey = on_end};
    if (!RDB_createReaderRdb(parser, read_stdin, &reader, NULL) ||
        !RDB_createHandlersData(parser, &cb, &ctx, NULL) ||
        !write_bytes("UTSA1\0", 6)) {
        RDB_deleteParser(parser);
        return 2;
    }
    RdbStatus result = RDB_parse(parser);
    int nonzero_checksum = 0;
    for (size_t i = 0; i < sizeof(reader.tail); ++i)
        nonzero_checksum |= reader.tail[i];
    int ok = result == RDB_STATUS_OK && RDB_getState(parser) == RDB_STATE_ENDED &&
             reader.count >= 8 && nonzero_checksum && fgetc(stdin) == EOF && !ferror(stdin) &&
             write_bytes("Z", 1) && write_u64(ctx.keys) && fflush(stdout) == 0;
    RDB_deleteParser(parser);
    return ok ? 0 : 1;
}
