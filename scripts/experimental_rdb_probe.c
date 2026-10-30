/* Synthetic-data-only librdb feasibility probe; not a backup or recovery tool. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "librdb-api.h"

typedef struct {
    int db, selected, found, items, invalid;
    long long expiry;
} Probe;

static void silent_log(RdbLogLevel level, const char *message) {
    (void) level; (void) message;
}

static RdbStatus read_stdin(void *unused, void *buffer, size_t size) {
    (void) unused;
    return fread(buffer, 1, size, stdin) == size ? RDB_STATUS_OK : RDB_STATUS_ERROR;
}

static RdbRes new_db(RdbParser *p, void *data, int db) {
    (void) p;
    ((Probe *) data)->db = db;
    return RDB_OK;
}

static RdbRes new_key(RdbParser *p, void *data, RdbBulk key, RdbKeyInfo *info) {
    Probe *probe = data;
    static const char wanted[] = "sess:synthetic";
    probe->selected = probe->db == 2 && RDB_bulkLen(p, key) == sizeof(wanted) - 1 &&
                      memcmp(key, wanted, sizeof(wanted) - 1) == 0;
    if (probe->selected) {
        probe->found++;
        if (info->expiretime != probe->expiry || info->dataType != RDB_DATA_TYPE_LIST)
            probe->invalid = 1;
    }
    return RDB_OK;
}

static RdbRes list_item(RdbParser *p, void *data, RdbBulk item) {
    Probe *probe = data;
    static const char first[] = "alpha";
    static const char second[] = {'b', 'e', 't', 'a', '\0', 'x'};
    if (!probe->selected) return RDB_OK;
    const char *expected = probe->items == 0 ? first : second;
    size_t size = probe->items == 0 ? sizeof(first) - 1 : sizeof(second);
    if (probe->items >= 2 || RDB_bulkLen(p, item) != size || memcmp(item, expected, size))
        probe->invalid = 1;
    probe->items++;
    return RDB_OK;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char *end = NULL;
    long long expiry = strtoll(argv[1], &end, 10);
    if (!end || *end || expiry <= 0) return 2;
    Probe probe = {.db = -1, .expiry = expiry};
    RdbParser *parser = RDB_createParserRdb(NULL);
    if (!parser) return 2;
    RDB_setLogger(parser, silent_log);
    RDB_setDeepIntegCheck(parser, 1);
    RdbHandlersDataCallbacks cb = {.handleNewDb = new_db, .handleNewKey = new_key,
                                   .handleListItem = list_item};
    if (!RDB_createReaderRdb(parser, read_stdin, NULL, NULL) ||
        !RDB_createHandlersData(parser, &cb, &probe, NULL)) {
        RDB_deleteParser(parser);
        return 2;
    }
    RdbStatus status = RDB_parse(parser);
    RdbRes error = RDB_getErrorCode(parser);
    int ok = status == RDB_STATUS_OK && RDB_getState(parser) == RDB_STATE_ENDED &&
             probe.found == 1 && probe.items == 2 && !probe.invalid;
    RDB_deleteParser(parser);
    return ok ? 0 : error == RDB_ERR_CHECKSUM_FAILURE ? 3 : 1;
}
