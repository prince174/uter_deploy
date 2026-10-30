/* Disposable CI fault injection only: abort exactly before replacing state.json
 * in the explicitly selected synthetic installation directory. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    const char *home = getenv("UTER_CI_FAULT_HOME");
    char link[64], resolved[4096];
    if (home && newpath && strcmp(newpath, "state.json") == 0 && newdirfd >= 0) {
        int n = snprintf(link, sizeof(link), "/proc/self/fd/%d", newdirfd);
        if (n > 0 && (size_t)n < sizeof(link)) {
            ssize_t length = readlink(link, resolved, sizeof(resolved)-1);
            if (length > 0) {
                resolved[length] = '\0';
                if (strcmp(resolved, home) == 0) _exit(88);
            }
        }
    }
    int (*original)(int,const char*,int,const char*) = dlsym(RTLD_NEXT,"renameat");
    if (!original) _exit(89);
    return original(olddirfd,oldpath,newdirfd,newpath);
}
