/* Disposable CI fault injection only. Exit after exactly one selected unlink
 * inside the explicitly named synthetic installation; do not print any data. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int unlinkat(int dirfd, const char *path, int flags) {
    int (*original)(int,const char*,int) = dlsym(RTLD_NEXT,"unlinkat");
    if (!original) _exit(90);
    const char *home=getenv("UTER_CI_FAULT_HOME"), *selected=getenv("UTER_CI_FAULT_ENTRY");
    int target=selected && path && strcmp(path,selected)==0 &&
        (!strcmp(selected,"compose-fence-plan.json") ||
         !strcmp(selected,"compose-fenced-target-result.json") ||
         !strcmp(selected,"redis-fence-operation.json"));
    if (home && target && dirfd>=0) {
        char link[64],resolved[4096];
        int n=snprintf(link,sizeof(link),"/proc/self/fd/%d",dirfd);
        if (n>0 && (size_t)n<sizeof(link)) {
            ssize_t length=readlink(link,resolved,sizeof(resolved)-1);
            if (length>0) {
                resolved[length]='\0';
                if (!strcmp(resolved,home)) {
                    int result=original(dirfd,path,flags);
                    if (result==0) { kill(getpid(),SIGKILL); _exit(89); }
                    return result;
                }
            }
        }
    }
    return original(dirfd,path,flags);
}
