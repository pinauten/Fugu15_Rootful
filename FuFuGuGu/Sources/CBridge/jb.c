#include <stdarg.h>
#include <string.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <spawn.h>
#include <sys/mount.h>

#include "init.h"

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacment,_replacee) \
__attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };
#endif

extern void swift_init(int console_fd);
extern int isTokenBlacklisted(audit_token_t au);
extern int sysctlbyname_get_data_np(const char *name, void **buf, size_t *len);

mach_port_t bp = 0;

int sandbox_check_by_audit_token(audit_token_t au, const char *operation, int sandbox_filter_type, ...);
int my_sandbox_check_by_audit_token(audit_token_t au, const char *operation, int sandbox_filter_type, ...) {
    va_list a;
    va_start(a, sandbox_filter_type);
    const char *name = va_arg(a, const char *);
    const void *arg2 = va_arg(a, void *);
    const void *arg3 = va_arg(a, void *);
    const void *arg4 = va_arg(a, void *);
    const void *arg5 = va_arg(a, void *);
    const void *arg6 = va_arg(a, void *);
    const void *arg7 = va_arg(a, void *);
    const void *arg8 = va_arg(a, void *);
    const void *arg9 = va_arg(a, void *);
    const void *arg10 = va_arg(a, void *);
    va_end(a);
    if (name && operation) {
        if (strcmp(operation, "mach-lookup") == 0) {
            if (strncmp((char *)name, "jb-global-", sizeof("jb-global-")-1) == 0) {
                if (!isTokenBlacklisted(au)) {
                  return 0;
                }
            }
        }
    }
    return sandbox_check_by_audit_token(au, operation, sandbox_filter_type, name, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}
DYLD_INTERPOSE(my_sandbox_check_by_audit_token, sandbox_check_by_audit_token);

extern char **environ;

int my_kill(pid_t pid, int sig) {
    if (pid == -1 && sig == SIGKILL){
        int fd_console = open("/dev/console", O_RDWR, 0);
        dprintf(fd_console, "Launchd is about to restart userspace (hopefully!), doing execve...\n");
        if (bp != 0) {
            kern_return_t kr = task_set_bootstrap_port(mach_task_self_, bp);
            if (kr != KERN_SUCCESS) {
                dprintf(fd_console, "Stashed jailbreakd port!\n");
            } else {
                dprintf(fd_console, "No task_set_bootstrap_port for you...\n");
            }
        } else {
            dprintf(fd_console, "No bootstrap port - let's hope it's set it already...\n");
        }
        
        setenv("XPC_USERSPACE_REBOOTED", "1", 1);
        setenv("DYLD_INSERT_LIBRARIES", "/usr/lib/libFuFuGuGu.dylib", 1);
        setenv("DYLD_AMFI_FAKE", "0xFF", 1);
        
        close(fd_console);
        
        uint32_t val = 1;
        sysctlbyname("vm.shared_region_pivot", 0LL, 0LL, &val, 4uLL);
        
        char * const argv[] = { "/sbin/launchd", NULL };
        execve("/sbin/launchd", argv, environ);
        return 0;
    }
    return kill(pid, sig);
}
DYLD_INTERPOSE(my_kill, kill);

int posix_spawn_common(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *act, const posix_spawnattr_t * __restrict attr, char *const argv[__restrict], char *const envp[__restrict], int isSpawnP) {
    if (isSpawnP) {
        return posix_spawnp(pid, path, act, attr, argv, envp);
    } else {
        return posix_spawn(pid, path, act, attr, argv, envp);
    }
}

int my_posix_spawn(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *act, const posix_spawnattr_t * __restrict attr, char *const argv[__restrict], char *const envp[__restrict]) {
    return posix_spawn_common(pid, path, act, attr, argv, envp, 0);
}
DYLD_INTERPOSE(my_posix_spawn, posix_spawn);

int my_posix_spawnp(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *act, const posix_spawnattr_t * __restrict attr, char *const argv[__restrict], char *const envp[__restrict]) {
    return posix_spawn_common(pid, path, act, attr, argv, envp, 1);
}
DYLD_INTERPOSE(my_posix_spawnp, posix_spawnp);

__attribute__((constructor))
static void customConstructor(int argc, const char **argv){
    int fd_console = open("/dev/console",O_RDWR,0);
    dprintf(fd_console,"================ Hello from Stage 2 dylib ================ \n");
    
    dprintf(fd_console,"I can haz bootstrap port?\n");
    kern_return_t kr = task_get_bootstrap_port(mach_task_self_, &bp);
    if (kr == KERN_SUCCESS) {
        if (!MACH_PORT_VALID(bp)) {
            dprintf(fd_console,"No bootstrap port for you...\n");
        } else {
            dprintf(fd_console,"Got bootstrap port!\n");
        }
    } else {
        dprintf(fd_console,"No task_get_bootstrap_port???\n");
    }
    
    // XXX: Should send message here I guess?
    
    swift_init(fd_console);

    dprintf(fd_console,"========= Goodbye from Stage 2 dylib constructor ========= \n");
    close(fd_console);
}
