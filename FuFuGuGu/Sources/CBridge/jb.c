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
#include <xpc/xpc.h>
#include <bootstrap.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <sys/stat.h>
#include <xpc/xpc.h>

#include "CodeSignature.h"

#include "init.h"

#define INJECT_KEY "DYLD_INSERT_LIBRARIES"
#define INJECT_VALUE "/usr/lib/jbinjector.dylib"
#define INJECT_KEY2 "DYLD_AMFI_FAKE"
#define INJECT_VALUE2 "0xff"

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacment,_replacee) \
__attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };
#endif

int xpc_receive_mach_msg(void *a1, void *a2, void *a3, void *a4, xpc_object_t *a5, void *a6, void *a7, void *a8);
int xpc_pipe_routine_reply(xpc_object_t reply);
xpc_object_t xpc_mach_send_create_with_disposition(mach_port_t port, int disposition);
void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);

#pragma clang diagnostic ignored "-Wavailability"
pid_t audit_token_to_pid(audit_token_t atoken) API_AVAILABLE(ios(15));
int audit_token_to_pidversion(audit_token_t atoken) API_AVAILABLE(ios(15));

void swift_reboot_hook(int console_fd);

typedef xpc_object_t xpc_pipe_t;
xpc_pipe_t xpc_pipe_create_from_port(mach_port_t port, uint64_t flags);
int xpc_pipe_routine(xpc_pipe_t pipe, xpc_object_t request, xpc_object_t* reply);

mach_msg_header_t* dispatch_mach_msg_get_msg(void *message, size_t *size_ptr);

void swift_fix_launch_daemons(xpc_object_t dict);

xpc_pipe_t gJBDPipe = NULL;

#define assure(cond) do {if (!(cond)){err = __LINE__; goto error;}}while(0)

const char* xpcproxy_blacklist[] = {
    "diagnosticd",  // syslog
    "logd",         // syslog
    "MTLCompilerService",     // ?_?
    "mapspushd",              // stupid Apple Maps
    "nsurlsessiond",          // stupid Reddit app
    "applecamerad",
    "videosubscriptionsd",    // u_u
    "notifyd",
    "OTAPKIAssetTool",        // h_h
    "cfprefsd",               // o_o
    "com.apple.FileProvider.LocalStorage",  // seems to crash from oosb r/w etc
    "amfid",        // don't inject into amfid on corellium
    "net",
    "wifi",
    "report",
    "fseventsd",
    "osanalyticshelper",
    "BlastDoor",
    "wifid",
    NULL
};

int isBlacklisted(const char *name) {
    for (const char **bl = xpcproxy_blacklist; *bl; bl++) {
        if (strstr(name, *bl)) {
            return 1;
        }
    }
    
    return 0;
}

#define safeClose(fd) do{if ((fd) != -1){close(fd); fd = -1;}}while(0)
#define safeFree(buf) do{if ((buf)){free(buf); buf = NULL;}}while(0)
#define assure(cond) do {if (!(cond)){err = __LINE__; goto error;}}while(0)

extern void swift_init(int console_fd, mach_port_t servicePort, mach_port_t *XPCServicePort);
extern int isTokenBlacklisted(audit_token_t au);
extern int sysctlbyname_get_data_np(const char *name, void **buf, size_t *len);

uint64_t gUserReturnDidHappen;

mach_port_t bp = 0;
mach_port_t servicePort = 0;
bool didRegisterJBDService = false;

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
            } else if (strcmp(name, "com.apple.nfcd.hwmanager") == 0) {
                return 0;
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
        
        // Clear bootstrap port (stashd will set it again)
        task_set_bootstrap_port(mach_task_self_, MACH_PORT_NULL);
        
        // Call swift hook
        swift_reboot_hook(fd_console);
        
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

xpc_object_t my_xpc_dictionary_get_value(xpc_object_t dict, const char *key) {
    xpc_object_t retval = xpc_dictionary_get_value(dict, key);
    if (strcmp(key, "LaunchDaemons") == 0) {
        swift_fix_launch_daemons(retval);
    }
    
    return retval;
}
DYLD_INTERPOSE(my_xpc_dictionary_get_value, xpc_dictionary_get_value);

void injectDylibToEnvVars(char *const envp[], char ***outEnvp, char **freeme) {
    bool key1Seen = false;
    bool key2Seen = false;
    
    size_t envCount = 0;
    if (envp) {
        while (envp[envCount] != NULL) {
            envCount++;
        }
    }
    
    char **newEnvp = malloc((envCount + 3) * sizeof(char*));
    memset(newEnvp, 0, (envCount + 3) * sizeof(char*));
    
    for (size_t i = 0; i < envCount; i++) {
        if (!key1Seen && !strncmp(envp[i], INJECT_KEY "=", sizeof(INJECT_KEY))) {
            if (strncmp(envp[i], INJECT_KEY "=" INJECT_VALUE ":", sizeof(INJECT_KEY "=" INJECT_VALUE)) && strcmp(envp[i], INJECT_KEY "=" INJECT_VALUE)) {
                char *var = malloc(strlen(envp[i]) + sizeof(INJECT_VALUE ":"));
                
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Wdeprecated"
                sprintf(var, "%s=%s:%s", INJECT_KEY, INJECT_VALUE, envp[i] + sizeof(INJECT_KEY));
                #pragma clang diagnostic pop
                
                freeme[0] = var;
                newEnvp[i] = var;
                key1Seen = true;
                continue;
            }
        } else if (!key2Seen && !strncmp(envp[i], INJECT_KEY2 "=", sizeof(INJECT_KEY2))) {
            if (strcmp(envp[i], INJECT_KEY2 "=" INJECT_VALUE2)) {
                newEnvp[i] = INJECT_KEY2 "=" INJECT_VALUE2;
                key2Seen = true;
                continue;
            }
        }
        
        newEnvp[i] = envp[i];
    }
    
    if (!key1Seen) {
        newEnvp[envCount] = INJECT_KEY "=" INJECT_VALUE;
        envCount++;
    }
    
    if (!key2Seen) {
        newEnvp[envCount] = INJECT_KEY2 "=" INJECT_VALUE2;
    }
    
    *outEnvp = newEnvp;
}

#pragma mark lib

int trustCDHash(const uint8_t *hash, size_t hashSize, uint8_t hashType){
    int err = 0;
    if (true){
        xpc_object_t req = NULL;
        xpc_object_t rsp = NULL;
        //
        assure(req = xpc_dictionary_create(NULL, NULL, 0));
        xpc_dictionary_set_string(req, "action", "trustcdhash");
        xpc_dictionary_set_data(req, "hashdata", hash, hashSize);
        xpc_dictionary_set_uint64(req, "hashtype", hashType);
        assure(!xpc_pipe_routine(gJBDPipe, req, &rsp));
        err = (int)xpc_dictionary_get_uint64(rsp, "status");
    error:
        if (req){
            xpc_release(req); req = NULL;
        }
        if (rsp){
            xpc_release(rsp); rsp = NULL;
        }
    }
    return err;
}

int giveCSDEBUGToPid(pid_t tgtpid, int forceDisablePAC, int *pacDisabled){
    int err = 0;
    if (true){
        xpc_object_t req = NULL;
        xpc_object_t rsp = NULL;
        //
        assure(req = xpc_dictionary_create(NULL, NULL, 0));
        xpc_dictionary_set_string(req, "action", "csdebug");
        xpc_dictionary_set_uint64(req, "pid", tgtpid);
        if (forceDisablePAC) {
            xpc_dictionary_set_uint64(req, "forceDisablePAC", 1);
        }
        assure(!xpc_pipe_routine(gJBDPipe, req, &rsp));
        xpc_object_t val = xpc_dictionary_get_value(rsp, "status");
        if (val) {
            err = (int)xpc_dictionary_get_uint64(rsp, "status");
        } else {
            assure(0);
        }
        
        if (err == 0 && pacDisabled)
            *pacDisabled = (int) xpc_dictionary_get_uint64(rsp, "pacDisabled");
    error:
        if (req){
            xpc_release(req); req = NULL;
        }
        if (rsp){
            xpc_release(rsp); rsp = NULL;
        }
    }
    return err;
}

int fixprot(pid_t pid, xpc_object_t start, xpc_object_t end, uint64_t forceExec) {
    int err = 0;
    if (gJBDPipe){
        xpc_object_t req = NULL;
        xpc_object_t rsp = NULL;
        assure(req = xpc_dictionary_create(NULL, NULL, 0));
        xpc_dictionary_set_string(req, "action", "fixprot");
        xpc_dictionary_set_uint64(req, "pid", pid);
        xpc_dictionary_set_value(req, "start", start);
        xpc_dictionary_set_value(req, "end", end);
        if (forceExec) {
            xpc_dictionary_set_uint64(req, "forceExec", 1);
        }
        assure(!xpc_pipe_routine(gJBDPipe, req, &rsp));
        err = (int)xpc_dictionary_get_uint64(rsp, "status");
    error:
        if (req){
            xpc_release(req); req = NULL;
        }
        if (rsp){
            xpc_release(rsp); rsp = NULL;
        }
    }
    return err;
}

int my_posix_spawn_common(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], int is_spawnp){
    int fd_console = open("/dev/console",O_RDWR,0);
    dprintf(fd_console, "spawning %s", path);
    for (size_t i = 0; argv[i]; i++) {
        dprintf(fd_console, " %s", argv[i]);
    }
    
    if (attrp) {
        short flags = 0;
        posix_spawnattr_getflags(attrp, &flags);
        if (flags & POSIX_SPAWN_SETEXEC) {
            // launchd re-execing itself
            // Call our hook instead
            my_kill(-1, SIGKILL);
            return -1;
        }
    }
    
    int ret = 0;
    char **out = NULL;
    char *freeme = NULL;
    trustCDHashesForBinaryPathSimple(path);
    
    injectDylibToEnvVars(envp, &out, &freeme);
    
    dprintf(fd_console, "\n");
    close(fd_console);
    
    if (strcmp(path, "/usr/libexec/xpcproxy") == 0) {
        if (argv[1] != NULL && !isBlacklisted(argv[1]))
            if (out)
                envp = out;
    } else {
        if (out)
            envp = out;
    }
    
    host_set_special_port(mach_host_self(), HOST_CLOSURED_PORT, servicePort);
    
    if (is_spawnp)
        ret = posix_spawnp(pid, path, file_actions, attrp, argv, envp);
    else
        ret = posix_spawn(pid, path, file_actions, attrp, argv, envp);
    
error:
    safeFree(out);
    safeFree(freeme);
    return ret;
}

int my_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]){
    return my_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, 0);
}
DYLD_INTERPOSE(my_posix_spawn, posix_spawn);

int my_posix_spawnp(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]){
    return my_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, 1);
}
DYLD_INTERPOSE(my_posix_spawnp, posix_spawnp);

#define FUFUGUGU_MSG_MAGIC 0x4675467547754775

#define FUFUGUGU_ACTION_CSDEBUG        0
#define FUFUGUGU_ACTION_TRUST          1
#define FUFUGUGU_ACTION_FIXPROT_SINGLE 2

struct FuFuGuGuMsg {
    mach_msg_header_t hdr;
    uint64_t          magic;
    uint64_t          action;
};

struct FuFuGuGuMsgCSDebug {
    struct FuFuGuGuMsg base;
    uint64_t           pid;
    uint64_t           forceDisablePAC;
};

struct FuFuGuGuMsgTrust {
    struct FuFuGuGuMsg base;
    uint64_t           hashType;
    uint64_t           hashLen;
    uint8_t            hash[0];
};

struct FuFuGuGuMsgFixprotSingle {
    struct FuFuGuGuMsg base;
    uint64_t           pid;
    void               *address;
    size_t             size;
};

struct FuFuGuGuMsgReply {
    mach_msg_header_t hdr;
    uint64_t          magic;
    uint64_t          action;
    uint64_t          status;
};

struct FuFuGuGuMsgReplyCSDebug {
    struct FuFuGuGuMsgReply base;
    int pacDisabled;
};

void handle_FuFuGuGu_msg(struct FuFuGuGuMsg *msg) {
    // Note: We never own the message
    //       If we need to take ownership of some port, either set it to zero or copy the right
    int err = 999;
    char rplBuf[1024];
    bzero(rplBuf, sizeof(rplBuf));
    
    struct FuFuGuGuMsgReply *rpl = (struct FuFuGuGuMsgReply*) rplBuf;
    rpl->hdr.msgh_size = sizeof(struct FuFuGuGuMsgReply);
    rpl->magic  = msg->magic;
    rpl->action = msg->action;
    
    switch (msg->action) {
        case FUFUGUGU_ACTION_CSDEBUG: {
            assure(msg->hdr.msgh_size >= sizeof(struct FuFuGuGuMsgCSDebug));
            
            struct FuFuGuGuMsgCSDebug *csdebug = (struct FuFuGuGuMsgCSDebug*) msg;
            struct FuFuGuGuMsgReplyCSDebug *csdebugReply = (struct FuFuGuGuMsgReplyCSDebug*) msg;
            csdebugReply->base.hdr.msgh_size = sizeof(struct FuFuGuGuMsgReplyCSDebug);
            
            err = giveCSDEBUGToPid((pid_t) csdebug->pid, (int) csdebug->forceDisablePAC, &csdebugReply->pacDisabled);
            break;
        }
        
        case FUFUGUGU_ACTION_TRUST: {
            assure(msg->hdr.msgh_size >= sizeof(struct FuFuGuGuMsgTrust));
            
            struct FuFuGuGuMsgTrust *trust = (struct FuFuGuGuMsgTrust*) msg;
            assure(msg->hdr.msgh_size >= (sizeof(struct FuFuGuGuMsgTrust) + trust->hashLen));
            
            err = trustCDHash(trust->hash, trust->hashLen, (uint8_t) trust->hashType);
            break;
        }
            
        case FUFUGUGU_ACTION_FIXPROT_SINGLE: {
            assure(msg->hdr.msgh_size >= sizeof(struct FuFuGuGuMsgFixprotSingle));
            
            struct FuFuGuGuMsgFixprotSingle *fixprotMsg = (struct FuFuGuGuMsgFixprotSingle*) msg;
            
            xpc_object_t start = xpc_uint64_create((uint64_t) fixprotMsg->address);
            xpc_object_t end = xpc_uint64_create((uint64_t) fixprotMsg->address + fixprotMsg->size);
            
            xpc_object_t startAr = xpc_array_create(NULL, 0);
            xpc_object_t endAr   = xpc_array_create(NULL, 0);
            
            xpc_array_append_value(startAr, start);
            xpc_array_append_value(endAr, end);
            
            err = fixprot((pid_t) fixprotMsg->pid, startAr, endAr, 0);
            
            xpc_release(endAr);
            xpc_release(startAr);
            xpc_release(end);
            xpc_release(start);
            break;
        }
        
        default:
            break;
    }
    
error:
    rpl->status = err;
    
    if (MACH_PORT_VALID(msg->hdr.msgh_remote_port) && MACH_MSGH_BITS_REMOTE(msg->hdr.msgh_bits) != 0) {
        // Send reply
        uint32_t bits = MACH_MSGH_BITS_REMOTE(msg->hdr.msgh_bits);
        if (bits == MACH_MSG_TYPE_COPY_SEND)
            bits = MACH_MSG_TYPE_MOVE_SEND;
        
        rpl->hdr.msgh_bits = MACH_MSGH_BITS(bits, 0);
        // size already set
        rpl->hdr.msgh_remote_port  = msg->hdr.msgh_remote_port;
        rpl->hdr.msgh_local_port   = 0;
        rpl->hdr.msgh_voucher_port = 0;
        rpl->hdr.msgh_id           = msg->hdr.msgh_id + 100;
        
        kern_return_t kr = mach_msg_send(&rpl->hdr);
        if (kr == KERN_SUCCESS /*|| kr == MACH_SEND_INVALID_MEMORY || kr == MACH_SEND_INVALID_RIGHT || kr == MACH_SEND_INVALID_TYPE || kr == MACH_SEND_MSG_TOO_SMALL*/) {
            // All of these imply the message was either sent or destroyed
            // -> Kill the reply port in the original message as we certainly got rid of the associated right
            msg->hdr.msgh_remote_port = 0;
            msg->hdr.msgh_bits = msg->hdr.msgh_bits & ~MACH_MSGH_BITS_REMOTE_MASK;
        }
    }
}

int my_xpc_receive_mach_msg(void *msg, void *a2, void *a3, void *a4, xpc_object_t *object_out, void *a6, void *a7, void *a8) {
    size_t msgBufSize = 0;
    struct FuFuGuGuMsg *fMsg = (struct FuFuGuGuMsg*) dispatch_mach_msg_get_msg(msg, &msgBufSize);
    if (fMsg != NULL && msgBufSize >= sizeof(mach_msg_header_t)) {
        size_t msgSize = fMsg->hdr.msgh_size;
        if (msgSize <= msgBufSize && msgSize >= sizeof(struct FuFuGuGuMsg) && fMsg->magic == FUFUGUGU_MSG_MAGIC) {
            handle_FuFuGuGu_msg(fMsg);
            
            // Pass the message to xpc_receive_mach_msg anyway, it will get rid of it for us
        }
    }
    
    int err = xpc_receive_mach_msg(msg, a2, a3, a4, object_out, a6, a7, a8);
    if (err == 0 && object_out && *object_out && servicePort) {
        if (xpc_get_type(*object_out) == XPC_TYPE_DICTIONARY) {
            xpc_object_t dict = *object_out;
            uint64_t type = xpc_dictionary_get_uint64(dict, "type");
            if (type == 7) {
                const char *name = xpc_dictionary_get_string(dict, "name");
                if (name && strcmp(name, "jb-global-jbd") == 0) {
                    xpc_object_t port = xpc_mach_send_create_with_disposition(servicePort, MACH_MSG_TYPE_MAKE_SEND);
                    if (port) {
                        xpc_object_t *reply = xpc_dictionary_create_reply(dict);
                        if (reply) {
                            xpc_dictionary_set_value(reply, "port", port);
                            xpc_release(port);
                            
                            audit_token_t token;
                            xpc_dictionary_get_audit_token(dict, &token);
                            
                            pid_t pid = audit_token_to_pid(token);
                            int execcnt = audit_token_to_pidversion(token);
                            
                            xpc_dictionary_set_uint64(reply, "req_pid", (uint64_t) pid);
                            xpc_dictionary_set_uint64(reply, "rec_execcnt", (uint64_t) execcnt);
                            
                            xpc_pipe_routine_reply(reply);
                            xpc_release(reply);
                            xpc_release(dict);
                            
                            return 22;
                        }
                        
                        xpc_release(port);
                    }
                }
            }
        }
    }
    
    return err;
}
DYLD_INTERPOSE(my_xpc_receive_mach_msg, xpc_receive_mach_msg);

__attribute__((constructor))
static void customConstructor(int argc, const char **argv){
    int fd_console = open("/dev/console",O_RDWR,0);
    dprintf(fd_console,"================ Hello from Stage 2 dylib ================ \n");
    
    dprintf(fd_console,"I can haz bootstrap port?\n");
    kern_return_t kr = task_get_bootstrap_port(mach_task_self_, &bp);
    if (kr == KERN_SUCCESS) {
        if (!MACH_PORT_VALID(bp)) {
            dprintf(fd_console,"No bootstrap port, no KRW, nothing I can do, goodbye!\n");
            return;
        } else {
            dprintf(fd_console,"Got bootstrap port!\n");
            task_set_bootstrap_port(mach_task_self_, 0);
        }
    } else {
        dprintf(fd_console,"No task_get_bootstrap_port???\n");
        dprintf(fd_console,"No bootstrap port, no KRW, nothing I can do, goodbye!\n");
        return;
    }
    
    swift_init(fd_console, bp, &servicePort);
    
    mach_port_insert_right(mach_task_self_, servicePort, servicePort, MACH_MSG_TYPE_MAKE_SEND);
    gJBDPipe = xpc_pipe_create_from_port(servicePort, 0);
    
    dprintf(fd_console,"========= Goodbye from Stage 2 dylib constructor ========= \n");
    close(fd_console);
}

void dmb_sy(void) {
    asm volatile("dmb sy");
}
