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

xpc_pipe_t gJBDPipe = NULL;

void *my_malloc(size_t sz) {
    int fd_console = open("/dev/console",O_RDWR,0);
    void *res = malloc(sz);
    dprintf(fd_console, "malloc %zu -> %p\n", sz, res);
    usleep(10000);
    close(fd_console);
    
    return res;
}

//#define free(ptr) {int fd_console = open("/dev/console",O_RDWR,0); dprintf(fd_console, "Freeing %p\n", ptr); usleep(10000); free(ptr); close(fd_console);}
//#define malloc my_malloc

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
        /*xpc_object_t programArguments = xpc_array_create(NULL, 0);
        xpc_array_append_value(programArguments, xpc_string_create("/sbin/babyd"));
        
        xpc_object_t submitJob = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_bool(submitJob, "KeepAlive", false);
        xpc_dictionary_set_bool(submitJob, "RunAtLoad", true);
        xpc_dictionary_set_string(submitJob, "UserName", "root");
        xpc_dictionary_set_string(submitJob, "Program", "/sbin/babyd");
        xpc_dictionary_set_string(submitJob, "Label", "de.pinauten.babyd");
        xpc_dictionary_set_value(submitJob, "ProgramArguments", programArguments);
        
        xpc_dictionary_set_value(retval, "/System/Library/LaunchDaemons/de.pinauten.babyd.plist", submitJob);*/
    }
    
    return retval;
}
DYLD_INTERPOSE(my_xpc_dictionary_get_value, xpc_dictionary_get_value);

void injectDylibToEnvVars(char *const envp[], char ***outEnvp, char **freeme) {
    bool key1Seen = false;
    bool key2Seen = false;
    
    size_t envCount = 0;
    while (envp[envCount] != NULL) {
        envCount++;
    }
    
    char **newEnvp = malloc((envCount + 3) * sizeof(char*));
    memset(newEnvp, 0, (envCount + 3) * sizeof(char*));
    
    for (size_t i = 0; i < envCount; i++) {
        char *env = envp[i];
        
        if (!key1Seen && !strncmp(envp[i], INJECT_KEY "=", sizeof(INJECT_KEY))) {
            if (strncmp(envp[i], INJECT_KEY "=" INJECT_VALUE ":", sizeof(INJECT_KEY "=" INJECT_VALUE)) && strcmp(envp[i], INJECT_KEY "=" INJECT_VALUE)) {
                char *var = malloc(strlen(envp[i]) + sizeof(INJECT_VALUE ":"));
                sprintf(var, "%s=%s:%s", INJECT_KEY, INJECT_VALUE, envp[i] + sizeof(INJECT_KEY));
                freeme[0] = var;
                newEnvp[i] = var;
                key1Seen = true;
                continue;
            }
        } else if (!key2Seen && !strncmp(envp[i], INJECT_KEY2 "=", sizeof(INJECT_KEY2))) {
            if (strncmp(envp[i], INJECT_KEY2 "=" INJECT_VALUE2 ":", sizeof(INJECT_KEY2 "=" INJECT_VALUE2)) && strcmp(envp[i], INJECT_KEY2 "=" INJECT_VALUE2)) {
                char *var = malloc(strlen(envp[i]) + sizeof(INJECT_VALUE2 ":"));
                sprintf(var, "%s=%s:%s", INJECT_KEY2, INJECT_VALUE2, envp[i] + sizeof(INJECT_KEY2));
                freeme[1] = var;
                newEnvp[i] = var;
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

#pragma mark codehashes

/*
 * Magic numbers used by Code Signing
 */
enum {
    CSMAGIC_REQUIREMENT    = 0xfade0c00,        /* single Requirement blob */
    CSMAGIC_REQUIREMENTS = 0xfade0c01,        /* Requirements vector (internal requirements) */
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,        /* CodeDirectory blob */
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */
};

enum {
    CS_PAGE_SIZE_4K                = 4096,
    CS_PAGE_SIZE_16K               = 16384,

    CS_HASHTYPE_SHA1              = 1,
    CS_HASHTYPE_SHA256            = 2,
    CS_HASHTYPE_SHA256_TRUNCATED  = 3,
    CS_HASHTYPE_SHA384 = 4,

    CS_HASH_SIZE_SHA1             = 20,
    CS_HASH_SIZE_SHA256           = 32,
    CS_HASH_SIZE_SHA256_TRUNCATED = 20,

    CSSLOT_CODEDIRECTORY                 = 0,
    CSSLOT_INFOSLOT                      = 1,
    CSSLOT_REQUIREMENTS                  = 2,
    CSSLOT_RESOURCEDIR                   = 3,
    CSSLOT_APPLICATION                   = 4,
    CSSLOT_ENTITLEMENTS                  = 5,
    CSSLOT_ALTERNATE_CODEDIRECTORIES     = 0x1000,
    CSSLOT_ALTERNATE_CODEDIRECTORY_MAX   = 5,
    CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT =
    CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX,
    CSSLOT_CMS_SIGNATURE                 = 0x10000,
//    kSecCodeSignatureAdhoc      = 2
};


/*
 * Structure of an embedded-signature SuperBlob
 */
typedef struct __BlobIndex {
    uint32_t type;                    /* type of entry */
    uint32_t offset;                /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;                    /* magic number */
    uint32_t length;                /* total length of SuperBlob */
    uint32_t count;                    /* number of index entries following */
    CS_BlobIndex index[];            /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;


/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
    uint32_t magic;                    /* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;                /* total length of CodeDirectory blob */
    uint32_t version;                /* compatibility version */
    uint32_t flags;                    /* setup and mode flags */
    uint32_t hashOffset;            /* offset of hash slot element at index zero */
    uint32_t identOffset;            /* offset of identifier string */
    uint32_t nSpecialSlots;            /* number of special hash slots */
    uint32_t nCodeSlots;            /* number of ordinary (code) hash slots */
    uint32_t codeLimit;                /* limit to main image signature range */
    uint8_t hashSize;                /* size of each hash in bytes */
    uint8_t hashType;                /* type of hash (cdHashType* constants) */
    uint8_t spare1;                    /* unused (must be zero) */
    uint8_t    pageSize;                /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;                /* unused (must be zero) */
    /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;


/*
 * Sample code to locate the CodeDirectory from an embedded signature blob
 */
static inline const CS_CodeDirectory *findCodeDirectory(const CS_SuperBlob *embedded)
{
    if (embedded && ntohl(embedded->magic) == CSMAGIC_EMBEDDED_SIGNATURE) {
        const CS_BlobIndex *limit = &embedded->index[ntohl(embedded->count)];
        const CS_BlobIndex *p;
        for (p = embedded->index; p < limit; ++p)
            if (ntohl(p->type) == CSSLOT_CODEDIRECTORY) {
                const unsigned char *base = (const unsigned char *)embedded;
                const CS_CodeDirectory *cd = (const CS_CodeDirectory *)(base + ntohl(p->offset));
                if (ntohl(cd->magic) == CSMAGIC_CODEDIRECTORY)
                    return cd;
            }
    }
    // not found
    return NULL;
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

int giveCSDEBUGToPid(pid_t tgtpid, int fork){
    int err = 0;
    if (true){
        xpc_object_t req = NULL;
        xpc_object_t rsp = NULL;
        //
        assure(req = xpc_dictionary_create(NULL, NULL, 0));
        xpc_dictionary_set_string(req, "action", "csdebug");
        xpc_dictionary_set_uint64(req, "pid", tgtpid);
        if (fork) {
            xpc_dictionary_set_uint64(req, "isFork", 1);
        }
        assure(!xpc_pipe_routine(gJBDPipe, req, &rsp));
        xpc_object_t val = xpc_dictionary_get_value(rsp, "status");
        if (val) {
            err = (int)xpc_dictionary_get_uint64(rsp, "status");
        } else {
            assure(0);
        }
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

#pragma mark parsing
int trustCDHashForCSSuperBlob(const CS_CodeDirectory *csdir){
    int err = 0;
    uint8_t hash[CC_SHA384_DIGEST_LENGTH] = {};
    size_t hashSize = sizeof(hash);
    switch (csdir->hashType) {
        case CS_HASHTYPE_SHA1:
            CC_SHA1(csdir, ntohl(csdir->length), hash);
            hashSize = 20;
            break;
        case CS_HASHTYPE_SHA256:
            CC_SHA256(csdir, ntohl(csdir->length), hash);
            hashSize = 20;
            break;
        case CS_HASHTYPE_SHA256_TRUNCATED:
            CC_SHA256(csdir, ntohl(csdir->length), hash);
            hashSize = 20;
            break;
        case CS_HASHTYPE_SHA384:
            CC_SHA384(csdir, ntohl(csdir->length), hash);
            hashSize = 20;
            break;
        default:
            assure(0);
    }
    err = trustCDHash(hash,hashSize,csdir->hashType);
error:
    return err;
}

int trustCDHashesForMachHeader(struct mach_header_64 *mh){
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    int err = 0;
    uint8_t *codesig = NULL;
    size_t codesigSize = 0;
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == LC_CODE_SIGNATURE){
            struct linkedit_data_command* cs = (struct linkedit_data_command*)lcmd;
            codesig += (uint64_t)mh + cs->dataoff;
            codesigSize = cs->datasize;
        }
    }
    assure(codesig && codesigSize);
    err = trustCDHashForCSSuperBlob(findCodeDirectory((const CS_SuperBlob*)codesig));
error:
    return err;
}

int trustCDHashesForBinary(const char *path){
    int fd = -1;
    uint8_t *buf = NULL;
    //
    int err = 0;
    size_t bufSize = 0;
    struct stat st = {};
    assure((fd = open(path, O_RDONLY)) != -1);
    assure(!fstat(fd, &st));
    assure(buf = malloc(bufSize = st.st_size));
    assure(read(fd, buf, bufSize) == bufSize);
    
    {
        struct fat_header *ft = (struct fat_header*)buf;
        if (ft->magic != ntohl(FAT_MAGIC)){
            err = trustCDHashesForMachHeader((struct mach_header_64*)buf);
        }else{
            uint32_t narch = ntohl(ft->nfat_arch);
            struct fat_arch *gfa = (struct fat_arch *)(ft+1);
            for (int i=0; i<narch; i++) {
                struct fat_arch *fa = &gfa[i];
                struct mach_header_64 *mh = (struct mach_header_64 *)(buf+ntohl(fa->offset));
                if (ntohl(fa->cputype) == CPU_TYPE_ARM64) {
                    if ((err = trustCDHashesForMachHeader(mh))) goto error;
                }
            }
        }
    }
    
error:
    safeFree(buf);
    safeClose(fd);
    return err;
}

int my_posix_spawn_common(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], int is_spawnp){
    int fd_console = open("/dev/console",O_RDWR,0);
    dprintf(fd_console, "spawning %s", path);
    for (size_t i = 0; argv[i]; i++) {
        dprintf(fd_console, " %s", argv[i]);
    }
    
    
    int ret = 0;
    char **out = NULL;
    char *freeme[2] = { NULL, NULL };
    trustCDHashesForBinary(path);
    /*if (strcmp(path, "/usr/libexec/xpcproxy") != 0) {
        dprintf(fd_console, "Doing injection!\n");
        injectDylibToEnvVars(envp, &out, freeme);
    } else {
        dprintf(fd_console, "xpcproxy - Not injecting\n");
    }*/
    injectDylibToEnvVars(envp, &out, freeme);
    dprintf(fd_console, "\n");
    close(fd_console);
    if (out)
        envp = out;
    if (strcmp(path, "/usr/libexec/xpcproxy") == 0)
        task_set_bootstrap_port(mach_task_self_, servicePort);
    
    short flags = 0;
    int deallocAttr = 0;
    posix_spawnattr_t tmpAttr;
    pid_t tmpPid = 0;
    if (!attrp) {
        attrp = &tmpAttr;
        posix_spawnattr_init(&tmpAttr);
        posix_spawnattr_setflags(&tmpAttr, POSIX_SPAWN_START_SUSPENDED);
        deallocAttr = 1;
    } else {
        posix_spawnattr_getflags(attrp, &flags);
        posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
    }
    
    if (!pid)
        pid = &tmpPid;
    
    if (is_spawnp)
        ret = posix_spawnp(pid, path, file_actions, attrp, argv, envp);
    else
        ret = posix_spawn(pid, path, file_actions, attrp, argv, envp);
    
    if (ret == 0) {
        //giveCSDEBUGToPid(*pid, 0);
        if ((flags & POSIX_SPAWN_START_SUSPENDED) == 0)
            kill(*pid, SIGCONT);
    }
    
    if (deallocAttr)
        posix_spawnattr_destroy(&tmpAttr);
    else
        posix_spawnattr_setflags(attrp, flags);
    
    task_set_bootstrap_port(mach_task_self_, MACH_PORT_NULL);
error:
    safeFree(out);
    safeFree(freeme[0]);
    safeFree(freeme[1]);
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

int sendPort(mach_port_t to, mach_port_t port) {
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
    } msg;
    
    msg.header.msgh_remote_port = to;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof(msg);
    
    msg.body.msgh_descriptor_count = 1;
    msg.task_port.name = port;
    msg.task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.task_port.type = MACH_MSG_PORT_DESCRIPTOR;
    
    kern_return_t kr = mach_msg_send(&msg.header);
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    
    return 0;
}

mach_port_t recvPort(mach_port_t from) {
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
        mach_msg_trailer_t         trailer;
        uint64_t                   pad[20];
    } msg;
    
    kern_return_t kr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg), from, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        return MACH_PORT_NULL;
    }
    
    return msg.task_port.name;
}

int my_xpc_receive_mach_msg(void *a1, void *a2, void *a3, void *a4, xpc_object_t *object_out, void *a6, void *a7, void *a8) {
    int err = xpc_receive_mach_msg(a1, a2, a3, a4, object_out, a6, a7, a8);
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
        }
    } else {
        dprintf(fd_console,"No task_get_bootstrap_port???\n");
        dprintf(fd_console,"No bootstrap port, no KRW, nothing I can do, goodbye!\n");
        return;
    }
    
    swift_init(fd_console, bp, &servicePort);
    
    gJBDPipe = xpc_pipe_create_from_port(servicePort, 0);
    
    dprintf(fd_console,"========= Goodbye from Stage 2 dylib constructor ========= \n");
    close(fd_console);
}

void dmb_sy(void) {
    asm volatile("dmb sy");
}
