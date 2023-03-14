//
//  main.c
//  jbinjector
//
//  Created by tihmstar on 03.03.23.
//

#include <stdio.h>
//#include <bootstrap.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
//#include <Security/CSCommon.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach/vm_map.h>
//#include <mach/mach_vm.h>
#include <mach/vm_statistics.h>
#include <dlfcn.h>
//#include <xpc/xpc.h>
#include <ptrauth.h>
#include <sys/mman.h>

#include "CodeSignature.h"

typedef void * xpc_object_t;
typedef xpc_object_t xpc_pipe_t;
xpc_pipe_t xpc_pipe_create_from_port(mach_port_t port, uint64_t flags);
int xpc_pipe_routine(xpc_pipe_t pipe, xpc_object_t request, xpc_object_t* reply);

typedef bool (^xpc_array_applier_t)(size_t index, xpc_object_t value);

xpc_object_t xpc_dictionary_create(const char * const * keys, const xpc_object_t * values, size_t);
void xpc_dictionary_set_string(xpc_object_t, const char *, const char *);
void xpc_dictionary_set_uint64(xpc_object_t, const char *, uint64_t);
uint64_t xpc_dictionary_get_uint64(xpc_object_t, const char *);
xpc_object_t xpc_dictionary_get_value(xpc_object_t, const char *);
void xpc_dictionary_set_value(xpc_object_t xdict, const char *key, xpc_object_t value);
xpc_object_t xpc_array_create(xpc_object_t  _Nonnull const *objects, size_t count);
void xpc_array_append_value(xpc_object_t xarray, xpc_object_t value);
bool xpc_array_apply(xpc_object_t xarray, xpc_array_applier_t applier);
uint64_t xpc_array_get_uint64(xpc_object_t xarray, size_t index);
xpc_object_t xpc_uint64_create(uint64_t value);
uint64_t xpc_uint64_get_value(xpc_object_t xuint);
void xpc_release(xpc_object_t);
void xpc_dictionary_set_data(xpc_object_t, const char *, const void *, size_t);
kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);

extern const void* _dyld_get_shared_cache_range(size_t* mappedSize);

xpc_pipe_t gJBDPipe  = NULL;
mach_port_t gJBDPort = MACH_PORT_NULL;

#ifdef DEBUG
#define debug(a...) printf(a)
//#define debug(a...) dprintf(gLogfd,a)
#else
#define debug(a...)
#endif

#define safeClose(fd) do{if ((fd) != -1){close(fd); fd = -1;}}while(0)
#define safeFree(buf) do{if ((buf)){free(buf); buf = NULL;}}while(0)
#define assure(cond) do {if (!(cond)){err = __LINE__; goto error;}}while(0)

#define guard(cond) if (__builtin_expect(!!(cond), 1)) {}

#define DYLD_INTERPOSE(_replacment,_replacee) \
__attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

#define INJECT_KEY "DYLD_INSERT_LIBRARIES"
#define INJECT_VALUE "/usr/lib/jbinjector.dylib"
#define INJECT_KEY2 "DYLD_AMFI_FAKE"
#define INJECT_VALUE2 "0xff"

#ifdef __aarch64__
#define EXECVE_NEEDLE "\x70\x07\x80\xD2\x01\x10\x00\xD4"
#define FORK_NEEDLE "\x50\x00\x80\xD2\x01\x10\x00\xD4"
#define DYLD_NEEDLE "\x90\x0B\x80\xD2\x01\x10\x00\xD4"
#define DYLD_PATCH "\x50\x00\x00\x58\x00\x02\x1F\xD6"
#else
#define EXECVE_NEEDLE "\x70\x07\x80\xD2\x01\x10\x00\xD4" //WRONG!!!
#define FORK_NEEDLE "\xB8\x02\x00\x00\x02\x0F\x05"
#define DYLD_NEEDLE "\xB8\x5C\x00\x00\x02\x49\x89\xCA\x0F\x05"
#define DYLD_PATCH "\x48\xB8\x48\x47\x46\x45\x44\x43\x42\x41\xFF\xE0"
#endif

#define DEBUG 1

#ifdef DEBUG
static int gLogfd = -1;
void init_dbglog(void){
    char path[0x100] = {};
    snprintf(path, sizeof(path), "/tmp/%d.log",getpid());
    gLogfd = open(path, O_CREAT | O_WRONLY, 0755);
}
#endif

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

#pragma mark lib
int giveCSDEBUGToPid(pid_t tgtpid, int fork){
    int err = 0;
    if (gJBDPipe){
        xpc_object_t req = NULL;
        xpc_object_t rsp = NULL;
        //
        assure(req = xpc_dictionary_create(NULL, NULL, 0));
        xpc_dictionary_set_string(req, "action", "csdebug");
        xpc_dictionary_set_uint64(req, "pid", tgtpid);
        if (fork) {
            xpc_dictionary_set_uint64(req, "parentPid", getpid());
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

int trustCDHash(const uint8_t *hash, size_t hashSize, uint8_t hashType) {
#ifdef DEBUG
    debug("Trusting hash: ");
    for (int i=0; i< hashSize; i++) debug("%02x",hash[i]);
    debug("\n");
#endif
    int err = 0;
    if (gJBDPipe){
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

void fixupImages(void) {
    size_t scSize = 0;
    uintptr_t scBase = (uintptr_t) _dyld_get_shared_cache_range(&scSize);
    uintptr_t scEnd  = scBase + scSize;
    
    xpc_object_t startArray = xpc_array_create(NULL, 0);
    xpc_object_t endArray = xpc_array_create(NULL, 0);
    
    uint32_t imgCnt = _dyld_image_count();
    for (uint32_t i = 0; i < imgCnt; i++) {
        const struct mach_header_64 *mh = (void*) _dyld_get_image_header(i);
        guard (mh != NULL) else {
            continue;
        }
        
        Dl_info dlInfo;
        guard (dladdr(mh, &dlInfo)) else {
            // Uh-Oh!
            continue;
        }
        
        guard (dlInfo.dli_fname != NULL) else {
            // No path?!
            continue;
        }
        
        guard ((uintptr_t) mh < scBase || (uintptr_t) mh >= scEnd) else {
            continue;
        }
        
        // Check if this needs to be fixed
        // mh must be executable -> Fix if it isn't
        vm_address_t addr  = (vm_address_t) mh;
        vm_size_t regionSz = 0;
        struct vm_region_basic_info_64 info;
        mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objectName = 0;
        kern_return_t kr = vm_region_64(mach_task_self_, &addr, &regionSz, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &info, &infoCnt, &objectName);
        guard (kr == KERN_SUCCESS) else {
            continue;
        }
        
        if (MACH_PORT_VALID(objectName)) {
            mach_port_deallocate(mach_task_self_, objectName);
            objectName = 0;
        }
        
        guard ((info.max_protection & VM_PROT_EXECUTE) == 0 && (info.protection & VM_PROT_EXECUTE) == 0) else {
            // Image is ok, no need to fix it
            continue;
        }
        
        // Okay, this image has to be fixed
        // Try to open image
        int fd = open(dlInfo.dli_fname, O_RDONLY);
        guard (fd >= 0) else {
            // Oops, couldn't open dylib
            // This *will* cause problems later on...
            continue;
        }
        
        size_t __block fatOffset = 0;
        
        // Attach signature
        int ok = trustCDHashesForBinary(fd, ^int(uint8_t *hash, size_t hashSize, uint8_t hashType, size_t thisFatOffset, size_t cdHashOffset, size_t cdHashSize, struct mach_header_64 *thisMh) {
            // Trust this CDHash
            trustCDHash(hash, hashSize, hashType);
            
            guard (thisMh->cputype == mh->cputype && thisMh->cpusubtype == mh->cpusubtype) else {
                // We're not using this slice, don't add signature
                return 0;
            }
            
            fatOffset = thisFatOffset;
            
            /*fsignatures_t siginfo;
            siginfo.fs_file_start = thisFatOffset;
            siginfo.fs_blob_start = (void*) cdHashOffset;
            siginfo.fs_blob_size  = cdHashSize;
            int err = 0;//fcntl(fd, F_ADDFILESIGS_RETURN, &siginfo);
            guard (err != -1) else {
                return 0;
            }*/
            
            // Indicate success by returning one
            // Error values are or-ed together, this way we can indicate at least one hash could be added
            return 1;
        });
        
        // Need to close fd - Otherwise mmap will fail...
        close(fd);
        
        guard (ok) else {
            // Oops, couldn't attach signature
            // This *will* cause problems later on...
            // XXX: Treat as completely unsigned -> munmap, vm_allocate and just copy the stuff in?
            //      Would add a bunch of dirty memory though...
            continue;
        }
        
        // Try to open image again
        fd = open(dlInfo.dli_fname, O_RDONLY);
        guard (fd >= 0) else {
            // Oops, couldn't open dylib
            // This *will* cause problems later on...
            // XXX: Can this ever happen?
            continue;
        }
        
        // Okay, time to go over all segments
        // munmap everything that should be executable, then mmap again
        uintptr_t slide = _dyld_get_image_vmaddr_slide(i);
        uint32_t cmds = mh->ncmds;
        struct segment_command_64 *sCmd = (struct segment_command_64*) (mh + 1);
        for (uint32_t c = 0; c < cmds; c++) {
            if (sCmd->cmd == LC_SEGMENT_64) {
                if (sCmd->initprot & VM_PROT_EXECUTE) {
                    // Ask jbd to fix prot
                    uintptr_t start = sCmd->vmaddr + slide;
                    uintptr_t end   = start + sCmd->vmsize;
                    start &= ~0x3FFFULL;
                    end = (end + 0x3FFFULL) & ~0x3FFFULL;
                    
                    xpc_object_t xStart = xpc_uint64_create(start);
                    xpc_object_t xEnd   = xpc_uint64_create(end);
                    xpc_array_append_value(startArray, xStart);
                    xpc_array_append_value(endArray, xEnd);
                    xpc_release(xEnd);
                    xpc_release(xStart);
                }
            }
            
            sCmd = (struct segment_command_64*) ((uintptr_t) sCmd + sCmd->cmdsize);
        }
        
        // Done!
        close(fd);
    }
    
    fixprot(getpid(), startArray, endArray, 0);
    xpc_array_apply(startArray, ^bool(size_t index, xpc_object_t value) {
        uint64_t start = xpc_uint64_get_value(value);
        uint64_t end   = xpc_array_get_uint64(endArray, index);
        vm_protect(mach_task_self_, start, end - start, 0, VM_PROT_READ | VM_PROT_EXECUTE);
        
        return true;
    });
    xpc_release(startArray);
    xpc_release(endArray);
}

#pragma mark parsing
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

#ifdef __aarch64__
__attribute__((naked)) uint64_t msyscall_errno(uint64_t syscall, ...){
    asm(
        "mov x16, x0\n"
        "ldp x0, x1, [sp]\n"
        "ldp x2, x3, [sp, 0x10]\n"
        "ldp x4, x5, [sp, 0x20]\n"
        "ldp x6, x7, [sp, 0x30]\n"
        "svc 0x80\n"
        "b.cs 20f\n"
        "ret\n"
        "20:\n"
        "b _cerror\n"
        );
}
#else
uint64_t msyscall_errno(uint64_t syscall, ...){
    return -99;
}
#endif

#ifdef __aarch64__
__attribute__((naked)) uint64_t msyscall(uint64_t syscall, ...){
    asm(
        "mov x16, x0\n"
        "ldp x0, x1, [sp]\n"
        "ldp x2, x3, [sp, 0x10]\n"
        "ldp x4, x5, [sp, 0x20]\n"
        "ldp x6, x7, [sp, 0x30]\n"
        "svc 0x80\n"
        "ret\n"
        );
}
#else
uint64_t msyscall(uint64_t s, ...){
    va_list a;
    va_start(a, s);
    void *arg1 = va_arg(a, void *);
    void *arg2 = va_arg(a, void *);
    void *arg3 = va_arg(a, void *);
    void *arg4 = va_arg(a, void *);
    void *arg5 = va_arg(a, void *);
    void *arg6 = va_arg(a, void *);
    void *arg7 = va_arg(a, void *);
    void *arg8 = va_arg(a, void *);
    va_end(a);
    errno = 0;
    syscall((int)s, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    return errno;
}
#endif

int my_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]){
    int ret = 0;
    char **out = NULL;
    char *freeme = NULL;
    if (gJBDPipe){
        trustCDHashesForBinaryPathSimple(path);
        if (!isBlacklisted(path)) {
            injectDylibToEnvVars(envp, &out, &freeme);
            envp = out;
        }
    }
    
    ret = posix_spawn(pid, path, file_actions, attrp, argv, envp);
error:
    safeFree(out);
    safeFree(freeme);
    return ret;
}
DYLD_INTERPOSE(my_posix_spawn, posix_spawn);

int my_posix_spawnp(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]){
    int ret = 0;
    char **out = NULL;
    char *freeme = NULL;
    if (gJBDPipe){
        trustCDHashesForBinaryPathSimple(path);
        if (!isBlacklisted(path)) {
            injectDylibToEnvVars(envp, &out, &freeme);
            envp = out;
        }
    }
    
    ret = posix_spawnp(pid, path, file_actions, attrp, argv, envp);
error:
    safeFree(out);
    safeFree(freeme);
    return ret;
}
DYLD_INTERPOSE(my_posix_spawnp, posix_spawnp);

#ifndef AUE_FORK
#define AUE_FORK 2
#endif

#ifndef AUE_GETPID
#define AUE_GETPID 20
#endif

#ifndef __aarch64__
__attribute__((naked)) pid_t my_fork_internal(void){
    asm(
        ".intel_syntax noprefix\n"
        "add rsp, 0x18\n"
        "jmp _my_fork_internal_\n"
        );
}

pid_t my_fork_scall(void){
    return -99;
}

pid_t my_fork_internal_(void){
#else
    
__attribute__((naked)) pid_t my_fork_scall(void) {
    asm(
        "mov x16, 0x2\n"
        "svc 0x80\n"
        "b.cs 30f\n"
        "cbz x1, 40f\n"
        "adrp x16, __current_pid@GOTPAGE\n"
        "ldr x16, [x16, __current_pid@GOTPAGEOFF]\n"
        "mov w0, #0\n"
        "str w0, [x16]\n"
        "40:\n"
        "ret\n"
        "30:\n"
        "b _cerror\n"
        );
}
    
pid_t my_fork_internal(void){
#endif
    pid_t retval = my_fork_scall();
    if (retval == -1) return retval;
    
    if (retval == 0){
        //child
        msyscall(37, getpid(), SIGSTOP, 1);
    }
    
    return retval;
}
    
int hookFork(void);
int hookExecve(void);
    
mach_port_t recvPort(mach_port_t from) {
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
        mach_msg_trailer_t         trailer;
        uint64_t                   pad[0x20];
    } msg;
    
    kern_return_t kr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg), from, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        return MACH_PORT_NULL;
    }
    
    return msg.task_port.name;
}
    
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
    
pid_t my_fork_vfork(int isVfork, mach_port_t *helper) {
    mach_port_t bp = MACH_PORT_NULL;
    task_get_bootstrap_port(mach_task_self_, &bp);
    
    mach_port_t conn = 0;
    mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &conn);
    mach_port_insert_right(mach_task_self_, conn, conn, MACH_MSG_TYPE_MAKE_SEND);
    
    task_set_bootstrap_port(mach_task_self_, conn);
    pid_t p = fork();
    int err = errno;
    if (p != -1 && p != 0) {
        //parent
        task_set_bootstrap_port(mach_task_self_, bp);
        
        {
            int asd = 0;
            waitpid(p, &asd, WUNTRACED);
        }
        giveCSDEBUGToPid(p, 1);
        xpc_object_t startArray = xpc_array_create(NULL, 0);
        xpc_object_t endArray = xpc_array_create(NULL, 0);
        
        vm_address_t addr = 0;
        vm_address_t prevAddr = 1;
        while (addr != prevAddr) {
            prevAddr = addr;
            
            vm_size_t regionSz = 0;
            struct vm_region_basic_info_64 info;
            mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t objectName = 0;
            kern_return_t kr = vm_region_64(mach_task_self_, &addr, &regionSz, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &info, &infoCnt, &objectName);
            if (kr != KERN_SUCCESS)
                break;
            
            if (regionSz && (info.protection & VM_PROT_EXECUTE)) {
                xpc_object_t xStart = xpc_uint64_create(addr);
                xpc_object_t xEnd   = xpc_uint64_create(addr + regionSz);
                
                xpc_array_append_value(startArray, xStart);
                xpc_array_append_value(endArray, xEnd);
                
                xpc_release(xEnd);
                xpc_release(xStart);
            }
            
            if (!regionSz)
                regionSz = 0x4000;
            
            addr += regionSz;
        }
        
        fixprot(p, startArray, endArray, 1);
        xpc_release(startArray);
        xpc_release(endArray);
        
        kill(p, SIGCONT);
        
        // Get child port
        mach_port_t childPort = recvPort(conn);
        
        // Send bootstrap port
        sendPort(childPort, bp);
        
        // Send jbd port
        sendPort(childPort, gJBDPort);
        
        if (!isVfork)
            mach_port_deallocate(mach_task_self_, childPort);
        else
            *helper = childPort;
        
        mach_port_destroy(mach_task_self_, conn);
    } else if (p == 0) {
        // Child
        mach_port_t connection;
        task_get_bootstrap_port(mach_task_self(), &connection); // Might have a different name...
        
        // Create receive port and send to parent
        mach_port_t myPort;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &myPort);
        mach_port_insert_right(mach_task_self(), myPort, myPort, MACH_MSG_TYPE_MAKE_SEND);
        sendPort(connection, myPort);
        
        // Get real bootstrap port
        bp = recvPort(myPort);
        bootstrap_port = bp;
        task_set_bootstrap_port(mach_task_self(), bp);
        
        // Get jbd port
        gJBDPort = recvPort(myPort);
        gJBDPipe = xpc_pipe_create_from_port(gJBDPort, 0);
        
        mach_port_deallocate(mach_task_self_, connection);
        if (!isVfork)
            mach_port_destroy(mach_task_self_, myPort);
    }
    
    errno = err;
    
    return p;
}
    
pid_t my_fork(void) {
    return my_fork_vfork(0, NULL);
}
DYLD_INTERPOSE(my_fork, fork);
    
pid_t my_vfork(void){
    mach_port_t helper = 0;
    pid_t pid = my_fork_vfork(1, &helper);
    if (pid == -1)
        return pid;
    
    if (pid == 0)
        return pid;
    
    // Parent - Wait for the port to be destroyed
    // (Ghetto way to detect process died/exec'd)
    mach_port_t listen = 0;
    mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &listen);
    
    mach_port_t previous = 0;
    mach_port_request_notification(mach_task_self_, helper, MACH_NOTIFY_DEAD_NAME, 1, listen, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
    if (MACH_PORT_VALID(previous))
        mach_port_deallocate(mach_task_self_, previous);
    
    uint8_t buf[0x100];
    mach_msg_header_t *hdr = (mach_msg_header_t*) buf;
    hdr->msgh_local_port = listen;
    hdr->msgh_size = 0x100;
    mach_msg_receive(hdr);
    
    mach_port_destroy(mach_task_self_, listen);
    mach_port_destroy(mach_task_self_, helper);
    
    return pid;
}
DYLD_INTERPOSE(my_vfork, vfork);
    
#ifndef AUE_FCNTL
#define AUE_FCNTL 0x5c
#endif

int my_fcntl_internal(int fd, int cmd, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6, void *arg7, void *arg8){
    switch (cmd){
        case F_ADDSIGS:
        case F_ADDFILESIGS:
        case F_ADDFILESIGS_RETURN:
        {
            uint8_t *buf = NULL;
            //
            int err = 0;
            uint64_t lpos = -1;
            fsignatures_t *siginfo = (fsignatures_t *)arg1;
            lpos = lseek(fd, 0, SEEK_CUR);
            assure(buf = (uint8_t*)malloc(siginfo->fs_blob_size));
            lseek(fd, (uint64_t)siginfo->fs_blob_start, SEEK_SET);
            assure(read(fd, buf, siginfo->fs_blob_size));
            
            err = trustCodeDirectories(NULL, (const CS_SuperBlob *) buf, siginfo->fs_file_start, ^int(uint8_t *hash, size_t hashSize, uint8_t hashType, size_t fatOffset, size_t cdOffset, size_t cdSize, struct mach_header_64 *mh) {
                return trustCDHash(hash, hashSize, hashType);
            });
        error:
            lseek(fd, lpos, SEEK_SET);
            safeFree(buf);
            break;
        }
        default:
            break;
    }
    return (int)msyscall_errno(AUE_FCNTL, fd, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}

int my_fcntl_(int fd, int cmd, ...) {
    va_list a;
    va_start(a, cmd);
    void *arg1 = va_arg(a, void *);
    void *arg2 = va_arg(a, void *);
    void *arg3 = va_arg(a, void *);
    void *arg4 = va_arg(a, void *);
    void *arg5 = va_arg(a, void *);
    void *arg6 = va_arg(a, void *);
    void *arg7 = va_arg(a, void *);
    void *arg8 = va_arg(a, void *);
    va_end(a);
    return my_fcntl_internal(fd, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}
  
#ifdef __aarch64__
__attribute__((naked)) int my_fcntl(int fd, int cmd, ...) {
    asm("cmp x1, 59\n"
        "b.eq 50f\n"
        "cmp x1, 61\n"
        "b.eq 50f\n"
        "cmp x1, 97\n"
        "b.eq 50f\n"
        "b _fcntl\n"
        "50:\n"
        "b _my_fcntl_"
        );
}
#else
int my_fcntl(int fd, int cmd, ...){
    return -99;
}
#endif
DYLD_INTERPOSE(my_fcntl, fcntl);

void* find_dyld_address(void){
    kern_return_t err = 0;
    task_dyld_info_data_t task_dyld_info = {};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    err = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
    const struct dyld_all_image_infos* all_image_infos = (const struct dyld_all_image_infos*)task_dyld_info.all_image_info_addr;
    return (void*)all_image_infos->dyldImageLoadAddress;
}
 
#ifdef __aarch64__
__attribute__((naked))
kern_return_t my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
    asm volatile("mov x16, -14\nsvc #0x80\nret\n");
}
#else
kern_return_t my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
    return -99;
}
#endif

int hookAddr(void *addr, void *target){
    int err = 0;
    kern_return_t kret = 0;
    uint8_t *hooktgt = NULL;
    uint8_t *target_address = NULL;

    hooktgt = (uint8_t*)addr;

    debug("Applying hook\n");
    assure(!(kret = my_vm_protect(mach_task_self_, (mach_vm_address_t)hooktgt, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t), 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)));
    
    target_address = (uint8_t*) hooktgt;
    memcpy(target_address, DYLD_PATCH, sizeof(DYLD_PATCH)-1);
    uint64_t ptr = (uint64_t) ptrauth_strip(target, ptrauth_key_asia);
#ifdef __aarch64__
        *(void**)&target_address[sizeof(DYLD_PATCH)-1] = (void*)ptr;
#else
        *(void**)&target_address[2] = (void*)ptr;
#endif
    
    target_address = NULL;
    
    assure(!(kret = my_vm_protect(mach_task_self_, (mach_vm_address_t)hooktgt, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t), 0, VM_PROT_READ | VM_PROT_EXECUTE)));
    /*{
        vm_prot_t cur = 0;
        vm_prot_t max = 0;
        assure(!(kret = vm_remap(mach_task_self_, (vm_address_t*)&target_address, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t), 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, mach_task_self_, (mach_vm_address_t)hooktgt, false, &cur, &max, VM_INHERIT_NONE)));
        assure(!(kret = vm_protect(mach_task_self_, (mach_vm_address_t)target_address, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t), 0, VM_PROT_READ | VM_PROT_WRITE)));
        debug("Applying hook doing write\n");
        memcpy(target_address, DYLD_PATCH, sizeof(DYLD_PATCH)-1);
        uint64_t ptr = (uint64_t)target;
        ptr &= ~0xffff000000000000;
#ifdef __aarch64__
        *(void**)&target_address[sizeof(DYLD_PATCH)-1] = (void*)ptr;
#else
        *(void**)&target_address[2] = (void*)ptr;
#endif
        vm_inherit(mach_task_self_, (vm_address_t) hooktgt, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t), VM_INHERIT_COPY);
    }*/
    
error:
    if (target_address){
        kret = vm_deallocate(mach_task_self_, (mach_vm_address_t)target_address, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t));
        if (!err) err = kret;
    }
    debug("Applying hook done err=%d\n",err);
    return err;
}

int hookFCNTLDyld(void){
    int err = 0;
    uint8_t *mh = NULL;
    uint8_t *strsec = NULL;
    uint8_t *hooktgt = NULL;

    mh = (uint8_t*)find_dyld_address();

    assure(strsec = memmem(mh, 0xfffffff, "DYLD_INSERT_LIBRARIES", sizeof("DYLD_INSERT_LIBRARIES")));
    assure(hooktgt = memmem(mh, strsec-mh, DYLD_NEEDLE, sizeof(DYLD_NEEDLE)-1));
    err = hookAddr(hooktgt, my_fcntl_internal);
error:
    return err;
}
int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
    
    /* code signing attributes of a process */
    #define    CS_VALID                    0x0000001    /* dynamically valid */
    #define CS_ADHOC                    0x0000002    /* ad hoc signed */
    #define CS_GET_TASK_ALLOW            0x0000004    /* has get-task-allow entitlement */
    #define CS_INSTALLER                0x0000008    /* has installer entitlement */

    #define    CS_HARD                        0x0000100    /* don't load invalid pages */
    #define    CS_KILL                        0x0000200    /* kill process if it becomes invalid */
    #define CS_CHECK_EXPIRATION            0x0000400    /* force expiration checking */
    #define CS_RESTRICT                    0x0000800    /* tell dyld to treat restricted */
    #define CS_ENFORCEMENT                0x0001000    /* require enforcement */
    #define CS_REQUIRE_LV                0x0002000    /* require library validation */
    #define CS_ENTITLEMENTS_VALIDATED    0x0004000    /* code signature permits restricted entitlements */
    #define CS_NVRAM_UNRESTRICTED        0x0008000    /* has com.apple.rootless.restricted-nvram-variables.heritable entitlement */

    #define    CS_ALLOWED_MACHO             (CS_ADHOC | CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | \
                                          CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV)

    #define CS_EXEC_SET_HARD            0x0100000    /* set CS_HARD on any exec'ed process */
    #define CS_EXEC_SET_KILL            0x0200000    /* set CS_KILL on any exec'ed process */
    #define CS_EXEC_SET_ENFORCEMENT        0x0400000    /* set CS_ENFORCEMENT on any exec'ed process */
    #define CS_EXEC_INHERIT_SIP            0x0800000    /* set CS_INSTALLER on any exec'ed process */

    #define CS_KILLED                    0x1000000    /* was killed by kernel for invalidity */
    #define CS_DYLD_PLATFORM            0x2000000    /* dyld used to load this is a platform binary */
    #define CS_PLATFORM_BINARY            0x4000000    /* this is a platform binary */
    #define CS_PLATFORM_PATH            0x8000000    /* platform binary by the fact of path (osx only) */
    #define CS_DEBUGGED                    0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
    #define CS_SIGNED                    0x20000000  /* process has a signature (may have gone invalid) */
    #define CS_DEV_CODE                    0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */
    #define CS_DATAVAULT_CONTROLLER        0x80000000    /* has Data Vault controller entitlement */

static int realOps = 0;
int my_csops(pid_t pid, unsigned int ops, void * useraddr, size_t usersize){
    int retval = csops(pid, ops, useraddr, usersize);
    if (realOps){
        if (pid == getpid() || pid == 0){
            if (retval == 0 && ops == 0 && usersize >=  sizeof(int) && useraddr){
                *(int*)useraddr = (realOps & ~(CS_DEBUGGED | CS_GET_TASK_ALLOW)) | (CS_HARD | CS_KILL | CS_RESTRICT | CS_REQUIRE_LV | CS_ENFORCEMENT);
            }
        }
    }
    return retval;
}
DYLD_INTERPOSE(my_csops, csops);

int hookFork(void){
    int err = 0;
    uint8_t *hooktgt = NULL;
    
    debug("hookFork\n");
    uint8_t *nearbyLoc = (uint8_t*)ptrauth_strip((void*) mach_ports_register, 0);
    size_t searchSize = PAGE_SIZE*10;

    hooktgt = memmem(nearbyLoc, searchSize, FORK_NEEDLE, sizeof(FORK_NEEDLE)-1);
    debug("memmem 1 alive\n");
    if (!hooktgt){
        hooktgt = memmem(nearbyLoc-searchSize, searchSize, FORK_NEEDLE, sizeof(FORK_NEEDLE)-1);
        debug("memmem 2 alive\n");
    }
    assure(hooktgt);
    debug("found fork hook needle\n");
#ifdef __aarch64__
    {
        for (int i=0; i<10; i++){
            if (*(uint32_t*)hooktgt == 0xd503237f) goto foundbof;
            hooktgt-=4;
        }
        debug("failed to find bof!\n");
        assure(0);
    foundbof:;
    }
#endif
    err = hookAddr(hooktgt, my_fork_internal);
error:
    debug("hookfrok err=%d\n",err);
    return err;
}
    
int my_execve_internal(const char *pathname, char *const argv[],
                       char *const envp[]) {
    int ret = 0;
    char **out = NULL;
    char *freeme = NULL;
    if (gJBDPipe){
        trustCDHashesForBinaryPathSimple(pathname);
        if (!isBlacklisted(pathname)) {
            injectDylibToEnvVars(envp, &out, &freeme);
            envp = out;
        }
    }
    
    ret = (int) msyscall(0x3B, pathname, argv, envp);
    errno = ret;
error:
    safeFree(out);
    safeFree(freeme);
    return -1;
}
    
int hookExecve(void){
    int err = 0;
    uint8_t *hooktgt = NULL;
    
    debug("hookExecve\n");
    uint8_t *nearbyLoc = (uint8_t*)ptrauth_strip((void*) mach_ports_register, 0);
    size_t searchSize = PAGE_SIZE*10;

    hooktgt = memmem(nearbyLoc, searchSize, EXECVE_NEEDLE, sizeof(EXECVE_NEEDLE)-1);
    debug("memmem 1 alive\n");
    if (!hooktgt){
        hooktgt = memmem(nearbyLoc-searchSize, searchSize, EXECVE_NEEDLE, sizeof(EXECVE_NEEDLE)-1);
        debug("memmem 2 alive\n");
    }
    assure(hooktgt);
    debug("found execve hook needle\n");
    err = hookAddr(hooktgt, my_execve_internal);
error:
    debug("hookExecve err=%d\n",err);
    return err;
}
    
#ifdef XCODE
int main(int argc, const char * argv[], const char **envp) {
#else
__attribute__((constructor))  int constructor(){
#endif

#ifdef DEBUG
    init_dbglog();
#endif
    
#ifdef XCODE
    trustCDHashesForBinaryPathSimple("/tmp/kk/NewTerm_arm64");
#endif
    
    
    debug("hello");
    
    {
        //remove injected env vars
        unsetenv(INJECT_KEY2);
        char *dyldvar = getenv(INJECT_KEY);
        if (dyldvar) {
            char *origvar = strstr(dyldvar, ":");
            if (origvar) setenv(INJECT_KEY, origvar+1, 1);
            else unsetenv(INJECT_KEY);
        }
    }
    
    debug("hello\n");
    
    kern_return_t kret = 0;
    if ((kret = bootstrap_look_up(bootstrap_port, "jb-global-jbd", &gJBDPort))){
        if ((kret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, HOST_CLOSURED_PORT, &gJBDPort))){
    #ifndef XCODE
            debug("Failed to get JBD port\n");
            return 0;
    #endif
        }
        //task_set_bootstrap_port(mach_task_self_, MACH_PORT_NULL);
    }
    
    debug("Got JBD Port\n");

    if (!(gJBDPipe = xpc_pipe_create_from_port(gJBDPort, 0))){
#ifndef XCODE
        debug("Failed to get JBD pipe\n");
        return 0;
#endif
    }
    
    debug("Got JBD Pipe\n");
    
    csops(getpid(), 0, &realOps, sizeof(int));
    
    if (giveCSDEBUGToPid(getpid(), 0)){
#ifndef XCODE
        debug("Failed to get CSDEBUG\n");
        return 0;
#endif
    }
    
    debug("CSDEBUG\n");
    
    if (hookFCNTLDyld()){
        debug("Failed to hook FCNTL dyld\n");
        return 0;
    }
    
    debug("fcntl\n");
    
    fixupImages();
    
    debug("images\n");
    
    if (hookFork()){
        debug("Failed to hook fork\n");
        return 0;
    }
    
    debug("fork\n");
    
    if (hookExecve()){
        debug("Failed to hook execve\n");
        return 0;
    }
    
    debug("execve\n");
    
    debug("All done!\n");
    
#ifdef XCODE
    fork();
    debug("Fork done!\n");
    sleep(4);
#endif
    
    return 0;
}
