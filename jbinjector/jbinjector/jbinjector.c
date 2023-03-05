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
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
//#include <Security/CSCommon.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach/vm_map.h>
//#include <mach/mach_vm.h>
#include <mach/vm_statistics.h>
#include <dlfcn.h>
//#include <xpc/xpc.h>

typedef void * xpc_object_t;
typedef xpc_object_t xpc_pipe_t;
xpc_pipe_t xpc_pipe_create_from_port(mach_port_t port, uint64_t flags);
int xpc_pipe_routine(xpc_pipe_t pipe, xpc_object_t request, xpc_object_t* reply);

xpc_object_t xpc_dictionary_create(const char * const * keys, const xpc_object_t * values, size_t);
void xpc_dictionary_set_string(xpc_object_t, const char *, const char *);
void xpc_dictionary_set_uint64(xpc_object_t, const char *, uint64_t);
uint64_t xpc_dictionary_get_uint64(xpc_object_t, const char *);
void xpc_release(xpc_object_t);
void xpc_dictionary_set_data(xpc_object_t, const char *, const void *, size_t);
kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);

xpc_pipe_t gJBDPipe = NULL;

#ifdef DEBUG
#define debug(a...) printf(a)
#else
#define debug(a...)
#endif

#define safeClose(fd) do{if ((fd) != -1){close(fd); fd = -1;}}while(0)
#define safeFree(buf) do{if ((buf)){free(buf); buf = NULL;}}while(0)
#define assure(cond) do {if (!(cond)){err = __LINE__; goto error;}}while(0)

#define DYLD_INTERPOSE(_replacment,_replacee) \
__attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

#define INJECT_KEY "DYLD_INSERT_LIBRARIES"
#define INJECT_VALUE "/usr/lib/jbinjector.dylib"
#define INJECT_KEY2 "DYLD_AMFI_FAKE"
#define INJECT_VALUE2 "0xff"

#ifdef __aarch64__
#define FORK_NEEDLE "\x50\x00\x80\xD2\x01\x10\x00\xD4"
#define DYLD_NEEDLE "\x90\x0B\x80\xD2\x01\x10\x00\xD4"
#define DYLD_PATCH "\x50\x00\x00\x58\x00\x02\x1F\xD6"
#else
#define FORK_NEEDLE "\xB8\x02\x00\x00\x02\x0F\x05"
#define DYLD_NEEDLE "\xB8\x5C\x00\x00\x02\x49\x89\xCA\x0F\x05"
#define DYLD_PATCH "\x48\xB8\x48\x47\x46\x45\x44\x43\x42\x41\xFF\xE0"
#endif


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
int giveCSDEBUGToPid(pid_t tgtpid){
    int err = 0;
    if (gJBDPipe){
        xpc_object_t req = NULL;
        xpc_object_t rsp = NULL;
        //
        assure(req = xpc_dictionary_create(NULL, NULL, 0));
        xpc_dictionary_set_string(req, "action", "csdebug");
        xpc_dictionary_set_uint64(req, "pid", tgtpid);
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

int trustCDHash(const uint8_t *hash, size_t hashSize, uint8_t hashType){
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

void injectDylibToEnvVars(char *const envp[], char ***outEnvp, char **freeme) {
    if (envp == NULL)
        return;
    
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
    char **out = envp;
    char *freeme[2] = {};
    if (gJBDPipe){
        trustCDHashesForBinary(path);
        injectDylibToEnvVars(envp, &out, freeme);
        envp = out;
    }
    ret = posix_spawn(pid, path, file_actions, attrp, argv, envp);
error:
    safeFree(out);
    safeFree(freeme[0]);
    safeFree(freeme[1]);
    return ret;
}
DYLD_INTERPOSE(my_posix_spawn, posix_spawn);

int my_posix_spawnp(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]){
    int ret = 0;
    char **out = envp;
    char *freeme[2] = {};
    if (gJBDPipe){
        trustCDHashesForBinary(path);
        injectDylibToEnvVars(envp, &out, freeme);
        envp = out;
    }
    ret = posix_spawnp(pid, path, file_actions, attrp, argv, envp);
error:
    safeFree(out);
    safeFree(freeme[0]);
    safeFree(freeme[1]);
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
pid_t my_fork_internal_(void){
#else
pid_t my_fork_internal(void){
#endif
    int retval = -1;
    int isChild = -1;
#ifdef __aarch64__
    asm(
        "mov x16, 0x2\n"
        "svc 0x80\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        : "=r"(retval), "=r"(isChild)
        );
#else
    asm(
        ".intel_syntax noprefix\n"
        "mov eax, 0x2000002\n"
        "syscall\n"
        "mov %V0, rax\n"
        "mov %V1, rdx\n"
        : "=r"(retval), "=r"(isChild)
        );

#endif
    debug("retval=%d isParent=%x\n",retval,isChild);
    if (retval <= 0) return retval;
    //do our stuff
    
    {
        if (isChild){
            //child
            kill(retval, SIGSTOP);
        }else{
            //parent
            giveCSDEBUGToPid(retval);
            {
                int asd = 0;
                waitpid(retval, &asd, WUNTRACED);
            }
            kill(retval, SIGCONT);
        }
    }
    
    //final
error:
    if (isChild){
//        _current_pid = 0;
        retval = 0;
    }
    return retval;
}
    
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
            err = trustCDHashForCSSuperBlob(findCodeDirectory((const CS_SuperBlob*)buf));
        error:
            lseek(fd, lpos, SEEK_SET);
            safeFree(buf);
            break;
        }
        default:
            break;
    }
    errno = (int)msyscall(AUE_FCNTL, fd, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    return errno == 0 ? 0 : -1;
}

int my_fcntl(int fd, int cmd, ...){
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
DYLD_INTERPOSE(my_fcntl, fcntl);

void* find_dyld_address(void){
    kern_return_t err = 0;
    task_dyld_info_data_t task_dyld_info = {};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    err = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
    const struct dyld_all_image_infos* all_image_infos = (const struct dyld_all_image_infos*)task_dyld_info.all_image_info_addr;
    return (void*)all_image_infos->dyldImageLoadAddress;
}

int hookAddr(void *addr, void *target){
    int err = 0;
    kern_return_t kret = 0;
    uint8_t *hooktgt = NULL;
    uint8_t *target_address = NULL;

    hooktgt = (uint8_t*)addr;

    debug("Applying hook\n");
    assure(!(kret = vm_protect(mach_task_self_, (mach_vm_address_t)hooktgt, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t), 0, VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_COPY)));
    {
        vm_prot_t cur = 0;
        vm_prot_t max = 0;
        assure(!(kret = vm_remap(mach_task_self_, (mach_vm_address_t*)&target_address, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t), 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, mach_task_self_, (mach_vm_address_t)hooktgt, false, &cur, &max, VM_INHERIT_NONE)));
        assure(!(kret = vm_protect(mach_task_self_, (mach_vm_address_t)target_address, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t), 0, VM_PROT_READ | VM_PROT_WRITE)));
        memcpy(target_address, DYLD_PATCH, sizeof(DYLD_PATCH)-1);
        uint64_t ptr = (uint64_t)target;
        ptr &= ~0xffff000000000000;
#ifdef __aarch64__
        *(void**)&target_address[sizeof(DYLD_PATCH)-1] = (void*)ptr;
#else
        *(void**)&target_address[2] = (void*)ptr;
#endif
    }
    
error:
    if (target_address){
        kret = vm_deallocate(mach_task_self_, (mach_vm_address_t)target_address, (sizeof(DYLD_NEEDLE)-1)+sizeof(uint64_t));
        if (!err) err = kret;
    }
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

int hookFork(void){
    int err = 0;
    uint8_t *hooktgt = NULL;
    
    uint8_t *nearbyLoc = (uint8_t*)mach_ports_register;
    size_t searchSize = PAGE_SIZE*10;
    
    hooktgt = memmem(nearbyLoc, searchSize, FORK_NEEDLE, sizeof(FORK_NEEDLE)-1);
    if (!hooktgt){
        hooktgt = memmem(nearbyLoc-searchSize, searchSize, FORK_NEEDLE, sizeof(FORK_NEEDLE)-1);
    }
    assure(hooktgt);
#ifdef __aarch64__
    {
        for (int i=0; i<10; i++){
            if (*(uint32_t*)hooktgt == 0xd503237f) break;
            hooktgt-=4;
        }
        debug("failed to find bof!");
        assure(0);
    foundbof:;
    }
#endif
    err = hookAddr(hooktgt, my_fork_internal);
error:
    return err;
}

#ifdef XCODE
int main(int argc, const char * argv[], const char **envp) {
#else
__attribute__((constructor))  int constructor(){
#endif
    
    {
        //remove injected env vars
        unsetenv(INJECT_KEY2);
        char *dyldvar = getenv(INJECT_KEY);
        char *origvar = strstr(dyldvar, ":");
        if (origvar) setenv(INJECT_KEY, origvar+1, 1);
        else unsetenv(INJECT_KEY);
    }
    
    kern_return_t kret = 0;
    mach_port_t JBDPort = MACH_PORT_NULL;
    if ((kret = bootstrap_look_up(bootstrap_port, "jb-global-jbd", &JBDPort))){
#ifndef XCODE
        debug("Failed to get JBD port\n");
        return 0;
#endif
    }

    if (!(gJBDPipe = xpc_pipe_create_from_port(JBDPort, 0))){
#ifndef XCODE
        debug("Failed to get JBD pipe\n");
        return 0;
#endif
    }
    
    if (giveCSDEBUGToPid(getpid())){
        debug("Failed to get CSDEBUG\n");
        return 0;
    }

    if (hookFCNTLDyld()){
        debug("Failed to hook FCNTL dyld\n");
        return 0;
    }
    
    if (hookFork()){
        debug("Failed to hook fork\n");
        return 0;
    }
    
    debug("All done!\n");
    return 0;
}
