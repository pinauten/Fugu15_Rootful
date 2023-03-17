#include "libdyldhook.h"

#include <mach/mach.h>
#include <mach/machine/ndr_def.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "CodeSignature.h"

#define HOOK(name) MACHOMERGER_HOOK_##name

#define safeClose(fd) do{if ((fd) != -1){close(fd); fd = -1;}}while(0)
#define safePFree(buf) do{if ((buf)){pfree(buf); buf = NULL;}}while(0)
#define assure(cond) do {if (!(cond)){err = __LINE__; goto error;}}while(0)

extern mach_port_t mach_reply_port(void);

#undef bzero

kern_return_t fufuguguRequest(struct FuFuGuGuMsg *msg, struct FuFuGuGuMsgReply *reply);

mach_port_t gReplyPort = 0;
mach_port_t gBootstrapPort = 0;

mach_port_t mig_get_reply_port(void) {
    if (!gReplyPort) {
        gReplyPort = mach_reply_port();
    }
    
    return gReplyPort;
}

int giveCSDebugToPID(int pid, int forceDisablePAC, int *pacDisabled) {
    *pacDisabled = 0;
    
    struct FuFuGuGuMsgCSDebug csdebug;
    bzero(&csdebug, sizeof(csdebug));
    
    struct FuFuGuGuMsgReplyCSDebug csdebugRpl;
    bzero(&csdebugRpl, sizeof(csdebugRpl));
    
    csdebug.base.hdr.msgh_size = sizeof(csdebug);
    csdebugRpl.base.hdr.msgh_size = sizeof(csdebugRpl);
    
    csdebug.base.action = FUFUGUGU_ACTION_CSDEBUG;
    csdebug.pid = pid;
    csdebug.forceDisablePAC = forceDisablePAC;
    
    kern_return_t kr = fufuguguRequest(&csdebug.base, &csdebugRpl.base);
    if (kr != KERN_SUCCESS)
        return kr;
    
    if (csdebugRpl.base.status)
        return csdebugRpl.base.status;
    
    *pacDisabled = csdebugRpl.pacDisabled;
    return 0;
}

int trustCDHash(const uint8_t *hash, size_t hashSize, uint8_t hashType) {
    struct FuFuGuGuMsgTrust20 trust;
    bzero(&trust, sizeof(trust));
    
    struct FuFuGuGuMsgReply trustRpl;
    bzero(&trustRpl, sizeof(trustRpl));
    
    trust.base.hdr.msgh_size = sizeof(trust);
    trustRpl.hdr.msgh_size = sizeof(trustRpl);
    
    trust.base.action = FUFUGUGU_ACTION_TRUST;
    trust.hashType = 2;
    trust.hashLen = 20;
    memcpy(trust.hash, hash, 20);
    
    kern_return_t kr = fufuguguRequest(&trust.base, &trustRpl);
    if (kr != KERN_SUCCESS)
        return kr;
    
    return trustRpl.status;
}

kern_return_t fufuguguRequest(struct FuFuGuGuMsg *msg, struct FuFuGuGuMsgReply *reply) {
    mach_port_t replyPort = mig_get_reply_port();
    
    if (!replyPort)
        return KERN_FAILURE;
    
    if (!gBootstrapPort)
        task_get_bootstrap_port(task_self_trap(), &gBootstrapPort);
    
    if (!gBootstrapPort)
        return KERN_FAILURE;
    
    msg->magic = FUFUGUGU_MSG_MAGIC;
    
    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    // size already set
    msg->hdr.msgh_remote_port  = gBootstrapPort;
    msg->hdr.msgh_local_port   = replyPort;
    msg->hdr.msgh_voucher_port = 0;
    msg->hdr.msgh_id           = 0x40000000;
    
    kern_return_t kr = mach_msg(&msg->hdr, MACH_SEND_MSG, msg->hdr.msgh_size, 0, 0, 0, 0);
    if (kr != KERN_SUCCESS)
        return kr;
    
    kr = mach_msg(&reply->hdr, MACH_RCV_MSG, 0, reply->hdr.msgh_size, replyPort, 0, 0);
    if (kr != KERN_SUCCESS)
        return kr;
    
    // Get rid of any rights we might have received
    mach_msg_destroy(&reply->hdr);
    return KERN_SUCCESS;
}

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

void *palloc(void) {
    uintptr_t addr = 0;
    kern_return_t kr = vm_allocate(task_self_trap(), &addr, 0x4000, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
        return NULL;
    
    return (void*) addr;
}

void pfree(void *ptr) {
    vm_deallocate(task_self_trap(), (vm_address_t) ptr, 0x4000);
}

int HOOK(__fcntl)(int fd, int cmd, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6, void *arg7, void *arg8) {
    int hideErrors = 0;
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
            assure(siginfo->fs_blob_size <= 0x4000);
            assure(buf = (uint8_t*)palloc());
            lseek(fd, siginfo->fs_file_start + (uint64_t)siginfo->fs_blob_start, SEEK_SET);
            assure(read(fd, buf, siginfo->fs_blob_size));
            
            err = trustCodeDirectories(NULL, (const CS_SuperBlob *) buf, siginfo->fs_file_start);
        error:
            lseek(fd, lpos, SEEK_SET);
            safePFree(buf);
            hideErrors = 1;
            break;
        }
            
        case F_CHECK_LV:
            hideErrors = 1;
            break;
            
        default:
            break;
    }
    int res = (int)msyscall_errno(0x5C, fd, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    if (hideErrors && res == -1) {
        if (cmd == F_ADDFILESIGS_RETURN) {
            fsignatures_t *siginfo = (fsignatures_t *)arg1;
            siginfo->fs_file_start = -1;
        }
        
        return 0;
    }
    
    return res;
}

void libdyldhook_init(void *kernelParams) {
    int pacDisabled = 0;
    
    if (getpid() != 1)
        giveCSDebugToPID(getpid(), 1, &pacDisabled);
    
    // TODO: Handle pacDisabled
}
