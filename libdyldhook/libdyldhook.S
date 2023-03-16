#define MAKE_TRAMPOLINE_ALIAS(to, alias) .global _##alias %% .global _MACHOMERGER_TRAMPOLINE_##to## %% _##alias: %% _MACHOMERGER_TRAMPOLINE_##to##: %% b .
#define MAKE_TRAMPOLINE(to) MAKE_TRAMPOLINE_ALIAS(to, to)

#define SYSCALL_PROLOGUE stp x0, x1, [sp, -16]! %% stp x2, x3, [sp, -16]! %% stp x4, x5, [sp, -16]! %% stp x6, x7, [sp, -16]!
#define SYSCALL_EPILOGUE ldp x6, x7, [sp], 16 %% ldp x4, x5, [sp], 16 %% ldp x2, x3, [sp], 16 %% ldp x0, x1, [sp], 16

#define DEF_SYSCALL(name, num)  .global _##name %% _##name: %% SYSCALL_PROLOGUE %% mov x16, num %% svc #0x80 %% mov x16, x0 %% SYSCALL_EPILOGUE %% bcc name##_end %% cmp x16, #4 %% beq _##name %% mov x16, #-1 %% name##_end: %% mov x0, x16 %% ret
#define DEF_MACHTRAP(name, num) .global _##name %% _##name: %% mov x16, -num %% svc #0x80 %% ret

.text
.align 4

.global _MACHOMERGER_START_HOOK
_MACHOMERGER_START_HOOK:
    // Copy-Paste from dyld
    mov    x0, sp
    mov    x19, sp
    and    sp, x0, #~15 // force 16-byte alignment of stack
    mov    fp, #0

    // Call init
    bl _libdyldhook_init

    // Restore stack
    mov sp, x19

    // Jump to real start
    b _MACHOMERGER_REAL_START

MAKE_TRAMPOLINE(MACHOMERGER_REAL_START)
MAKE_TRAMPOLINE(cerror)
MAKE_TRAMPOLINE_ALIAS(__getpid, getpid)
MAKE_TRAMPOLINE_ALIAS(__bzero, bzero)
MAKE_TRAMPOLINE(mach_msg)
MAKE_TRAMPOLINE(mach_msg_destroy)
MAKE_TRAMPOLINE(mach_reply_port)
MAKE_TRAMPOLINE(memset)
MAKE_TRAMPOLINE(task_self_trap)
MAKE_TRAMPOLINE(__stack_chk_fail)
MAKE_TRAMPOLINE_ALIAS(_kernelrpc_mach_vm_allocate_trap, vm_allocate)
MAKE_TRAMPOLINE_ALIAS(_kernelrpc_mach_vm_deallocate_trap, vm_deallocate)

DEF_SYSCALL(read, 3)
DEF_SYSCALL(lseek, 199)

.data
.global ___stack_chk_guard
___stack_chk_guard:
    .quad 0x1337
