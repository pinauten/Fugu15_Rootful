//
//  KRWC.h
//  KRWC
//
//  Created by Linus Henze on 2023-01-13.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

#ifndef KRWC_h
#define KRWC_h

#include <stdint.h>
#include "../badRecovery/offsets.h"
#include "../badRecovery/badRecovery.h"
#include "../badRecovery/tlbFail.h"
#include "../badRecovery/kernel.h"

typedef uintptr_t (*patchfinder_get_offset_func)(const char * _Nonnull name);

// tfp0
void krw_init_tfp0(mach_port_t port);
int krw_kread_tfp0(uintptr_t kernSrc, void * _Nonnull dst, size_t size);
int krw_kwrite_tfp0(uintptr_t kernDst, const void * _Nonnull src, size_t size);
uintptr_t krw_kbase_tfp0(void);
void krw_cleanup_tfp0(void);

// weightBufs
int krw_init_weightBufs(void);
int krw_kread_weightBufs(uintptr_t kernSrc, void * _Nonnull dst, size_t size);
int krw_kwrite_weightBufs(uintptr_t kernDst, const void * _Nonnull src, size_t size);
uintptr_t krw_kbase_weightBufs(void);
int krw_cleanup_weightBufs(void);

// mcbc
int krw_init_mcbc(void);
int krw_kread_mcbc(uintptr_t kernSrc, void * _Nonnull dst, size_t size);
int krw_kwrite_mcbc(uintptr_t kernDst, const void * _Nonnull src, size_t size);
uintptr_t krw_kbase_mcbc(void);
int krw_cleanup_mcbc(void);

// generic
int krw_kread(uintptr_t kernSrc, void * _Nonnull dst, size_t size);
int krw_kwrite(uintptr_t kernDst, const void * _Nonnull src, size_t size);

extern uint64_t gUserReturnDidHappen;

static inline void set_thread_state_to_pac_loop(arm_thread_state64_t * _Nonnull state) {
    arm_thread_state64_set_pc_fptr(*state, (void*) pac_loop);
}

static inline void dmb_sy() {
    asm volatile("dmb sy");
}

#endif /* KRWC_h */
