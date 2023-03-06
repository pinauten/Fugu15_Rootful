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

int krw_init(patchfinder_get_offset_func _Nonnull func);

int krw_kread(uintptr_t kernSrc, void * _Nonnull dst, size_t size);
int krw_kwrite(uintptr_t kernDst, const void * _Nonnull src, size_t size);

uintptr_t krw_kbase(void);

void cleanup(void);

extern uint64_t gUserReturnDidHappen;

static inline void set_thread_state_to_pac_loop(arm_thread_state64_t * _Nonnull state) {
    arm_thread_state64_set_pc_fptr(*state, (void*) pac_loop);
}

static inline void dmb_sy() {
    asm volatile("dmb sy");
}

#endif /* KRWC_h */
