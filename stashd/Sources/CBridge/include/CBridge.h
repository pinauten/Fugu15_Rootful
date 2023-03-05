//
//  CBridge.h
//  jailbreakd/CBridge
//
//  Created by Linus Henze on 2023-01-15.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

#ifndef CBridge_h
#define CBridge_h

#include <mach/mach.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <stdbool.h>
#include <ptrauth.h>

kern_return_t bootstrap_check_in(mach_port_t bp,
                                 const char *service_name,
                                 mach_port_t *sp);

int main_jbdaemon(int argc, char **argv);

void dmb_sy(void);

typedef struct {
    uint64_t unk;
    uint64_t x[29];
    uint64_t fp;
    uint64_t lr;
    uint64_t sp;
    uint64_t pc;
    uint32_t cpsr;
    // Other stuff
    uint64_t other[70];
} kRegisterState;

extern void pac_loop(void);

extern volatile uint64_t gUserReturnDidHappen;

static inline void set_thread_state_to_pac_loop(arm_thread_state64_t *state) {
    arm_thread_state64_set_pc_fptr(*state, (void*) pac_loop);
}

#endif /* CBridge_h */
