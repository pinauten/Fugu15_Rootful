//
//  CBridge.h
//  CBridge
//
//  Created by Linus Henze on 23.01.23.
//

#ifndef CBridge_h
#define CBridge_h

#include <stdint.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <ptrauth.h>

// PAC
uint64_t signPtrUnauthenticated(uint64_t ptr, void *storage, uint16_t context, bool bound, uint8_t key);

// Not called from Swift -> Ignore return/argument types
void my_sandbox_check_by_audit_token(void);
void my_kill(void);

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

extern uint64_t gUserReturnDidHappen;

static inline void set_thread_state_to_pac_loop(arm_thread_state64_t *state) {
    arm_thread_state64_set_pc_fptr(*state, (void*) pac_loop);
}

#endif /* CBridge_h */
