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

// PAC
uint64_t signPtrUnauthenticated(uint64_t ptr, void *storage, uint16_t context, bool bound, uint8_t key);

// Not called from Swift -> Ignore return/argument types
void my_sandbox_check_by_audit_token(void);
void my_kill(void);

#endif /* CBridge_h */
