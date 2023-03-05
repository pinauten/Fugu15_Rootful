//
//  flush.c
//  jailbreakd/CBridge
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

#include <stdint.h>

uint64_t gUserReturnDidHappen;

void dmb_sy(void) {
    asm volatile("dmb sy");
}
