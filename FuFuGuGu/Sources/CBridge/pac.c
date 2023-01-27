//
//  pac.c
//  FuFuGuGu/CBridge
//
//  Created by Linus Henze on 24.01.23.
//

#include <stdio.h>
#include <stdbool.h>
#include <ptrauth.h>

/*
 case IA = 0
 case IB = 1
 case DA = 2
 case DB = 3
 */

uint64_t signPtrUnauthenticated(uint64_t ptr, void *storage, uint16_t context, bool bound, uint8_t key) {
    uint64_t data = bound ? (uint64_t) storage : 0;
    data &= 0xFFFFFFFFFFFFULL;
    data |= ((uint64_t) context) << 48;
    
    if (key == 0) {
        return (uint64_t) ptrauth_sign_unauthenticated((void*) ptr, ptrauth_key_asia, data);
    } else if (key == 1) {
        return (uint64_t) ptrauth_sign_unauthenticated((void*) ptr, ptrauth_key_asib, data);
    } else if (key == 2) {
        return (uint64_t) ptrauth_sign_unauthenticated((void*) ptr, ptrauth_key_asda, data);
    } else if (key == 3) {
        return (uint64_t) ptrauth_sign_unauthenticated((void*) ptr, ptrauth_key_asdb, data);
    }
}
