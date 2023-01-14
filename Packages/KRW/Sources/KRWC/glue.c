//
//  glue.c
//  KRWC
//
//  Created by Linus Henze on 2023-01-13.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//

#include "include/KRWC.h"
#include "badRecovery/offsets.h"

#include <string.h>
#include <stdbool.h>

extern int exploit(void);
extern void kwrite64(uint64_t address, uint64_t value);
extern uint64_t kread64(uint64_t address);
extern uint32_t kread32(uint64_t address);
extern uintptr_t gKernelBase;

KernelOffsetInfo gOffsets;
uint64_t gOurTask;
uint64_t gKernelPmap;

int krw_init(patchfinder_get_offset_func _Nonnull func) {
    return exploit();
}

int krw_kread(uintptr_t kernSrc, void * _Nonnull dst, size_t size) {
    uint32_t *v32 = (uint32_t*) dst;
    
    while (size) {
        size_t bytesToRead = (size > 4) ? 4 : size;
        uint32_t value = kread32(kernSrc);
        kernSrc += 4;
        
        if (bytesToRead == 4) {
            *v32++ = value;
        } else {
            memcpy(dst, &value, bytesToRead);
        }
        
        size -= bytesToRead;
    }
    
    return 0;
}

int krw_kwrite(uintptr_t kernDst, const void * _Nonnull src, size_t size) {
    uint8_t *v8 = (uint8_t*) src;
    
    while (size >= 8) {
        kwrite64(kernDst, *(uint64_t*)v8);
        size -= 8;
        v8 += 8;
        kernDst += 8;
    }
    
    if (size) {
        uint64_t val = kread64(kernDst);
        memcpy(&val, v8, size);
        kwrite64(kernDst, val);
    }
    
    return 0;
}

uintptr_t krw_kbase(void) {
    return gKernelBase;
}

bool kernread (uint64_t addr, size_t len, void *buffer) {
    return krw_kread(addr, buffer, len) == 0;
}

bool kernwrite(uint64_t addr, void *buffer, size_t len) {
    return krw_kwrite(addr, buffer, len);
}
