//
//  dummy.c
//  KRWC
//
//  Created by Linus Henze on 2023-01-13.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//

#include "include/KRWC.h"

extern int exploit(void);
extern uint32_t kread32(uint64_t address);
extern uintptr_t gKernelBase;

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
        } else if (bytesToRead == 3) {
            *(uint16_t*)v32 = (uint16_t) value;
            ((uint8_t*)v32)[2] = (uint8_t) (value >> 16);
        } else if (bytesToRead == 2) {
            *(uint16_t*)v32 = (uint16_t) value;
        } else if (bytesToRead == 1) {
            *(uint8_t*)v32 = (uint8_t) value;
        }
        
        size -= bytesToRead;
    }
    
    return 0;
}

int krw_kwrite(uintptr_t kernDst, const void * _Nonnull src, size_t size) {
    return 2;
}

uintptr_t krw_kbase(void) {
    return gKernelBase;
}
