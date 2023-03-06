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

mach_port_t kernPort = 0;

int krw_init(patchfinder_get_offset_func _Nonnull func) {
    if (task_for_pid(mach_task_self_, 0, &kernPort) == KERN_SUCCESS) {
        /*asm volatile(
            "mov x0, 0\n"
                     "mov x1, 1\n"
                     "mov x2, 2\n"
                     "mov x3, 3\n"
                     "mov x4, 4\n"
                     "mov x5, 5\n"
                     "mov x6, 6\n"
                     "mov x7, 7\n"
                     "mov x8, 8\n"
                     "mov x9, 9\n"
                     "mov x10, 10\n"
                     "mov x11, 11\n"
                     "mov x12, 12\n"
                     "mov x13, 13\n"
                     "mov x14, 14\n"
                     "mov x15, 15\n"
                     "mov x16, 16\n"
                     "mov x17, 17\n"
                     "mov x18, 18\n"
                     "mov x19, 19\n"
                     "mov x20, 20\n"
                     "mov x21, 21\n"
                     "mov x22, 22\n"
                     "mov x23, 23\n"
                     "mov x24, 24\n"
                     "mov x25, 25\n"
                     "mov x26, 26\n"
                     "mov x27, 27\n"
                     "mov x28, 28\n"
                     "mov x29, 29\n"
            "mov x16, 214\n"
            "svc 0x80\n"
        );*/
        
        uintptr_t base = 0;
        asm volatile(
            "mov x16, 213\n"
            "svc 0x80\n"
            "mov %0, x0\n"
            : "=r"(base)
        );
        
        gKernelBase = base << 0xC;
        
        return 0;
    }
    
    return exploit();
}

int krw_kread(uintptr_t kernSrc, void * _Nonnull dst, size_t size) {
    if (kernPort != 0) {
        vm_size_t outsize = 0;
        return vm_read_overwrite(kernPort, kernSrc, size, dst, &outsize);
    }
    
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
    if (kernPort != 0) {
        vm_size_t outsize = 0;
        return vm_write(kernPort, kernDst, src, (mach_msg_type_number_t) size);
    }
    
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
