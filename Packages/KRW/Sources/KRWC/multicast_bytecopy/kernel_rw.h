#ifndef __KERNEL_RW_H__
#define __KERNEL_RW_H__

#define KERNEL_RW_SIZE_FAKE_ARRAY 0x4000

#include "iokit.h"

void mcbc_kernel_rw_preinit(uint64_t kaddr, uint8_t *buf, size_t n);
int mcbc_kernel_rw_init(io_connect_t uc, uint32_t surf_id, int read_pipe, int write_pipe);

uint32_t mcbc_kread32(uint64_t kaddr);
uint64_t mcbc_kread64(uint64_t kaddr);

void mcbc_kwrite32(uint64_t kaddr, uint32_t val);
void mcbc_kwrite64(uint64_t kaddr, uint64_t val);

#endif
