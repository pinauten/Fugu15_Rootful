#ifndef __KERNEL_BASE_H__
#define __KERNEL_BASE_H__

#include <mach/mach.h>
#include <stdint.h>

uint64_t mcbc_our_task_from_holder(mach_port_t holder, uint64_t holder_addr);

#endif
