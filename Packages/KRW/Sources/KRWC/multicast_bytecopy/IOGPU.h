#ifndef __IOGPU_H__
#define __IOGPU_H__

#include "iokit.h"

#include <mach/mach.h>
#include <stdint.h>

io_connect_t mcbc_IOGPU_init(void);
void mcbc_IOGPU_exit(io_connect_t uc);

uint32_t mcbc_IOGPU_create_command_queue(io_connect_t uc, uint64_t member);

int mcbc_IOGPU_get_command_queue_extra_refills_needed(void);

#endif
