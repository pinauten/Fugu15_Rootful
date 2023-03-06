#ifndef __IOSURFACEROOT_H__
#define __IOSURFACEROOT_H__

#include "iokit.h"

#include <IOSurface/IOSurfaceRef.h>
#include <stdint.h>

io_connect_t mcbc_IOSurfaceRoot_init(void);
void mcbc_IOSurfaceRoot_exit(io_connect_t uc);

uint32_t mcbc_IOSurfaceRoot_create_surface_fast(io_connect_t uc);

kern_return_t mcbc_IOSurfaceRoot_lookup_surface(io_connect_t uc, uint32_t surf_id);

int mcbc_IOSurfaceRoot_release_surface(io_connect_t uc, uint32_t surf_id);
void mcbc_IOSurfaceRoot_release_all(io_connect_t uc);

uint32_t mcbc_IOSurfaceRoot_get_surface_use_count(io_connect_t uc, uint32_t surf_id);

void mcbc_IOSurfaceRoot_set_compressed_tile_data_region_memory_used_of_plane(io_connect_t uc, uint32_t surf_id, uint64_t tile);

uint32_t mcbc_IOSurfaceRoot_cause_array_size_to_be_0x4000(void);

#endif
