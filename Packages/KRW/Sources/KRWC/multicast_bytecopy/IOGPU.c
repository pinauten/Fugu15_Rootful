#include "IOGPU.h"

#include <sys/utsname.h>

io_connect_t mcbc_IOGPU_init(void)
{
    mach_port_t mp = MACH_PORT_NULL;
    kern_return_t IOMasterPort(mach_port_t, mach_port_t *);
    IOMasterPort(MACH_PORT_NULL, &mp);
    io_connect_t uc;

    io_service_t s = IOServiceGetMatchingService(mp, IOServiceMatching("AGXAccelerator"));
    if (s == MACH_PORT_NULL)
    {
        return 0;
    }
    
    if (IOServiceOpen(s, mach_task_self(), 1, &uc) != KERN_SUCCESS)
    {
        return 0;
    }
    
    return uc;
}

void mcbc_IOGPU_exit(io_connect_t uc)
{
    IOServiceClose(uc);
}

uint32_t mcbc_IOGPU_create_command_queue(io_connect_t uc, uint64_t member)
{
    uint64_t outStructCnt = 0x10;
    uint32_t inStructCnt = 0x408;
    uint8_t inStruct[0x408] = {0};
    uint8_t outStruct[0x10] = {0};
    
    // avoid null termination
    memset(inStruct, 0x01, 0x30);
    *(uint64_t *)(inStruct + 0x30) = member;

    kern_return_t kr = IOConnectCallStructMethod(uc, 7, inStruct, inStructCnt, outStruct, (size_t *)&outStructCnt);

    if (kr)
        return 0;
    
    return 1;
}

int mcbc_IOGPU_get_command_queue_extra_refills_needed(void)
{
    struct utsname u;
    uname(&u);
    
    // iPhone 7
    // iPhone 11
    // iPhone 12
    // iPhone 13
    // iPad (A10/A10X) - iPad7,*
    // iPad (A13) - iPad12,*
    // iPad (A14/M1) - iPad13,*
    // iPad (A15) - iPad14,*
    if (
       strstr(u.machine, "iPhone9,")
    || strstr(u.machine, "iPod9,")
    || strstr(u.machine, "iPhone12,")
    || strstr(u.machine, "iPhone13,")
    || strstr(u.machine, "iPhone14,")
    || strstr(u.machine, "iPad7,")
    || strstr(u.machine, "iPad12,")
    || strstr(u.machine, "iPad13,")
    || strstr(u.machine, "iPad14,")
    )
    {
        return 1;
    }
    // iPhone 8, X
    // iPhone XS, XR
    // iPad (A12X/A12Z) - iPad8,*
    // iPad (A12) - iPad11,*
    else if (
       strstr(u.machine, "iPhone10,")
    || strstr(u.machine, "iPhone11,")
    || strstr(u.machine, "iPad8,")
    || strstr(u.machine, "iPad11,")
    )
    {
        return 3;
    }
    
    printf("IOGPU_get_command_queue_extra_refills_needed(): Unknown device %s! May panic in generic part until correct number 1-5 is provided for this device!\n", u.machine);
    
    return -1;
}
