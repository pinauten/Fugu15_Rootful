#ifndef __SPRAY_H__
#define __SPRAY_H__

#include <mach/mach.h>
#include <stdint.h>

mach_port_t mcbc_spray_data_kalloc_kmsg_single(uint8_t *data, unsigned int size);
mach_port_t *mcbc_spray_data_kalloc_kmsg(uint8_t *data, unsigned int size, unsigned int count);
void mcbc_spray_data_kalloc_kmsg_on_ports(uint8_t *data, unsigned int size, unsigned int count, mach_port_t *ports);
mach_port_t *mcbc_spray_default_kalloc_ool_ports(unsigned int size, unsigned int count, mach_port_t *ool_ports);
mach_port_t *mcbc_spray_default_kalloc_ool_ports_with_data_kalloc_size(unsigned int size, unsigned int count, mach_port_t *ool_ports, unsigned int data_kalloc_size);

void mcbc_spray_default_kalloc_ool_ports_on_port(unsigned int size, unsigned int count, mach_port_t *ool_ports, mach_port_t p);
void mcbc_spray_default_kalloc_ool_ports_with_data_kalloc_size_on_port(unsigned int size, mach_port_t *ool_ports, unsigned int data_kalloc_size, mach_port_t p);
int mcbc_spray_default_kalloc_necp(int necp_fd, uint8_t *b, uint32_t sz);

kern_return_t mcbc_spray_kmsg_on_port(mach_port_t port, void *data, size_t size);

mach_port_t *mcbc_spray_ports(unsigned int count);
mach_port_t *mcbc_spray_ports_with_context(unsigned int count, uint64_t context);


#endif
