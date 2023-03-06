#ifndef __PORT_UTILS_H__
#define __PORT_UTILS_H__

#include <mach/mach.h>

mach_port_t mcbc_port_new(void);

void mcbc_port_destroy(mach_port_t p);
void port_deallocate(mach_port_t p);

void mcbc_port_destroy_n(mach_port_t *p, unsigned int count);
void mcbc_port_deallocate_n(mach_port_t *p, unsigned int count);

int mcbc_port_has_msg(mach_port_t p);
int mcbc_port_peek_trailer_size(mach_port_t p);

void mcbc_port_receive_msg(mach_port_t p, uint8_t *buf, unsigned int size);
void mcbc_port_receive_msg_n(mach_port_t *p, unsigned int count);

void mcbc_port_receive_msg_and_deallocate_n(mach_port_t *p, unsigned int count);

#endif
