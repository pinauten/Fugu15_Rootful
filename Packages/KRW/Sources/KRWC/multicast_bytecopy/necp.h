#ifndef __NECP_H__
#define __NECP_H__

#include <stdlib.h>
#include <stdint.h>

int mcbc_necp_open(int flags);
int mcbc_necp_client_action(int necp_fd, uint32_t action, uint8_t *client_id, size_t client_id_len, uint8_t *buffer, size_t buffer_size);

#endif
