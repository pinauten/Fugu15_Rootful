#include "necp.h"

#include <sys/syscall.h>
#include <unistd.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

int mcbc_necp_open(int flags)
{
    return syscall(SYS_necp_open, flags);
}

int mcbc_necp_client_action(int necp_fd, uint32_t action, uint8_t *client_id, size_t client_id_len, uint8_t *buffer, size_t buffer_size)
{
    return syscall(SYS_necp_client_action, necp_fd, action, client_id, client_id_len, buffer, buffer_size);
}
