#include "mcast.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>

int mcbc_mcast_race_sock;

int mcbc_mcast_join_group(int ip)
{
    struct group_req mreq = { 0 };
    struct sockaddr_in6 sin6 = {0};
    
    mreq.gr_interface = 1;

    sin6.sin6_len = sizeof(sin6);
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = 7878;
    sin6.sin6_addr.__u6_addr.__u6_addr32[3] = 0;
    sin6.sin6_addr.__u6_addr.__u6_addr32[2] = 0;
    sin6.sin6_addr.__u6_addr.__u6_addr32[1] = ip;
    sin6.sin6_addr.__u6_addr.__u6_addr32[0] = (htonl(0xFF000000));

    memcpy(&mreq.gr_group, &sin6, sizeof(sin6));
    
    mreq.gr_interface = 1;
    
    return setsockopt(mcbc_mcast_race_sock, IPPROTO_IPV6, MCAST_JOIN_GROUP, &mreq, sizeof(mreq));
}

void mcbc_mcast_increase_race_reliability(void)
{
    struct group_req mreq = { 0 };
    struct sockaddr_in6 sin6 = {0};
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    
    mreq.gr_interface = 1;

    sin6.sin6_len = sizeof(sin6);
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = 7878;
    sin6.sin6_addr.__u6_addr.__u6_addr32[3] = 0;
    sin6.sin6_addr.__u6_addr.__u6_addr32[2] = 0;
    sin6.sin6_addr.__u6_addr.__u6_addr32[1] = 0;
    sin6.sin6_addr.__u6_addr.__u6_addr32[0] = (htonl(0xFF000000));

    memcpy(&mreq.gr_group, &sin6, sizeof(sin6));

    for (int i = 0; i < 3000; ++i)
    {
        ((struct sockaddr_in6 *)(&mreq.gr_group))->sin6_addr.__u6_addr.__u6_addr32[1] = i + (3000 * 3000);
        setsockopt(s, IPPROTO_IPV6, MCAST_JOIN_GROUP, &mreq, sizeof(mreq));
    }
}
