#ifndef __MCAST_H__
#define __MCAST_H__

extern int mcbc_mcast_race_sock;

void mcbc_mcast_increase_race_reliability(void);
int mcbc_mcast_join_group(int ip);

#endif
