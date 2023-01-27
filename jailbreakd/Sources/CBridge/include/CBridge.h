//
//  CBridge.h
//  jailbreakd/CBridge
//
//  Created by Linus Henze on 2023-01-15.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

#ifndef CBridge_h
#define CBridge_h

#include <mach/mach.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <stdbool.h>

kern_return_t bootstrap_check_in(mach_port_t bp,
                                 const char *service_name,
                                 mach_port_t *sp);

int main_jbdaemon(int argc, char **argv);

void dmb_sy(void);

#endif /* CBridge_h */
