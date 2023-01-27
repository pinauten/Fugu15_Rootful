//
//  flush.c
//  jailbreakd/CBridge
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

void dmb_sy(void) {
    asm volatile("dmb sy");
}
