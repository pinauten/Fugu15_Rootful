//
//  mig.swift
//  jailbreakd
//
//  Created by Linus Henze on 2023-01-15.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import Darwin
import CBridge

//
// Note: Currently MIG methods have to manage all ports, regardless of the return code
//

@_cdecl("set_kernel_infos")
public func set_kernel_infos(_ server: mach_port_t) -> kern_return_t {
    print("set_kernel_infos")
    
    mach_port_deallocate(mach_task_self_, server)
    
    return KERN_SUCCESS
}

@_cdecl("set_bootstrap_port")
public func set_bootstrap_port(_ server: mach_port_t, bp: mach_port_t) -> kern_return_t {
    mach_port_deallocate(mach_task_self_, server)
    
    guard needsBootstrapPort else {
        print("[jailbreakd] set_bootstrap_port but don't need one!")
        mach_port_deallocate(mach_task_self_, bp)
        return KERN_FAILURE
    }
    
    var sp: mach_port_t = 0
    let kr = bootstrap_check_in(bootstrap_port, serviceName, &sp)
    guard kr == KERN_SUCCESS else {
        print("[jailbreakd] bootstrap_check_in failed: \(kr)")
        mach_port_deallocate(mach_task_self_, bp)
        return KERN_INVALID_ARGUMENT
    }
    
    mach_port_destroy(mach_task_self_, servicePort)
    servicePort = sp
    
    return KERN_SUCCESS
}
