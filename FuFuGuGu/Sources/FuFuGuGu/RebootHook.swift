//
//  RebootHook.swift
//  stashd
//
//  Created by Linus Henze on 2023-03-05.
//

import Foundation
import KernelPatchfinder
import SwiftXPC
import PatchfinderUtils

@_cdecl("swift_reboot_hook")
public func swift_reboot_hook(_ consoleFD: Int32) {
    console = consoleFD
    
    log("Launching stashd...")
    
    do {
        let cpu_ttep = try KRW.r64(virt: KRW.slide(virt: KRW.patchfinder.cpu_ttep!))
        
        let cArgs: [UnsafeMutablePointer<CChar>?] = try [
            strdup("/usr/bin/stashd"),
            strdup("launchedByFuFuGuGu15"),
            strdup(String(KRW.kbase())),
            strdup(String(KRW.kslide())),
            strdup(String(PPL_MAP_ADDR)),
            strdup(String(cpu_ttep)),     // For easy virt-to-phys
            nil
        ]
        defer { for arg in cArgs { free(arg) } }
        
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_START_SUSPENDED))
        
        var child: pid_t = 0
        let res = posix_spawn(&child, cArgs[0], nil, &attr, cArgs, environ)
        guard res == 0 else {
            log("Uh-Oh! Failed to launch jailbreakd: \(res)")
            return
        }
        
        log("stashd launched!")
        
        guard try KRW.initPPLBypass(inProcess: child) else {
            kill(child, SIGKILL)
            log("Uh-Oh! Failed to init PPL r/w jailbreakd")
            return
        }
        
        log("PPL bypass inited in stashd!")
        
        kill(child, SIGCONT)
        
        var servicePort: mach_port_t = 0
        while true {
            let kr = task_get_special_port(mach_task_self_, TASK_BOOTSTRAP_PORT, &servicePort)
            guard kr == KERN_SUCCESS else {
                log("Uh-Oh! task_get_special_port failed!")
                
                return
            }
            
            if servicePort != MACH_PORT_NULL {
                break
            }
        }
        
        log("Got stashd port!")
        
        // Init PAC bypass in process
        let pipe = XPCPipe(port: servicePort)
        let reply = pipe.send(message: ["action": "getThread"])
        guard let dict = reply as? XPCDict else {
            kill(child, SIGKILL)
            log("Uh-Oh! Invalid stashd reply")
            return
        }
        
        guard dict["error"] as? UInt64 == 0 else {
            kill(child, SIGKILL)
            log("Uh-Oh! Failed to get stashd thread")
            return
        }
        
        guard let th = dict["thread"] as? UInt64 else {
            kill(child, SIGKILL)
            log("Uh-Oh! Invalid stashd thread")
            return
        }
        
        do {
            try KRW.initKCallInThread(thread: th)
        } catch let e {
            kill(child, SIGKILL)
            
            log("Uh-Oh! An exception occured during initKCallInThread: \(e)")
            return
        }
        
        _ = pipe.send(message: ["action": "pacBypass2Stashd"])
        
        log("Stashed primitives, we're ready to reboot!")
    } catch let e {
        log("Uh-Oh! An exception occcured: \(e)")
    }
}
