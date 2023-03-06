//
//  C.swift
//  FuFuGuGu
//
//  Created by Linus Henze on 23.01.23.
//

import Foundation
import CBridge
import SwiftUtils

@testable
import SwiftXPC

var console: Int32 = 0

func myStripPtr(_ ptr: OpaquePointer) -> UInt64 {
    UInt64(UInt(bitPattern: stripPtr(ptr)))
}

func log(_ str: String) {
    write(console, str + "\n", str.count + 1)
    //sleep(1)
}

/*
                            0x36001025
 #define CS_HARD            0x00000100  /* don't load invalid pages */
 #define CS_KILL            0x00000200  /* kill process if it becomes invalid */
 #define CS_RESTRICT        0x00000800  /* tell dyld to treat restricted */
 #define CS_ENFORCEMENT     0x00001000  /* require enforcement */
 #define CS_REQUIRE_LV      0x00002000  /* require library validation */
 #define CS_PLATFORM_BINARY 0x04000000  /* this is a platform binary */
 */

func handleXPC(request: XPCDict, reply: XPCDict) -> UInt64 {
    if let action = request["action"] as? String {
        console = open("/dev/console",O_RDWR)
        log("Got action \(action)")
        switch action {
        case "csdebug":
            if let pid = request["pid"] as? UInt64 {
                let proc = try? Proc(pid: pid_t(pid))
                if let proc_ro = proc?.ro {
                    if let flags = proc_ro.cs_flags {
                        proc_ro.cs_flags = (flags & ~0x702b10) | 0x10000024
                        guard let pmap = proc?.task?.vmMap?.pmap else {
                            return 4
                        }
                        
                        pmap.debugged = 1
                        
                        return 0
                    } else {
                        return 3
                    }
                } else {
                    return 2
                }
            } else {
                return 1
            }
            
        case "trustcdhash":
            log("Doing trustcdhash")
            if let type = request["hashtype"] as? UInt64 {
                log("hashtype: \(type)")
                if type == 2 {
                    if let data = request["hashdata"] as? Data {
                        log("hashdata: \(data)")
                        guard data.count >= 20 else {
                            return 3
                        }
                        
                        log("Good length")
                        
                        if TrustCache.currentTrustCache == nil {
                            TrustCache.initialize()
                            if TrustCache.currentTrustCache == nil {
                                TrustCache.currentTrustCache = TrustCache()
                            }
                        }
                        
                        log("I haz initited")
                        
                        guard let tc = TrustCache.currentTrustCache else {
                            return 4
                        }
                        
                        log("I haz current")
                        
                        guard tc.append(hash: data[0..<20]) else {
                            return 5
                        }
                        
                        log("I haz appended")
                        
                        return 0
                    }
                    
                    return 2
                }
                
                return 1
            }
            
        default:
            break
        }
    }
    
    return 0
}

@_cdecl("swift_init")
public func swift_init(_ consoleFD: Int32, _ servicePort: mach_port_t, _ XPCServicePort: UnsafeMutablePointer<mach_port_t>) {
    console = consoleFD
    
    guard KRW.patchfinder != nil else {
        log("KernelPatchfinder.running == nil ?!")
        return
    }
    
    do {
        if servicePort != 0 {
            // Time to get KRW
            let pipe = XPCPipe(port: servicePort)
            guard let rpl = pipe.send(message: ["action": "initPPLBypass"]) as? XPCDict else {
                log("pipe.send[initPPLBypass] failed!")
                return
            }
            
            try initFromStashd(rpl: rpl)
            
            // Create kcall thread
            var kcallTh: mach_port_t = 0
            var kr = thread_create(mach_task_self_, &kcallTh)
            guard kr == KERN_SUCCESS else {
                log("thread_create failed!")
                return
            }
            
            guard let kobj = KRW.kobject(ofPort: kcallTh) else {
                log("KRW.kobject failed!")
                return
            }
            
            log("About to ask stashd to init PAC bypass")
            
            guard let rpl = pipe.send(message: ["action": "initPACBypass", "thread": kobj]) as? XPCDict else {
                log("pipe.send[initPACBypass] failed!")
                return
            }
            
            log("About to KRW.receiveKCall")
            
            try KRW.receiveKCall(thPort: kcallTh)
            
            log("Got PPL and PAC bypass!")
            
            _ = pipe.send(message: ["action": "exit"])
        }
        
        // Start KRW Server
        var kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, XPCServicePort)
        guard kr == KERN_SUCCESS else {
            log("mach_port_allocate failed!")
            return
        }
        
        let xpc = XPCServicePort.pointee
        
        kr = mach_port_insert_right(mach_task_self_, xpc, xpc, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
        guard kr == KERN_SUCCESS else {
            log("mach_port_insert_right failed!")
            return
        }
        
        DispatchQueue(label: "FuFuGuGuXPC").async {
            while true {
                guard let request = XPCPipe.receive(port: xpc) as? XPCDict else {
                    continue
                }
                
                guard let reply = request.createReply() else {
                    continue
                }
                
                defer { XPCPipe.reply(dict: reply) }
                
                reply["status"] = handleXPC(request: request, reply: reply)
            }
        }
        
        log("Fixing launchd...")
        
        let fixups = [
            (orig: "sandbox_check_by_audit_token", replacement: "my_sandbox_check_by_audit_token"),
            (orig: "kill", replacement: "my_kill"),
            (orig: "xpc_dictionary_get_value", replacement: "my_xpc_dictionary_get_value"),
            (orig: "posix_spawn", replacement: "my_posix_spawn"),
            (orig: "posix_spawnp", replacement: "my_posix_spawnp"),
            (orig: "xpc_receive_mach_msg", replacement: "my_xpc_receive_mach_msg")
        ] as [(orig: String, replacement: String)]
        
        try doFixups(fixups: fixups)
        
        log("Fixed launchd!")
    } catch let e {
        log("[FuFuGuGu] Failed to init: \(e)")
    }
}
