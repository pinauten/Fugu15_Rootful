//
//  C.swift
//  FuFuGuGu
//
//  Created by Linus Henze on 23.01.23.
//

import Foundation
import CBridge
import SwiftUtils
import SwiftXPC

var console: Int32 = 0

func myStripPtr(_ ptr: OpaquePointer) -> UInt64 {
    UInt64(UInt(bitPattern: stripPtr(ptr)))
}

func log(_ str: String) {
    write(console, str + "\n", str.count + 1)
    //sleep(1)
}

func handleXPC(request: XPCDict, reply: XPCDict) -> UInt64 {
    print("Got an XPC request!")
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
                
                reply["STATUS"] = handleXPC(request: request, reply: reply)
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
