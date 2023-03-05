//
//  main.swift
//  stashd
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import CBridge
import SwiftXPC

setsid()

func usage() -> Never {
    print("Usage: jailbreakd <provider>")
    print("Provider can be one of:")
    print("\tlaunchedByFugu15: Provider is Fugu15, arguments are kernel base, slide, PPL magic page, cpu ttep physical address")
    exit(-1)
}

if CommandLine.arguments.count < 2 {
    usage()
}

let console_fd = open("/dev/console", O_RDWR, 0)
dup2(console_fd, STDOUT_FILENO)
dup2(console_fd, STDERR_FILENO)

var launchdTP: mach_port_t = 0
kr = task_for_pid(mach_task_self_, 1, &launchdTP)
guard kr == KERN_SUCCESS else {
    print("[stashd] task_for_pid failed!")
    exit(-1)
}

var servicePort: mach_port_t = 0
var kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &servicePort)
guard kr == KERN_SUCCESS else {
    print("[stashd] mach_port_allocate failed!")
    exit(-1)
}

kr = mach_port_insert_right(mach_task_self_, servicePort, servicePort, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
guard kr == KERN_SUCCESS else {
    print("[stashd] mach_port_insert_right failed!")
    exit(-1)
}

let provider = CommandLine.arguments[1]
switch provider {
case "launchedByFugu15":
    // Also register that port
    typealias brT = @convention(c) (_: mach_port_t, _: UnsafeMutablePointer<CChar>, _: mach_port_t) -> kern_return_t
    let br = unsafeBitCast(dlsym(dlopen(nil, 0), "bootstrap_register"), to: brT.self)
    kr = br(bootstrap_port, strdup("jb-global-stashd"), servicePort)
    guard kr == KERN_SUCCESS else {
        print("[stashd] bootstrap_register failed!")
        exit(-1)
    }
    
    mach_port_insert_right(mach_task_self_, servicePort, servicePort, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
    fallthrough
    
case "launchedByFuFuGuGu15":
    try initFromFugu15()
    
default:
    print("Invalid provider \(provider)!")
    usage()
}

print("KRW initialized, starting server!")

kr = task_set_special_port(launchdTP, TASK_BOOTSTRAP_PORT, servicePort)
guard kr == KERN_SUCCESS else {
    print("[stashd] task_set_special_port failed!")
    exit(-1)
}

DispatchQueue(label: "XPCServer").async {
    var shouldExit = false
    var pacThread: mach_port_t!
    
    while !shouldExit {
        guard let req = XPCPipe.receive(port: servicePort) as? XPCDict else {
            continue
        }
        
        guard let reply = req.createReply() else {
            print("[stashd] Cannot create reply!")
            continue
        }
        
        var error: UInt64 = UInt64.max
        
        defer { reply["error"] = error; XPCPipe.reply(dict: reply) }
        
        guard let action = req["action"] as? String else {
            print("[stashd] Cannot get XPC action!")
            continue
        }
        
        switch action {
        case "initPPLBypass":
            print("[stashd] Initing PPL bypass in launchd!")
            do {
                try KRW.initPPLBypass(inProcess: 1)
                reply["kernelBase"] = KRW.kernelBase!
                reply["pplMagicPage"] = PPLRW.magicPageUInt64!
                reply["cpuTTEP"] = PPLRW.cpuTTEP!
                
                print("Inited PPL bypass in launchd!")
                error = 0
            } catch let e {
                print("[stashd] initPPLBypass failed: \(e)")
            }
            
        case "initPACBypass":
            print("[stashd] Initing PAC bypass in launchd!")
            guard let thread = req["thread"] as? UInt64 else {
                print("[stashd] launchd sent bad thread!")
                break
            }
            
            do {
                try KRW.initKCallInThread(thread: thread)
                error = 0
            } catch let e {
                print("[stashd] initPPLBypass failed: \(e)")
            }
            
        case "getThread":
            print("[stashd] Creating thread and sending it to launchd/Fugu15!")
            var th: mach_port_t = 0
            let kr = thread_create(mach_task_self_, &th)
            guard kr == KERN_SUCCESS else {
                error = 2
                break
            }
            
            guard let kobj = KRW.kobject(ofPort: th) else {
                error = 3
                break
            }
            
            reply["thread"] = kobj
            pacThread = th
            
            error = 0
            
        case "pacBypass2Stashd":
            print("[stashd] Received PPL bypass from launchd/Fugu15!")
            do {
                try KRW.receiveKCall(thPort: pacThread)
                
                print("[stashd] receiveKCall succeded!")
            } catch let e {
                print("[stashd] receiveKCall failed: \(e)")
            }
            
        case "exit":
            print("[stashd] Exiting!")
            shouldExit = true
            error = 0
            
        default:
            print("[stashd] Invalid action \(action)")
            error = 1
        }
    }
    
    exit(0)
}

dispatchMain()
