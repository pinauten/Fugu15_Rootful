//
//  main.swift
//  jailbreakd
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import CBridge
import MIGServer

setsid()

var needsBootstrapPort = false

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
dup2(console_fd, STDOUT_FILENO);
dup2(console_fd, STDERR_FILENO);

let provider = CommandLine.arguments[1]
switch provider {
case "launchedByFugu15":
    try initFromFugu15()
    
default:
    print("Invalid provider \(provider)!")
    usage()
}

let serviceName = "jb-global-jailbreakd"

var servicePort: mach_port_t = 0
let kr = bootstrap_check_in(bootstrap_port, serviceName, &servicePort)
guard kr == KERN_SUCCESS else {
    print("[jailbreakd] bootstrap_check_in failed: \(kr)")
    exit(-1)
}

DispatchQueue(label: "jailbreakd").async {
    let allocSize = 4096
    let inBuf  = malloc(allocSize)
    let outBuf = malloc(allocSize)
    
    let msgIn  = inBuf!.assumingMemoryBound(to: mach_msg_header_t.self)
    let msgOut = outBuf!.assumingMemoryBound(to: mach_msg_header_t.self)
    
    while true {
        msgIn.pointee.msgh_local_port = servicePort
        msgIn.pointee.msgh_size       = mach_msg_size_t(allocSize)
        var kr = mach_msg_receive(msgIn)
        guard kr == KERN_SUCCESS else {
            print("[jailbreakd] MIG Server: Failed to receive message: \(kr)")
            
            continue
        }
        
        init_server(msgIn, msgOut)
        
        kr = mach_msg_send(msgOut)
        guard kr == KERN_SUCCESS else {
            print("[jailbreakd] MIG Server: Failed to send reply: \(kr)")
            
            continue
        }
    }
}

DispatchQueue(label: "SuperviseLaunchd").async {
    var notifyPort: mach_port_t = 0
    mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &notifyPort)
    
    mach_port_insert_right(mach_task_self_, notifyPort, notifyPort, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
    
    let recvBuffer = malloc(2048)!
    let recvMsg    = recvBuffer.assumingMemoryBound(to: mach_msg_header_t.self)
    
    while true {
        var launchdTP: mach_port_t = 0
        if task_for_pid(mach_task_self_, 1, &launchdTP) == KERN_SUCCESS {
            mach_port_insert_right(mach_task_self_, servicePort, servicePort, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
            let kr = task_set_special_port(launchdTP, TASK_BOOTSTRAP_PORT, servicePort)
            if kr != KERN_SUCCESS {
                print("[jailbreakd] task_set_special_port failed!")
            }
            
            var previous: mach_port_t = 0
            if mach_port_request_notification(mach_task_self_, launchdTP, MACH_NOTIFY_DEAD_NAME, 1, notifyPort, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND_ONCE), &previous) == KERN_SUCCESS {
                /*if previous != 0 && previous != UInt32.max {
                    mach_port_deallocate(mach_task_self_, previous)
                }*/
                
                recvMsg.pointee.msgh_local_port = notifyPort
                recvMsg.pointee.msgh_size       = 2048
                
                let kr = mach_msg(recvMsg, MACH_RCV_MSG, 0, 2048, notifyPort, 0, 0)
                if kr != KERN_SUCCESS {
                    print("[jailbreakd] mach_msg failed?! \(kr)")
                } else {
                    mach_msg_destroy(recvMsg)
                    print("[jailbreakd] Launchd died!")
                    needsBootstrapPort = true
                }
            } else {
                print("[jailbreakd] mach_port_request_notification failed!")
            }
            
            mach_port_deallocate(mach_task_self_, launchdTP)
        } else {
            print("[jailbreakd] task_for_pid(1) failed!")
        }
    }
}

dispatchMain()
