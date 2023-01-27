//
//  FixupGOT.swift
//  FuFuGuGu
//
//  Created by Linus Henze on 23.01.23.
//

import Foundation
import MachO
import SwiftMachO
import CBridge

var someVariableThatINeedBecauseINeedToGetTheAddressOfSomethingInMyImage = 0

func doFixup(ptr: UnsafeMutablePointer<UInt64>, target: UInt64, diversity: UInt16, derived: Bool, key: ChainedFixups.ChainedStartsInSegment.ChainTarget.PACKey) {
    log("doFixup: \(target) \(diversity) \(derived) \(key) \(key.rawValue)")
    let signed = signPtrUnauthenticated(target, ptr, diversity, derived, key.rawValue)
    ptr.pointee = signed
}

func fPtrToUInt64(_ ptr: UnsafeMutableRawPointer) -> UInt64 {
    myStripPtr(OpaquePointer(ptr))
}

func doFixups(fixups: [(orig: String, replacement: String)]) throws {
    var info = Dl_info()
    let res = dladdr(&someVariableThatINeedBecauseINeedToGetTheAddressOfSomethingInMyImage, &info)
    guard res != 0 else {
        log("dladdr")
        return
    }
    
    let handle = dlopen(info.dli_fname, 0)
    let fixups = fixups.map { (orig: String, replacement: String) in
        (orig: orig, replacement: fPtrToUInt64(dlsym(handle, replacement)))
    }
    
    let slide = UInt64(_dyld_get_image_vmaddr_slide(0))
    let file = try MachO(fromFile: Bundle.main.executablePath ?? "/sbin/launchd")
    let chainedFixups = try file.getChainedFixups()
    try chainedFixups.forEachFixup({ location, vAddr, content in
        switch content {
        case .authBind(ordinal: _, diversity: let diversity, addrDiv: let addrDiv, key: let key, next: _):
            if let symbol = chainedFixups.symbol(forFixup: content) {
                for fixup in fixups {
                    if ("_" + fixup.orig) == symbol {
                        log("Rebinding \(fixup.orig)")
                        let addr = UInt(vAddr + slide)
                        let addrPtr = UnsafeMutableRawPointer(bitPattern: addr)!
                        var kr = vm_protect(mach_task_self_, addr, 0x8, 0, VM_PROT_READ | VM_PROT_WRITE)
                        if kr != KERN_SUCCESS {
                            kr = vm_protect(mach_task_self_, addr, 0x8, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)
                            guard kr == KERN_SUCCESS else {
                                log("Failed to rebind!")
                                break
                            }
                        }
                        
                        doFixup(ptr: addrPtr.assumingMemoryBound(to: UInt64.self), target: fixup.replacement, diversity: diversity, derived: addrDiv, key: key)
                        break
                    }
                }
            }
            
        default:
            break
        }
    })
}
