//
//  Kernel.swift
//  KRW
//
//  Created by Linus Henze on 2023-03-03.
//

import Foundation

public extension KRW {
    static func pmap_enter_options_addr(_ pmap: UInt64, _ pa: UInt64, _ va: UInt64) -> kern_return_t {
        while true {
            let kr = try? kcall(func: slide(virt: patchfinder.pmap_enter_options_addr!), a1: pmap, a2: va, a3: pa, a4: UInt64(VM_PROT_READ | VM_PROT_WRITE), a5: 0, a6: 0, a7: 1, a8: 1)
            guard let kr = kr else {
                return KERN_FAILURE
            }
            
            if kr != KERN_RESOURCE_SHORTAGE {
                return kern_return_t(kr)
            }
        }
    }
    
    static func pmap_remove(_ pmap: UInt64, _ start: UInt64, _ end: UInt64) {
        _ = try? kcall(func: slide(virt: patchfinder.pmap_remove_options!), a1: pmap, a2: start, a3: end, a4: 0x100, a5: 0, a6: 0, a7: 0, a8: 0)
    }
    
    static func kobject(ofPort port: mach_port_t) -> UInt64? {
        try? ourProc?.task?.getKObject(ofPort: port)
    }
}
