//
//  Alloc.swift
//  KRW
//
//  Created by Linus Henze on 2023-03-03.
//

import Foundation
import IOSurface

public extension KRW {
    internal static func my_getSurfacePort(size: UInt64) throws -> mach_port_t {
        let buf = UInt64(UInt(bitPattern: malloc(0x10)))
        
        let surf = IOSurfaceCreate([
            "IOSurfaceAddressRanges": Data(fromObject: buf) + Data(fromObject: 0x10 as UInt64) + Data(repeating: 0x0, count: Int(size) - 0x10),
            "IOSurfaceAllocSize": 0x10
        ] as CFDictionary)
        
        let port = IOSurfaceCreateMachPort(surf!)
        
        IOSurfaceDecrementUseCount(surf!)
        
        return port
    }
    
    static func alloc(size: UInt64, leak: Bool = false) throws -> UInt64 {
        if didInitPAC {
            if let kalloc_data_external = patchfinder.kalloc_data_external {
                return try kcall(func: slide(virt: kalloc_data_external), a1: size, a2: 1, a3: 0, a4: 0, a5: 0, a6: 0, a7: 0, a8: 0)
            }
        }
        
        let allocSize = max(size, 65536)
        
        while true {
            let port = try my_getSurfacePort(size: allocSize)
            let surface = try KRW.rPtr(virt: try KRW.ourProc!.task!.getKObject(ofPort: port) + 0x18 /* IOSurfaceSendRight -> IOSurface */)
            let va = try KRW.rPtr(virt: surface + 0x3e0 /* IOSurface -> IOSurfaceAddressRanges */)
            
            if (try? KRW.kvtophys(kv: va + allocSize)) != nil {
                mach_port_deallocate(mach_task_self_, port)
                continue
            }
            
            if leak {
                try KRW.w64(virt: surface + 0x3e0, value: 0)
                try KRW.w32(virt: surface + 0x3e8, value: 0)
            }
            
            return va + (allocSize - size)
        }
    }
}
