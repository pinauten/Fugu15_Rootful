//
//  Structs.swift
//  
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import KRWC

public class KernelObject {
    public let address: UInt64
    
    public init(address: UInt64) {
        self.address = address
    }
    
    public func rPtr(offset: UInt64) throws -> UInt64 {
        try KRW.rPtr(virt: self.address + offset)
    }
    
    public func r64(offset: UInt64) throws -> UInt64 {
        try KRW.r64(virt: self.address + offset)
    }
    
    public func r32(offset: UInt64) throws -> UInt32 {
        try KRW.r32(virt: self.address + offset)
    }
    
    public func r16(offset: UInt64) throws -> UInt16 {
        try KRW.r16(virt: self.address + offset)
    }
    
    public func r8(offset: UInt64) throws -> UInt8 {
        try KRW.r8(virt: self.address + offset)
    }
    
    public func w64(offset: UInt64, value: UInt64) throws {
        try KRW.w64(virt: self.address + offset, value: value)
    }
    
    public func w64PPL(offset: UInt64, value: UInt64) throws {
        try KRW.pplwrite(virt: self.address + offset, data: Data(fromObject: value))
    }
}

public class Proc: KernelObject {
    public convenience init?(pid: pid_t) throws {
        guard let allproc = KRW.patchfinder.allproc else {
            throw KRWError.patchfinderFailed(symbol: "allproc")
        }
        
        var curProc = try KRW.slide(virt: allproc)
        while curProc != 0 {
            if try KRW.r32(virt: curProc + 0x68 /* PROC_PID */) == pid {
                self.init(address: curProc)
                return
            }
            
            curProc = try KRW.rPtr(virt: curProc)
        }
        
        return nil
    }
    
    public var task: Task? {
        guard let addr = try? rPtr(offset: 0x10) else {
            return nil
        }
        
        return Task(address: addr)
    }
    
    public var p_flag: UInt32? {
        get {
            try? r32(offset: 0x0)
        }
        set {
            try? KRW.w32(virt: address + 0x0, value: newValue ?? 0)
        }
    }
    
    public var ro: Proc_RO? {
        guard ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 15 && ProcessInfo.processInfo.operatingSystemVersion.minorVersion >= 2 else {
            return nil
        }
        
        guard let ro = try? rPtr(offset: 0x20) else {
            return nil
        }
        
        return Proc_RO(address: ro)
    }
    
    public var ucred: UInt64? {
        get {
            if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 15 && ProcessInfo.processInfo.operatingSystemVersion.minorVersion >= 2 {
                return ro?.ucred
            }
            
            return nil // FIXME!
        }
        
        set {
            if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 15 && ProcessInfo.processInfo.operatingSystemVersion.minorVersion >= 2 {
                ro?.ucred = newValue
                return
            }
            
            // FIXME!
        }
    }
}

public class Proc_RO: KernelObject {
    public var ucred: UInt64? {
        get {
            try? rPtr(offset: 0x20)
        }
        
        set {
            guard let new = newValue else {
                return
            }
            
            try? w64PPL(offset: 0x20, value: new)
        }
    }
}

public class Task: KernelObject {
    public var itk_space: ITK_Space? {
        guard let ITK_SPACE_OFF = KRW.patchfinder.ITK_SPACE else {
            return nil
        }
        
        guard let itkSpace = try? rPtr(offset: ITK_SPACE_OFF) else {
            return nil
        }
        
        return ITK_Space(address: itkSpace)
    }
    
    public var vmMap: VMMap? {
        guard let addr = try? rPtr(offset: 0x28) else {
            return nil
        }
        
        return VMMap(address: addr)
    }
    
    public var firstThread: KThread? {
        guard let addr = try? rPtr(offset: 0x60) else {
            return nil
        }
        
        return KThread(address: addr)
    }
    
    public func getKObject(ofPort port: mach_port_t) throws -> UInt64 {
        guard let addr = try itk_space?.is_table?.getKPort(ofPort: port)?.kObject else {
            throw KRWError.failedToGetKObject(ofPort: port)
        }
        
        return addr
    }
}

public class KThread: KernelObject {
    public var actContext: UInt64? {
        guard let addr = try? rPtr(offset: KRW.patchfinder.ACT_CONTEXT!) else {
            return nil
        }
        
        return addr
    }
}

public class ITK_Space: KernelObject {
    public var is_table: IS_Table? {
        guard let addr = try? rPtr(offset: 0x20) else {
            return nil
        }
        
        return IS_Table(address: addr)
    }
}

public class IS_Table: KernelObject {
    public func getKPort(ofPort port: mach_port_t) throws -> KPort? {
        guard let addr = try? rPtr(offset: UInt64(port >> 8) * 0x18) else {
            return nil
        }
        
        return KPort(address: addr)
    }
}

public class KPort: KernelObject {
    public var kObject: UInt64? {
        var PORT_KOBJECT: UInt64 = 0x58
        if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 15 && ProcessInfo.processInfo.operatingSystemVersion.minorVersion >= 2 {
            PORT_KOBJECT = 0x48
        }
        
        return try? rPtr(offset: PORT_KOBJECT)
    }
}

public class VMMap: KernelObject {
    public var pmap: PMap? {
        guard let VM_MAP_PMAP = KRW.patchfinder.VM_MAP_PMAP else {
            return nil
        }
        
        guard let pmap = try? rPtr(offset: VM_MAP_PMAP) else {
            return nil
        }
        
        return PMap(address: pmap)
    }
}

public class PMap: KernelObject {
    public var type: UInt8? {
        get {
            let adjust: UInt64 = (KRW.patchfinder.kernel_el == 2) ? 8 : 0
            
            return try? r8(offset: 0xC8 + adjust)
        }
        
        set {
            guard newValue != nil else {
                return
            }
            
            let adjust: UInt64 = (KRW.patchfinder.kernel_el == 2) ? 8 : 0
            
            try? KRW.pplwrite(virt: self.address + 0xC8 + adjust, data: Data(fromObject: newValue.unsafelyUnwrapped))
        }
    }
}
