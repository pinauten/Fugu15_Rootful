//
//  KRW.swift
//  jailbreakd
//
//  Created by Linus Henze on 23.01.23.
//

import Foundation
import KernelPatchfinder
import CBridge

public enum KRWError: Error {
    case failed(providerError: Int32)
    case patchfinderFailed(symbol: String)
    case failedToTranslate(address: UInt64, table: String, entry: UInt64)
    case failedToGetKObject(ofPort: mach_port_t)
}

public class KRW {
    private  static var didInit     = false
    internal static var didInitPAC  = false
    
    public private(set) static var kernelBase: UInt64!
    
    public static let patchfinder = KernelPatchfinder.running!
    
    internal static var signedState = Data()
    internal static var actContext: UInt64!
    internal static var mappedState: UnsafeMutablePointer<kRegisterState>!
    internal static var scratchMemory: UInt64!
    internal static var scratchMemoryMapped: UnsafeMutablePointer<UInt64>!
    internal static var kernelStack: UInt64!
    internal static var kcallThread: mach_port_t!
    
    public private(set) static var ourProc: Proc? = {
        try? Proc(pid: getpid())
    }()
    
    public private(set) static var kernelProc: Proc? = {
        try? Proc(pid: 0)
    }()
    
    public private(set) static var launchdProc: Proc? = {
        try? Proc(pid: 1)
    }()
    
    public static func doInit(kernelBase: UInt64, magicPage: UInt64, cpuTTEP: UInt64) throws {
        guard !didInit else {
            return
        }
        
        Self.kernelBase = kernelBase
        
        PPLRW.initialize(magicPage: magicPage, cpuTTEP: cpuTTEP)
        
        didInit = true
    }
    
    public static func kread(virt: UInt64, size: Int) throws -> Data {
        precondition(didInit)
        
        return try PPLRW.read(virt: virt, count: size)
    }
    
    public static func kreadGeneric<T>(virt: UInt64, type: T.Type = T.self) throws -> T {
        try kread(virt: virt, size: MemoryLayout<T>.size).getGeneric(type: T.self)
    }
    
    public static func rPtr(virt: UInt64) throws -> UInt64 {
        let ptr: UInt64 = try kreadGeneric(virt: virt)
        if ((ptr >> 55) & 1) == 1 {
            return ptr | 0xFFFFFF8000000000
        }
        
        return ptr
    }
    
    public static func r64(virt: UInt64) throws -> UInt64 {
        try kreadGeneric(virt: virt)
    }
    
    public static func r32(virt: UInt64) throws -> UInt32 {
        try kreadGeneric(virt: virt)
    }
    
    public static func r16(virt: UInt64) throws -> UInt16 {
        try kreadGeneric(virt: virt)
    }
    
    public static func r8(virt: UInt64) throws -> UInt8 {
        try kreadGeneric(virt: virt)
    }
    
    public static func kwrite(virt: UInt64, data: Data) throws {
        precondition(didInit)
        
        return try PPLRW.write(virt: virt, data: data)
    }
    
    public static func kwriteGeneric<T>(virt: UInt64, object: T) throws {
        try kwrite(virt: virt, data: Data(fromObject: object))
    }
    
    public static func w64(virt: UInt64, value: UInt64) throws {
        try kwriteGeneric(virt: virt, object: value)
    }
    
    public static func w32(virt: UInt64, value: UInt32) throws {
        try kwriteGeneric(virt: virt, object: value)
    }
    
    public static func w16(virt: UInt64, value: UInt16) throws {
        try kwriteGeneric(virt: virt, object: value)
    }
    
    public static func w8(virt: UInt64, value: UInt8) throws {
        try kwriteGeneric(virt: virt, object: value)
    }
    
    public static func kbase() throws -> UInt64 {
        precondition(didInit)
        
        return kernelBase
    }
    
    public static func kslide() throws -> UInt64 {
        try Self.kbase() &- 0xFFFFFFF007004000
    }
    
    public static func slide(virt: UInt64) throws -> UInt64 {
        try virt + Self.kslide()
    }
}
