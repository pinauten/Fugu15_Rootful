//
//  KRW.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-13.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//

import Foundation
import KRWC
import KernelPatchfinder
import iDownload
import PatchfinderUtils

public enum KRWError: Error {
    case failed(providerError: Int32)
    case patchfinderFailed(symbol: String)
    case failedToTranslate(address: UInt64, table: String, entry: UInt64)
    case failedToGetKObject(ofPort: mach_port_t)
}

public enum KRWExploit {
    case tfp0
    case weightBufs
    case mcbc
}

public class KRW {
    private static var didInit: Bool {
        selectedExploit != nil
    }
    
    internal static var didInitPAC   = false
    internal static var didInitPPL   = false
    internal static var didInitPPLRW = false
    public   static let patchfinder  = KernelPatchfinder.running!
    
    internal static var phystokvTable: [phystokvEntry] = []
    public internal(set) static var physBase: UInt64 = 0
    public internal(set) static var virtBase: UInt64 = 0
    public internal(set) static var ttep: UInt64?
    
    internal static var signedState = Data()
    internal static var actContext: UInt64!
    internal static var mappedState: UnsafeMutablePointer<kRegisterState>!
    internal static var scratchMemory: UInt64!
    internal static var scratchMemoryMapped: UnsafeMutablePointer<UInt64>!
    internal static var kernelStack: UInt64!
    internal static var kcallThread: mach_port_t!
    
    public static var exploitToUse: KRWExploit?
    public private(set) static var selectedExploit: KRWExploit?
    
    public private(set) static var ourProc: Proc? = {
        try? Proc(pid: getpid())
    }()
    
    public private(set) static var kernelProc: Proc? = {
        try? Proc(pid: 0)
    }()
    
    public private(set) static var launchdProc: Proc? = {
        try? Proc(pid: 1)
    }()
    
    public static var logger: (_: String) -> Void = {_ in }
    
    public init() throws {
        try Self.doInit()
    }
    
    internal static func doInit() throws {
        guard !didInit else {
            return
        }
        
        logger("Status: Gaining KRW")
        
        if let exploit = exploitToUse {
            switch exploit {
            case .tfp0:
                var tfp0: mach_port_t = 0
                let kr = task_for_pid(mach_task_self_, 0, &tfp0)
                if kr == KERN_SUCCESS {
                    krw_init_tfp0(tfp0)
                    selectedExploit = .tfp0
                    return
                }
                
                throw KRWError.failed(providerError: kr)
                
            case .weightBufs:
                let res = krw_init_weightBufs()
                guard res == 0 else {
                    throw KRWError.failed(providerError: res)
                }
                
                selectedExploit = .weightBufs
                return
                
            case .mcbc:
                let res = krw_init_mcbc()
                guard res == 0 else {
                    throw KRWError.failed(providerError: res)
                }
                
                selectedExploit = .mcbc
                return
            }
        }
        
        logger("No exploit selected -> Choosing one automatically")
        
        // Select an exploit
        // Try tfp0 first
        var tfp0: mach_port_t = 0
        if task_for_pid(mach_task_self_, 0, &tfp0) == KERN_SUCCESS {
            logger("Automatically selected tfp0")
            krw_init_tfp0(tfp0)
            selectedExploit = .tfp0
            return
        }
        
        // On a stock device, check if mcbc is supported
        // If it is, use it
        let vers = ProcessInfo.processInfo.operatingSystemVersion
        if vers.majorVersion >= 15 && vers.minorVersion < 2 {
            logger("Automatically selected mcbc")
            if krw_init_mcbc() == 0 {
                selectedExploit = .mcbc
                return
            }
            
            logger("mcbc failed!")
        }
        
        logger("Automatically selected weightBufs")
        
        // Finally, try weightBufs
        let res = krw_init_weightBufs()
        guard res == 0 else {
            logger("weightBufs -> No more exploits to try!")
            throw KRWError.failed(providerError: res)
        }
        
        selectedExploit = .weightBufs
    }
    
    public static func kread(virt: UInt64, size: Int) throws -> Data {
        if didInitPPLRW {
            return try PPLRW.read(virt: virt, count: size)
        }
        
        try doInit()
        
        var data = Data(repeating: 0, count: size)
        let res = data.withUnsafeMutableBytes { ptr in
            switch selectedExploit.unsafelyUnwrapped {
            case .tfp0:
                return krw_kread_tfp0(UInt(virt), ptr.baseAddress!, size)
                
            case .weightBufs:
                return krw_kread_weightBufs(UInt(virt), ptr.baseAddress!, size)
                
            case .mcbc:
                return krw_kread_mcbc(UInt(virt), ptr.baseAddress!, size)
            }
        }
        
        guard res == 0 else {
            throw KRWError.failed(providerError: res)
        }
        
        return data
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
        if didInitPPLRW {
            try PPLRW.write(virt: virt, data: data)
            return
        }
        
        try doInit()
        
        let res = data.withUnsafeBytes { ptr in
            switch selectedExploit.unsafelyUnwrapped {
            case .tfp0:
                return krw_kwrite_tfp0(UInt(virt), ptr.baseAddress!, ptr.count)
                
            case .weightBufs:
                return krw_kwrite_weightBufs(UInt(virt), ptr.baseAddress!, ptr.count)
                
            case .mcbc:
                return krw_kwrite_mcbc(UInt(virt), ptr.baseAddress!, ptr.count)
            }
        }
        
        guard res == 0 else {
            throw KRWError.failed(providerError: res)
        }
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
        try doInit()
        
        switch selectedExploit.unsafelyUnwrapped {
        case .tfp0:
            return UInt64(krw_kbase_tfp0())
            
        case .weightBufs:
            return UInt64(krw_kbase_weightBufs())
            
        case .mcbc:
            return UInt64(krw_kbase_mcbc())
        }
    }
    
    public static func kslide() throws -> UInt64 {
        try Self.kbase() &- 0xFFFFFFF007004000
    }
    
    public static func slide(virt: UInt64) throws -> UInt64 {
        try virt + Self.kslide()
    }
    
    public static func cleanup() {
        guard let exploit = selectedExploit else {
            return
        }
        
        switch exploit {
        case .tfp0:
            krw_cleanup_tfp0()
            
        case .weightBufs:
            krw_cleanup_weightBufs()
            
        case .mcbc:
            krw_cleanup_mcbc()
        }
    }
}
