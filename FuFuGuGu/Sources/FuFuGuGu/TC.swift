//
//  TC.swift
//  
//
//  Created by Linus Henze on 2023-03-05.
//

import Foundation

#if canImport(KRW)
import KRW
#endif

class TrustCache {
    static var appendTrustCache: TrustCache?
    static var currentTrustCache: TrustCache?
    static var firstTrustCache: TrustCache? = {
        guard let tc = KRW.patchfinder.pmap_image4_trust_caches else {
            return nil
        }
        
        let pmap_image4_trust_caches = try! KRW.slide(virt: tc)
        
        guard let first = try? KRW.rPtr(virt: pmap_image4_trust_caches) else {
            return nil
        }
        
        return TrustCache(kernelAddressHeader: first)
    }()
    
    let kernelAddressHeader: UInt64
    let kernelAddress: UInt64
    let physAddr: UInt64
    var allocCount: Int
    var usedCount: Int
    
    var next: TrustCache? {
        guard let addr = try? KRW.rPtr(virt: kernelAddressHeader) else {
            return nil
        }
        
        if addr == 0 {
            return nil
        }
        
        return TrustCache(kernelAddressHeader: addr)
    }
    
    static func initialize() {
        var cur = Self.firstTrustCache
        
        while cur != nil {
            if PPLRW.r32(phys: cur.unsafelyUnwrapped.physAddr + 0x4) == 0x13371337 {
                currentTrustCache = cur
                appendTrustCache  = cur
                return
            }
            
            cur = cur.unsafelyUnwrapped.next
        }
    }
    
    convenience init?() {
        guard let buf = try? KRW.alloc(size: 0x4000, leak: true) else {
            return nil
        }
        
        guard let bufPhys = try? KRW.kvtophys(kv: buf) else {
            return nil
        }
        
        PPLRW.getWindow().performWithMapping(to: bufPhys) { ptr in
            ptr.assumingMemoryBound(to: UInt64.self).pointee                    = 0x0        // Next
            ptr.advanced(by: 0x08).assumingMemoryBound(to: UInt64.self).pointee = buf + 0x10 // Our TC
            ptr.advanced(by: 0x10).assumingMemoryBound(to: UInt32.self).pointee = 0x1        // Version
            ptr.advanced(by: 0x14).assumingMemoryBound(to: UInt32.self).pointee = 0x13371337 // Magic
            ptr.advanced(by: 0x24).assumingMemoryBound(to: UInt32.self).pointee = 742        // Number of entries
            
            let entry = Data(repeating: 0xFF, count: 20) + Data(fromObject: 0x2 as UInt16)
            for i in 0..<742 {
                let cur = ptr.advanced(by: 0x28 + (22 * i))
                entry.withUnsafeBytes { ePtr in
                    cur.copyMemory(from: ePtr.baseAddress!, byteCount: 22)
                }
            }
        }
        
        // If we have a TrustCache that we can append to, do it
        if let append = Self.appendTrustCache {
            let next = append.next?.kernelAddressHeader ?? 0
            PPLRW.write(phys: bufPhys, data: Data(fromObject: next))
            try! PPLRW.write(virt: append.kernelAddressHeader, data: Data(fromObject: buf))
            
            self.init(kernelAddressHeader: buf)
        } else {
            guard var cur = Self.firstTrustCache else {
                return nil
            }
            
            while cur.next != nil {
                cur = cur.next.unsafelyUnwrapped
            }
            
            try! PPLRW.write(virt: cur.kernelAddressHeader, data: Data(fromObject: buf))
            
            self.init(kernelAddressHeader: buf)
            
            Self.appendTrustCache = self
        }
    }
    
    init?(kernelAddressHeader: UInt64) {
        guard let ka = try? KRW.rPtr(virt: kernelAddressHeader + 0x8) else {
            return nil
        }
        
        self.kernelAddressHeader = kernelAddressHeader
        self.kernelAddress = ka
        
        var allocCount: Int?
        var usedCount: Int?
        
        let off = Int(ka & 0x3FFF)
        let pg  = ka & ~0x3FFF
        guard let physAddr = try? KRW.kvtophys(kv: pg) else {
            return nil
        }
        
        self.physAddr = physAddr + UInt64(off)
        
        let window = PPLRW.getWindow()
        window.performWithMapping(to: physAddr) { ptr in
            // Check how many entries there are
            allocCount = Int(ptr.advanced(by: 0x14 + off).assumingMemoryBound(to: UInt32.self).pointee)
            
            // Check how many used entries there are
            for i in 0..<allocCount.unsafelyUnwrapped {
                let cur = ptr.advanced(by: 0x18 + (22 * i) + off)
                let data = Data(bytes: cur, count: 20)
                if data == Data(repeating: 0xFF, count: 20) {
                    usedCount = i
                    break
                }
            }
            
            // All entries used
            if usedCount == nil {
                usedCount = allocCount
            }
        }
        
        self.allocCount = allocCount!
        self.usedCount  = usedCount!
    }
    
    private func insert(hash: Data, at: UnsafeMutablePointer<UInt8>) {
        // First copy the old hash after the current one *backwards*
        let after = at.advanced(by: 22)
        for i in 0..<20 {
            after[19&-i] = at[19&-i]
        }
        
        // Copy the new hash, *forwards*
        for i in 0..<20 {
            at[i] = hash[i]
        }
    }
    
    func append(hash: Data) -> Bool {
        guard hash.count == 20 else {
            return false
        }
        
        guard usedCount < allocCount else {
            try? PPLRW.write(virt: kernelAddress &+ 0x4, data: Data(fromObject: 0xDEADBEEF as UInt32))
            let new = TrustCache()
            Self.currentTrustCache = new
            return new?.append(hash: hash) ?? false
        }
        
        func checkIf(a: Data, isSmallerThan b: Data) -> Int {
            for i in 0..<20 {
                if a[i] < b[i] {
                    return 1
                } else if a[i] > b[i] {
                    return 0
                }
            }
            
            return -1
        }
        
        let off = Int(physAddr & 0x3FFF)
        let pg  = physAddr & ~0x3FFF
        return PPLRW.getWindow().performWithMapping(to: pg) { ptr_tmp in
            let ptr = ptr_tmp.advanced(by: off)
            for i in 0..<usedCount {
                let cur = ptr.advanced(by: 0x18 &+ (22 &* i))
                let res = checkIf(a: hash, isSmallerThan: Data(bytes: cur, count: 20))
                if res == -1 {
                    // Already in there - Nothing to do!
                    return true
                } else if res == 1 {
                    // Insert here!
                    for j in 0..<(usedCount - i) {
                        let cur = ptr.advanced(by: 0x18 &+ (22 &* (usedCount &- j)))
                        let prev = ptr.advanced(by: 0x18 &+ (22 &* (usedCount &- j &- 1)))
                        insert(hash: Data(bytes: prev, count: 20), at: cur.assumingMemoryBound(to: UInt8.self))
                    }
                    
                    insert(hash: hash, at: cur.assumingMemoryBound(to: UInt8.self))
                    usedCount = usedCount &+ 1
                    return true
                }
            }
            
            // Insert afterwards
            let last = ptr.advanced(by: 0x18 &+ (22 &* usedCount))
            insert(hash: hash, at: last.assumingMemoryBound(to: UInt8.self))
            usedCount = usedCount &+ 1
            return true
        }
    }
}
