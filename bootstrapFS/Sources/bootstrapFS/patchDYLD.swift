//
//  patchDYLD.swift
//  bootstrapFS
//
//  Created by Linus Henze on 2023-01-29.
//

import Foundation
import SwiftMachO
import PatchfinderUtils

enum PatchDYLDError: Error {
    case sectionNotFound(segment: String, section: String)
    case DYLD_AMFI_FAKE_notFound
    case DYLD_AMFI_FAKE_xrefNotFound
    case noCMP
    case badCMP
    case noCondBranch
    case noCmpBranch
    case posixSpawnFailed(prog: String)
    case childFailed(prog: String, args: [String])
    case cs_invalid_strNotFound
    case cs_invalid_str_xrefNotFound
    case cs_invalid_str_cmpNotFound
}

func getProcOutput(prog: String, args: [String]) throws -> String {
    let out = Pipe()
    
    var argv = [strdup(prog)]
    for arg in args {
        argv.append(strdup(arg))
    }
    
    argv.append(nil)
    
    defer { for arg in argv { free(arg) } }
    
    var fAct: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&fAct)
    posix_spawn_file_actions_adddup2(&fAct, out.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)
    posix_spawn_file_actions_adddup2(&fAct, out.fileHandleForWriting.fileDescriptor, STDERR_FILENO)
    
    var child: pid_t = 0
    var res = posix_spawnp(&child, argv[0], &fAct, nil, argv, environ)
    guard res == 0 else {
        throw PatchDYLDError.posixSpawnFailed(prog: prog)
    }
    
    try? out.fileHandleForWriting.close()
    
    let outData = try out.fileHandleForReading.readToEnd() ?? Data()
    
    waitpid(child, &res, 0)
    
    guard res == 0 else {
        throw PatchDYLDError.childFailed(prog: prog, args: args)
    }
    
    return String(data: outData, encoding: .utf8) ?? ""
}

func buildTrustCache(hashes: [Data]) -> Data {
    var hashes = hashes
    
    // First remove all duplicates
    var hashDupl: [Data] = []
    hashes.removeAll { dat in
        if hashDupl.contains(dat) {
            return true
        }
        
        hashDupl.append(dat)
        
        return false
    }
    
    // Then sort
    hashes.sort { a, b in
        assert(a.count == 20)
        assert(b.count == 20)
        
        for i in 0..<20 {
            if a[i] < b[i] {
                return true
            } else if a[i] > b[i] {
                return false
            }
        }
        
        return false
    }
    
    // Generate a random trust cache UUID
    var randUUID = UUID().uuid
    
    // Trust Cache Format
    // 0x0  -> Version
    // 0x4  -> UUID (16 bytes)
    // 0x14 -> Number of entries
    var tc = Data(fromObject: 1 as UInt32)        // Version
    tc.append(Data(bytes: &randUUID, count: 16))  // UUID
    tc.appendGeneric(value: UInt32(hashes.count)) // Count
    for i in 0..<hashes.count {
        tc.append(hashes[i])
    }
    
    return tc
}

func patchDYLD(real: String, patched: String, trustCache: String) throws {
    let machO = try MachO(fromFile: real, okToLoadFAT: false)
    guard let cstr = machO.pfSection(segment: "__TEXT", section: "__cstring") else {
        throw PatchDYLDError.sectionNotFound(segment: "__TEXT", section: "__cstring")
    }
    
    guard let text = machO.pfSegment(forName: "__TEXT") else {
        throw PatchDYLDError.sectionNotFound(segment: "__TEXT", section: "__text")
    }
    
    guard let dyld_amfi_fake = cstr.addrOf("DYLD_AMFI_FAKE") else {
        throw PatchDYLDError.DYLD_AMFI_FAKE_notFound
    }
    
    guard let xref = text.findNextXref(to: dyld_amfi_fake, optimization: .noBranches) else {
        throw PatchDYLDError.DYLD_AMFI_FAKE_xrefNotFound
    }
    
    var nopA: Int!
    var nopB: Int!
    
    if let cmp = AArch64Instr.Args.cmp(text.instruction(at: xref + 0x10) ?? 0) {
        guard cmp.regA == 0 && cmp.isImm && cmp.immOrRegB == 0 else {
            throw PatchDYLDError.badCMP
        }
        
        guard AArch64Instr.Emulate.conditionalBranch(text.instruction(at: xref + 0x18) ?? 0, pc: xref + 0x18) != nil else {
            throw PatchDYLDError.noCondBranch
        }
        
        guard AArch64Instr.Emulate.compareBranch(text.instruction(at: xref + 0x20) ?? 0, pc: xref + 0x20) != nil else {
            throw PatchDYLDError.noCmpBranch
        }
        
        // Okay, simply nop-ing xref + 0x14 and xref + 0x20 should be enough
        nopA = Int((xref + 0x14) - text.baseAddress)
        nopB = Int((xref + 0x20) - text.baseAddress)
    } else {
        guard AArch64Instr.Emulate.compareBranch(text.instruction(at: xref + 0x10) ?? 0, pc: xref + 0x10) != nil else {
            throw PatchDYLDError.noCondBranch
        }
        
        guard AArch64Instr.Emulate.compareBranch(text.instruction(at: xref + 0x18) ?? 0, pc: xref + 0x18) != nil else {
            throw PatchDYLDError.noCmpBranch
        }
        
        // Okay, simply nop-ing xref + 0x10 and xref + 0x18 should be enough
        nopA = Int((xref + 0x0C) - text.baseAddress)
        nopB = Int((xref + 0x18) - text.baseAddress)
    }
    
    // XXX: Assuming contiguous MachO
    var data = machO.data
    data.withUnsafeMutableBytes { ptr in
        let base = ptr.baseAddress!
        base.advanced(by: nopA).assumingMemoryBound(to: UInt32.self).pointee = 0xD503201F
        base.advanced(by: nopB).assumingMemoryBound(to: UInt32.self).pointee = 0xD503201F
    }
    
    try data.write(to: URL(fileURLWithPath: patched))
    
    // Now run MachOMerger to inject libdyldhook
    _ = try getProcOutput(prog: "/private/preboot/MachOMerger", args: [patched, "/private/preboot/libdyldhook.dylib", patched])
    
    // Re-Sign it
    _ = try getProcOutput(prog: ldid, args: ["-S", patched])
    
    // Create TrustCache
    let sigInfoLines = try getProcOutput(prog: ldid, args: ["-h", patched]).split(separator: "\n")
    var cdHashes: [Data] = []
    for line in sigInfoLines {
        if line.starts(with: "CDHash=") {
            let hex = line.replacingOccurrences(of: "CDHash=", with: "")
            cdHashes.append(hex.decodeHex()![..<20] + Data(fromObject: 2 as UInt16))
        }
    }
    
    try buildTrustCache(hashes: cdHashes).write(to: URL(fileURLWithPath: trustCache))
}
