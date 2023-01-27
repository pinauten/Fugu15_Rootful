//
//  C.swift
//  FuFuGuGu
//
//  Created by Linus Henze on 23.01.23.
//

import Foundation
import CBridge
import SwiftUtils

var console: Int32 = 0

func myStripPtr(_ ptr: OpaquePointer) -> UInt64 {
    UInt64(UInt(bitPattern: stripPtr(ptr)))
}

func log(_ str: String) {
    write(console, str + "\n", str.count + 1)
}

@_cdecl("swift_init")
public func swift_init(_ consoleFD: Int32) {
    console = consoleFD
    do {
        log("Fixing launchd...")
        
        let fixups = [
            (orig: "sandbox_check_by_audit_token", replacement: "my_sandbox_check_by_audit_token"),
            (orig: "kill", replacement: "my_kill"),
            (orig: "posix_spawn", replacement: "my_posix_spawn"),
            (orig: "posix_spawnp", replacement: "my_posix_spawnp")
        ] as [(orig: String, replacement: String)]
        
        try doFixups(fixups: fixups)
        
        log("Fixed launchd!")
    } catch let e {
        log("Failed to fixup launchd: \(e)")
    }
}
