//
//  Fugu15.swift
//  jailbreakd
//
//  Created by Linus Henze on 23.01.23.
//

import Foundation
import SwiftXPC

func initFromStashd(rpl: XPCDict) throws {
    guard let kernelBase = rpl["kernelBase"] as? UInt64 else {
        while (true) {
            log("Invalid kernel base!")
        }
    }
    
    guard let pplMagicPage = rpl["pplMagicPage"] as? UInt64 else {
        while (true) {
            log("Invalid PPL magic page!")
        }
    }
    
    guard let cpuTTEP = rpl["cpuTTEP"] as? UInt64 else {
        while (true) {
            log("Invalid cpu ttep!")
        }
    }
    
    try KRW.doInit(kernelBase: kernelBase, magicPage: pplMagicPage, cpuTTEP: cpuTTEP)
    log("About to print kernel base!")
    try log("\(PPLRW.r64(virt: kernelBase))")
}
