//
//  Fugu15.swift
//  jailbreakd
//
//  Created by Linus Henze on 23.01.23.
//

import Foundation

func initFromFugu15() throws {
    if CommandLine.arguments.count != 6 {
        print("Invalid command line arguments!")
        exit(-1)
    }
    
    guard let kernelBase = UInt64(CommandLine.arguments[2]) else {
        print("Invalid kernel base!")
        exit(-1)
    }
    
    guard let kernelSlide = UInt64(CommandLine.arguments[3]) else {
        print("Invalid kernel slide!")
        exit(-1)
    }
    
    guard let pplMagicPage = UInt64(CommandLine.arguments[4]) else {
        print("Invalid PPL magic page!")
        exit(-1)
    }
    
    guard let cpuTTEP = UInt64(CommandLine.arguments[5]) else {
        print("Invalid cpu ttep!")
        exit(-1)
    }
    
    PPLRW.initialize(magicPage: pplMagicPage, cpuTTEP: cpuTTEP)
    try print("\(PPLRW.r64(virt: kernelBase))")
}
