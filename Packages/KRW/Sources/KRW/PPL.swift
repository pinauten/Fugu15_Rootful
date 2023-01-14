//
//  PPL.swift
//  KRW
//
//  Created by Linus Henze on 2023-01-14.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//  

import Foundation
import KRWC

public extension KRW {
    static func doPPLBypass() throws {
        try doPacBypass()
        
        guard !didInitPPL else {
            return
        }
        
        gKernelPmap = kernelProc!.task!.vmMap!.pmap!
        
        if !pplBypass() {
            throw KRWError.failed(providerError: 1338)
        }
        
        didInitPPL = true
    }
    
    static func pplwrite(virt: UInt64, data: Data) throws {
        try doPPLBypass()
        
        _ = data.withUnsafeBytes { ptr in
            kernwrite_PPL(virt, ptr.baseAddress!, ptr.count)
        }
    }
    
    static func pplwrite(phys: UInt64, data: Data) throws {
        try doPPLBypass()
        
        _ = data.withUnsafeBytes { ptr in
            physwrite_PPL(phys, ptr.baseAddress!, ptr.count)
        }
    }
}
