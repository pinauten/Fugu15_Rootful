//
//  prepare.swift
//  bootstrapFS
//
//  Created by Linus Henze on 24.01.23.
//

import Foundation

enum BootstrapError: Error {
    case statFailed(error: Int32, str: String)
}

@objc
class CopyDelegate: NSObject, FileManagerDelegate {
    let baseSrc: String
    let baseDst: String
    let baseSrcIndexLast: String.Index
    
    init(baseSrc: String, baseDst: String) {
        self.baseSrc = baseSrc
        self.baseDst = baseDst
        self.baseSrcIndexLast = baseSrc.index(after: baseSrc.indices.last!)
    }
    
    func fileManager(_ fileManager: FileManager, shouldCopyItemAtPath srcPath: String, toPath dstPath: String) -> Bool {
        let path = String(srcPath[baseSrcIndexLast...])
        
        print(path)
        
        return true
    }
}

func copyRootfs(real: String, new: String) throws {
    let fm       = FileManager()
    let delegate = CopyDelegate(baseSrc: real, baseDst: new)
    fm.delegate  = delegate
    
    for item in try FileManager.default.contentsOfDirectory(atPath: real) {
        let src = real + "/\(item)"
        let dst = new  + "/\(item)"
        try fm.copyItem(atPath: src, toPath: dst)
    }
}
