//
//  C.swift
//  FuFuGuGu
//
//  Created by Linus Henze on 23.01.23.
//

import Foundation

@_cdecl("isTokenBlacklisted")
public func isTokenBlacklisted(_ token: audit_token_t) -> Int {
    return 0
}
