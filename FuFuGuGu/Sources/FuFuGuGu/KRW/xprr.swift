//
//  xprr.swift
//  Fugu15
//
//  Created by Linus Henze.
//  Copyright © 2023 Pinauten GmbH. All rights reserved.
//

import Foundation

func pte_to_perm(_ pte: UInt64) -> UInt64 {
    (((pte) >> 4) & 0xC) | (((pte) >> 52) & 2) | (((pte) >> 54) & 1)
}

func perm_to_pte(_ perm: UInt64) -> UInt64 {
    (((perm) & 0xC) << 4) | (((perm) & 2) << 52) | (((perm) & 1) << 54)
}

let PERM_KRW_URW: UInt64 = 0x7 // R/W for kernel and user

let PTE_NON_GLOBAL:      UInt64 = 1 << 11
let PTE_VALID:           UInt64 = 1 << 10 // Access flag
let PTE_OUTER_SHAREABLE: UInt64 = 2 << 8
let PTE_INNER_SHAREABLE: UInt64 = 3 << 8

let PTE_LEVEL3_ENTRY = PTE_VALID | 0x3
