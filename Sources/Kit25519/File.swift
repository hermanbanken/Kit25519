//
//  Data.swift
//  Kit25519
//
//  Created by Herman Banken on 20/09/2022.
//

import Foundation

extension Data {
  /// base64url encoding is different from base64 due to some characters requiring url encoding
  init?(base64UrlEncoded: String) {
    let replaced = base64UrlEncoded
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let padding = replaced.count % 4
    if padding > 0 {
      self.init(base64Encoded: replaced + String(repeating: "=", count: 4 - padding))
    } else {
      self.init(base64Encoded: replaced)
    }
  }

  /// base64url encoding is different from base64 due to some characters requiring url encoding
  func base64urlEncodedString() -> String {
    return self.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
