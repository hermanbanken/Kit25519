//
//  PEM.swift
//  Kit25519
//
//  Created by Herman Banken on 19/09/2022.
//

import Foundation
import ASN1Parser

enum PEM {
  static func Parse(pem: Data) throws -> ASN1 {
    let regex = NSRegularExpression("^-----BEGIN (?<begin>[^-]+)-----(?<base64>[\\s\\S]*)-----END (?<end>[^-]+)-----\\s?$")
    let str = String(decoding: pem, as: UTF8.self)
    let match = regex.firstMatch(str)
    guard
      case let begin?? = (match?.range(withName: "begin")).map({ Range($0, in: str) }),
      case let end?? = (match?.range(withName: "end")).map({ Range($0, in: str) }),
      case let base64?? = (match?.range(withName: "base64")).map({ Range($0, in: str) }),
        str[begin] == str[end]
    else {
      throw ASN1Error.invalidPemHeaderTrailer
    }

    guard let der = Data(base64Encoded: str[base64].trimmingCharacters(in: .whitespacesAndNewlines)) else {
      throw ASN1Error.invalidBase64
    }

    return try ASN1.Parse(der: der)
  }
  static func Encode(subject: DerRepresentable, kind: String) -> Data {
    return "-----BEGIN \(kind)-----\n".data(using: .utf8)! + subject.der.base64EncodedData() + "\n-----END \(kind)-----".data(using: .utf8)!
  }
}

fileprivate extension NSRegularExpression {
  convenience init(_ pattern: String) {
    do {
      try self.init(pattern: pattern)
    } catch {
      preconditionFailure("Illegal regular expression: \(pattern).")
    }
  }
  func firstMatch(_ string: String) -> NSTextCheckingResult? {
    let range = NSRange(location: 0, length: string.utf16.count)
    return firstMatch(in: string, options: [], range: range)
  }

  func matches(_ string: String) -> Bool {
    return firstMatch(string) != nil
  }
}
