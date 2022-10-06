//
//  ASNTests.swift
//  Kit25519Tests
//
//  Created by Herman Banken on 19/09/2022.
//

import Foundation
import XCTest
import CryptoKit
import ASN1Parser
@testable import Kit25519

class ASNTests: XCTestCase {

  func testDecodePrivateCurve25519() throws {
    /// generated using: $ openssl genpkey -algorithm ed25519
    let pem = """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIG7vV6svjL9EdzX3CrxtoIzJThZQ3h1mJR1Ku5nFcIxu
-----END PRIVATE KEY-----
""".data(using: .utf8)!

    // Manually extracted using https://lapo.it/asn1js/
    let raw = Data(hex: "6EEF57AB2F8CBF447735F70ABC6DA08CC94E1650DE1D66251D4ABB99C5708C6E")!
    let result = try PEM.Parse(pem: pem)
    XCTAssertEqual(result, ASN1.Ed25519PrivateKey(rawBytes: raw))

    XCTAssertEqual("98f04b1e25056b79d80a538a3aa023a6ca135353d982684e7132c7d02280e447", try Curve25519.Signing.PrivateKey(rawRepresentation: raw).publicKey.rawRepresentation.hex)
    XCTAssertEqual(String(data: result.toPEM(), encoding: .utf8)!, String(data: pem, encoding: .utf8)!)
  }

  func testDecodePublicCurve25519() throws {
    /// generated using: $ openssl genpkey -algorithm ed25519 | openssl pkey -pubout
    let pem = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjza1vaTZKws/LOf4YbVRn2RGrKJH7ryODg4WcRt+0+8=
-----END PUBLIC KEY-----
""".data(using: .utf8)!

    // Manually extracted using https://lapo.it/asn1js/
    let raw = Data(hex: "8F36B5BDA4D92B0B3F2CE7F861B5519F6446ACA247EEBC8E0E0E16711B7ED3EF")!
    let result = try PEM.Parse(pem: pem)
    XCTAssertEqual(result, ASN1.Ed25519PublicKey(rawBytes: raw))
    XCTAssertEqual(String(data: result.toPEM(), encoding: .utf8)!, String(data: pem, encoding: .utf8)!)
 }

  // Checked with https://lapo.it/asn1js/#MCowBQYDK2VwAyEAjza1vaTZKws_LOf4YbVRn2RGrKJH7ryODg4WcRt-0-8
  func testOidCoding() throws {
    let x = DEREncoder.encode(der: try ASN1ObjectIdentifier(oid: "1.3.101.110")) // 06 03 2B 65 6E curveX25519
    XCTAssertEqual(x.hex, "06032b656e")

    let e = DEREncoder.encode(der: try ASN1ObjectIdentifier(oid: "1.3.101.112")) // 06 03 2B 65 70 curveEd25519
    XCTAssertEqual(e.hex, "06032b6570")
  }
}

/// https://stackoverflow.com/a/46663290/552203
extension Data {
  init?(hex: String) {
    let len = hex.count / 2
     var data = Data(capacity: len)
     var i = hex.startIndex
     for _ in 0..<len {
       let j = hex.index(i, offsetBy: 2)
       let bytes = hex[i..<j]
       if var num = UInt8(bytes, radix: 16) {
         data.append(&num, count: 1)
       } else {
         return nil
       }
       i = j
     }
     self = data
  }

  var hex: String {
      return map { String(format: "%02x", $0) }
          .joined()
  }
}
