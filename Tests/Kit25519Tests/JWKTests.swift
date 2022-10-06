//
//  JWKTests.swift
//  Kit25519Tests
//
//  Created by Herman Banken on 26/09/2022.
//

import Foundation
import XCTest
@testable import Kit25519

class JWKTests: XCTestCase {

  func testDecode() throws {
    let result = try JSONDecoder().decode(JWKKeySet.self, from: """
{"keys":[
  {"crv":"Ed25519","kid":"C9U8CBqgBLTJ1bW1yP4tMS-szT54GpKaqShw7ZyHS4Q","kty":"OKP","x":"TVxDZ7wZ_zR3Bn5Iq3wMyH-XKiTLhGG-E88wI9s0A0Q"}
]}
""".data(using: .utf8)!)
    XCTAssertFalse(result.keys.isEmpty)
    XCTAssertEqual(result.keys.first, JWKKey(rawData: [
      "crv": "Ed25519",
      "x": "TVxDZ7wZ_zR3Bn5Iq3wMyH-XKiTLhGG-E88wI9s0A0Q"
    ], kty: "OKP", kid: "C9U8CBqgBLTJ1bW1yP4tMS-szT54GpKaqShw7ZyHS4Q"))

    guard let signingVerifier = result.keys.first?.asSigningVerifier() else { XCTFail("Not decoded"); return }
    XCTAssertFalse(signingVerifier.isValidSignature(Data(), for: "foobar".data(using: .utf8)!))
  }

}
