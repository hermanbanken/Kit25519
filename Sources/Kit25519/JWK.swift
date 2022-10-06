//
//  JWK.swift
//  Kit25519
//
//  Created by Herman Banken on 26/09/2022.
//

import Foundation
import CryptoKit

struct JWKKeySet: Decodable {
  let keys: [JWKKey]
}

/// ## Basic support for JSON Web Key (JWK) format
/// This only supports OKP keys and only Curve25519 because we don't plan on using other schemas.
/// Still, adhering to the JWK format allows us to graceflly start adding more schemas when required.
struct JWKKey {
  var rawData: [String: String]
  let kty: String
  let kid: String?

  enum CodingKeys: String, CodingKey {
    case kty
    case kid
  }

  func asSigningVerifier() -> SigningVerifier? {
    // JOSE spec explainer: https://github.com/Spomky-Labs/jose/blob/master/doc/object/jwk.md#octet-key-pair-okp
    if kty == "OKP" /* octet key pair */ && rawData["crv"] == "Ed25519" {
      if #available(iOS 13.0, *) {
        guard let data = Data(base64UrlEncoded: rawData["x"] ?? ""),
          let key = try? Curve25519.Signing.PublicKey(rawRepresentation: data) else { return nil }
        return key
      }
    }

    return nil
  }
}

extension JWKKey: Decodable {
  init(from decoder: Decoder) throws {
    let rawData = try decoder.singleValueContainer().decode([String: String].self)
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.kty = try container.decode(String.self, forKey: .kty)
    self.kid = try container.decodeIfPresent(String.self, forKey: .kid)
    self.rawData = rawData.filter({ $0.key != "kid" && $0.key != "kty" })
  }
}

extension JWKKey: Hashable, Equatable {
  func hash(into hasher: inout Hasher) {
    hasher.combine(kty)
    hasher.combine(kid)
    hasher.combine(rawData)
  }
}
