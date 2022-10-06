//
//  Curve25519.swift
//  Kit25519
//
//  Created by Herman Banken on 20/09/2022.
//

import Foundation
import CryptoKit

extension Curve25519.Signing.PrivateKey: Signer {
  var `public`: SigningVerifier { self.publicKey }

  var der: Data {
    get { return ASN1.Ed25519PrivateKey(rawBytes: rawRepresentation).der }
  }
}

extension CryptoKit.Curve25519.Signing.PublicKey: SigningVerifier {}

extension Curve25519.Signing.PublicKey: DerRepresentable {
  var der: Data {
    get { return ASN1.Ed25519PublicKey(rawBytes: rawRepresentation).der }
  }
}

extension Curve25519.KeyAgreement.PublicKey: DerRepresentable {
  var der: Data {
    get { return ASN1.X25519PublicKey(rawBytes: rawRepresentation).der }
  }
}

extension Curve25519.KeyAgreement.PublicKey: AgreementPublicKey {
  var data: Data {
    return self.rawRepresentation
  }
}

extension Curve25519.KeyAgreement.PrivateKey: AgreementPrivateKey {
  var `public`: AgreementPublicKey {
    return self.publicKey
  }

  var der: Data {
    get { return ASN1.X25519PrivateKey(rawBytes: rawRepresentation).der }
  }

  func deriveSymmetricKey(salt: Data, sharedInfo: Data, othersPublicKey: AgreementPublicKey) throws -> SymmetricBlackbox {
    guard let otherKey = othersPublicKey as? Curve25519.KeyAgreement.PublicKey else {
      throw Kit25519Error.invalidInputKey
    }
    return try self.sharedSecretFromKeyAgreement(with: otherKey).hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: sharedInfo, outputByteCount: 32)
  }
}

extension ASN1 {
  var asAgreementPrivateKey: AgreementPrivateKey {
    get throws {
      switch self {
      case .X25519PrivateKey(rawBytes: let data):
        if #available(iOS 13.0, *) {
          guard let pk = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) else { break }
          return pk
        }
      default:
        break
      }
      throw NSError.init(domain: "crypto", code: 500, userInfo: ["der": der.base64EncodedString(), "method": "asAgreementPrivateKey"])
    }
  }

  var asAgreementPublicKey: AgreementPublicKey {
    get throws {
      switch self {
      case .X25519PublicKey(rawBytes: let data):
        if #available(iOS 13.0, *) {
          guard let pk = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: data) else { break }
          return pk
        }
      default:
        break
      }
      throw NSError.init(domain: "crypto", code: 500, userInfo: ["der": der.base64EncodedString(), "method": "asAgreementPublicKey"])
    }
  }

  var asSigner: Signer {
    get throws {
      switch self {
      case .Ed25519PrivateKey(rawBytes: let data):
        if #available(iOS 13.0, *) {
          guard let pk = try? Curve25519.Signing.PrivateKey(rawRepresentation: data) else { break }
          return pk
        }
      default:
        break
      }
      throw NSError.init(domain: "crypto", code: 500, userInfo: ["der": der.base64EncodedString(), "method": "asSigner"])
    }
  }

  var asSigningVerifier: SigningVerifier {
    get throws {
      switch self {
      case .Ed25519PublicKey(rawBytes: let data):
        if #available(iOS 13.0, *) {
          guard let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: data) else { break }
          return pk
        }
      default:
        break
      }
      throw NSError.init(domain: "crypto", code: 500, userInfo: ["der": der.base64EncodedString(), "method": "asSigningVerifier "])
    }
  }
}

enum Kit25519Error: Error {
  case invalidInputKey
  case invalidPublicKey(error: Error)
}
