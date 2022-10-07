//
//  ANS.swift
//  Kit25519
//
//  Created by Herman Banken on 19/09/2022.
//

import Foundation
import ASN1Parser

// Reference: https://datatracker.ietf.org/doc/rfc8410/
private let curveEd25519Header = try! ASN1Sequence(ASN1ObjectIdentifier(oid: "1.3.101.112"))
private let curveX25519Header = try! ASN1Sequence(ASN1ObjectIdentifier(oid: "1.3.101.110"))

/// This exists as a convenience wrapper to handle DER encoded forms of (Curve25519) keys, and to encode those keys back to DER.
/// Notably there are 2 formats of Curve25519, being X25519 and Ed25519 which have a different representation/and other optimized usage.
public enum ASN1: Equatable, DerRepresentable {
  case X25519PublicKey(rawBytes: Data)
  case X25519PrivateKey(rawBytes: Data)
  case Ed25519PublicKey(rawBytes: Data)
  case Ed25519PrivateKey(rawBytes: Data)

  /// Parameter data is expected to be ASN.1 DER binary format.
  /// This format is typically Base64 encoded within header and trailer of a PEM file
  public static func Parse(der: Data) throws -> ASN1 {
    let asnValue: ASN1Value = try DERParser.parse(der: der)

    // https://www.rfc-editor.org/rfc/rfc7468: Textual Encodings of PKIX, PKCS, and CMS Structures:
    // https://www.rfc-editor.org/rfc/rfc8410#section-9: curveEd25519 public key ASN.1 module
    if
      let seqRoot = try? asnValue.asSequence,
      seqRoot.count == 2, // [algo oid, ...attrs], publicKey
      seqRoot.values[0].isEqualTo(curveEd25519Header) || seqRoot.values[0].isEqualTo(curveX25519Header),
      let bytes = (try? seqRoot.values[1].asBitString)?.bytes {
      if seqRoot.values[0].isEqualTo(curveEd25519Header) {
        return Ed25519PublicKey(rawBytes: Data(bytes))
      } else {
        return X25519PublicKey(rawBytes: Data(bytes))
      }
    }

    // https://www.rfc-editor.org/rfc/rfc5958 ASN.1 assymetric key format
    if
      let seqRoot = try? asnValue.asSequence,
      seqRoot.count == 3, // version, [algo oid, ...attrs], privateKey
      seqRoot.values[1].isEqualTo(curveEd25519Header) || seqRoot.values[1].isEqualTo(curveX25519Header),
      let privateKeyOctetDer = try? seqRoot.values[2].asOctetString.bytes,
      let privateKey = try? DERParser.parse(der: Data(privateKeyOctetDer)),
      let bytes = try? privateKey.asOctetString.bytes {
      if seqRoot.values[1].isEqualTo(curveEd25519Header) {
        return Ed25519PrivateKey(rawBytes: Data(bytes))
      } else {
        return X25519PrivateKey(rawBytes: Data(bytes))
      }
    }

    throw ASN1Error.unsupportedASNSequence
  }

  public var der: Data {
    switch self {
    // Ed25519
    case .Ed25519PrivateKey(rawBytes: let data):
      return ASN1Sequence(ASN1Integer(0), curveEd25519Header, ASN1OctetString(ASN1OctetString(data.map({$0})).data.map({$0}))).data
    case .Ed25519PublicKey(rawBytes: let data):
      return ASN1Sequence(curveEd25519Header, ASN1BitString(value: data.map({$0}), paddingLength: 0)).data

    // X25519
    case .X25519PrivateKey(rawBytes: let data):
      return ASN1Sequence(ASN1Integer(0), curveX25519Header, ASN1OctetString(ASN1OctetString(data.map({$0})).data.map({$0}))).data
    case .X25519PublicKey(rawBytes: let data):
      return ASN1Sequence(curveX25519Header, ASN1BitString(value: data.map({$0}), paddingLength: 0)).data
    }
  }

  public func toPEM() -> Data {
    switch self {
    case .Ed25519PrivateKey, .X25519PrivateKey:
      return PEM.Encode(subject: self, kind: "PRIVATE KEY")
    case .Ed25519PublicKey, .X25519PublicKey:
      return PEM.Encode(subject: self, kind: "PUBLIC KEY")
    }
  }
}

public extension ASN1Value {
  var data: Data {
    get {
      return DEREncoder.encode(der: self)
    }
  }
}

public enum ASN1Error: Error {
  case invalidPemHeaderTrailer
  case invalidBase64
  case unsupportedASNSequence
}
