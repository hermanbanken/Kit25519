//
//  Protocols.swift
//  Kit25519
//
//  Created by Herman Banken on 20/09/2022.
//

import Foundation

protocol DerRepresentable {
  var der: Data { get }
}

protocol Signer: DerRepresentable {
  /// Generates as signature
  func signature<D>(for data: D) throws -> Data where D: DataProtocol
  var `public`: SigningVerifier { get }
}

protocol SigningVerifier: DerRepresentable {
  /// Verifies a signature
  ///
  /// - Parameters:
  ///   - signature: The 64-bytes signature to verify.
  ///   - data: The digest that was signed.
  /// - Returns: True if the signature is valid. False otherwise.
  func isValidSignature<S, D>(_ signature: S, for data: D) -> Bool where S: DataProtocol, D: DataProtocol
}

protocol AgreementPrivateKey: DerRepresentable {
  func deriveSymmetricKey(salt: Data, sharedInfo: Data, othersPublicKey: AgreementPublicKey) throws -> SymmetricBlackbox

  var `public`: AgreementPublicKey { get }
}

protocol AgreementPublicKey: DerRepresentable {
  var data: Data { get }
}

protocol SymmetricBlackbox: ContiguousBytes {
  func encrypt(data: Data) throws -> Data
  func decrypt(data: Data) throws -> Data
}
