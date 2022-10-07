//
//  File.swift
//  
//
//  Created by Herman Banken on 06/10/2022.
//

import Foundation
import CryptoKit

@available(iOS 13.0, *)
extension SymmetricKey: SymmetricBlackbox {

  /// - Parameters:
  ///   - data: The message to be encrypted
  /// - Returns: Combined output has the format: nonce + ciphertext + tag
  public func encrypt(data msg: Data) throws -> Data {
    let box = try ChaChaPoly.seal(msg, using: self, nonce: ChaChaPoly.Nonce())
    return box.combined
  }

  /// - Parameters:
  ///   - data: The combined input (nonce + ciphertext + tag) to be decrypted
  /// - Returns: Encrypted data
  public func decrypt(data: Data) throws -> Data {
    return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: data), using: self)
  }

}
