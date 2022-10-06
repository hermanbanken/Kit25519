@testable import Kit25519
import CryptoKit
import XCTest

final class Kit25519Tests: XCTestCase {
  /// This test explains the picked cryptography scheme (based on CryptoKit) in an example.
  /// This documents the recommended use of these methods.
  @available(iOS 13.0, *)
  func testEncryption() throws {
    // Both parties made a private key
    let yourPrivateKey = Curve25519.KeyAgreement.PrivateKey()
    let othersPrivateKey = Curve25519.KeyAgreement.PrivateKey()

    // Both got the others public key and derive a common ground, the shared secret. Hooray maths!
    let sharedSecret1 = try yourPrivateKey.sharedSecretFromKeyAgreement(with: othersPrivateKey.publicKey)
    let sharedSecret2 = try othersPrivateKey.sharedSecretFromKeyAgreement(with: yourPrivateKey.publicKey)

    // Both derive a symmetric key using some parameters for key randomness (a fixed salt and shared info) because EC don't provide entirely uniformly distributed shared secrets
    // WARNING: never use different salts to derive multiple keys from the same shared secret. This weakens the security, see https://soatok.blog/2021/11/17/understanding-hkdf.
    let sharedKey1 = sharedSecret1.hkdfDerivedSymmetricKey(using: SHA256.self, salt: "salty".data(using: .utf8)!, sharedInfo: "example: filename".data(using: .utf8)!, outputByteCount: 32)
    let sharedKey2 = sharedSecret2.hkdfDerivedSymmetricKey(using: SHA256.self, salt: "salty".data(using: .utf8)!, sharedInfo: "example: filename".data(using: .utf8)!, outputByteCount: 32)

    // Both have the same encryption key now
    XCTAssertEqual(sharedKey1, sharedKey2)

    // Encrypt
    let msg = "foobar".data(using: .utf8)!
    let encrypted = try ChaChaPoly.seal(msg, using: sharedKey1, nonce: ChaChaPoly.Nonce()).combined // this is transferred over networks

    // Decrypt
    let decrypted = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: encrypted), using: sharedKey2)
    XCTAssertEqual(msg, decrypted)
  }
}
