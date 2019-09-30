//
// Copyright © 2019 Apple Inc., IZE Ltd. and the project authors
// Licensed under MIT License
//
// See LICENSE.txt for license information.
//

import XCTest
import CryptoKit
@testable import BerkananCrypto

final class BerkananCryptoTests: XCTestCase {
  
  func testP256KeyAgreementPrivateKeyInitRawRepresentation() {
    do {
      let key = try P256.KeyAgreement.PrivateKey()
      let represenation = key.rawRepresentation
      let _ = try P256.KeyAgreement.PrivateKey(rawRepresentation: represenation)
    }
    catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testP256KeyAgreementPublicKeyInitRawRepresentation() {
    do {
      let privateKey = try P256.KeyAgreement.PrivateKey()
      let publicKey = privateKey.publicKey
      let represenation = publicKey.rawRepresentation
      let publicKey2 = try P256.KeyAgreement.PublicKey(
        rawRepresentation: represenation
      )
      XCTAssertEqual(publicKey.rawRepresentation, publicKey2.rawRepresentation)
    }
    catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testP256KeyAgreementPrivateKeyInitX963Representation() {
    do {
      let key = try P256.KeyAgreement.PrivateKey()
      let represenation = key.x963Representation
      let _ = try P256.KeyAgreement.PrivateKey(
        x963Representation: represenation
      )
    }
    catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  struct TestPrivateKeyProvider: PrivateKeyProvider {
    
    var privateKeyType: PrivateKeyType = .p256
    
    var signingKey: SigningPrivateKey?
    var keyAgreementKey: KeyAgreementPrivateKey?
    
    public init(
      signingPrivateKey: SigningPrivateKey? = nil,
      keyAgreementPrivateKey: KeyAgreementPrivateKey? = nil
    ) {
      self.signingKey = signingPrivateKey
      self.keyAgreementKey = keyAgreementPrivateKey
    }
    
    func signingPrivateKey() throws -> SigningPrivateKey {
      guard let signingKey = self.signingKey else {
        throw CocoaError(.fileNoSuchFile)
      }
      return signingKey
    }
    
    func keyAgreementPrivateKey() throws -> KeyAgreementPrivateKey {
      guard let keyAgreementKey = self.keyAgreementKey else {
        throw CocoaError(.fileNoSuchFile)
      }
      return keyAgreementKey
    }
    
  }
  
  func testEncryption() {
    do {
      let message = "I'm building a terrific new app!".data(using: .utf8)!
      let senderSigningKey = try P256.Signing.PrivateKey()
      let senderSigningPublicKey = senderSigningKey.publicKey
      let receiverEncryptionKey =
        try P256.KeyAgreement.PrivateKey()
      let receiverEncryptionPublicKey = receiverEncryptionKey.publicKey
      let sealedMessage = try Data.encrypt(
        message,
        to: receiverEncryptionPublicKey,
        ourSigningKeyProvidedBy:
        TestPrivateKeyProvider(signingPrivateKey: senderSigningKey)
      )
      let _ = try Data.decrypt(
        sealedMessage,
        usingOurEncryptionKeyProvidedBy:
        TestPrivateKeyProvider(keyAgreementPrivateKey: receiverEncryptionKey),
        from: senderSigningPublicKey
      )
    }
    catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  static var allTests = [
    ("testP256KeyAgreementPrivateKeyInitRawRepresentation", testP256KeyAgreementPrivateKeyInitRawRepresentation),
    ("testP256KeyAgreementPublicKeyInitRawRepresentation", testP256KeyAgreementPublicKeyInitRawRepresentation),
    ("testP256KeyAgreementPrivateKeyInitX963Representation", testP256KeyAgreementPrivateKeyInitX963Representation),
    ("testEncryption", testEncryption),
  ]
}
