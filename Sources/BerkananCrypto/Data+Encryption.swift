//
// Copyright © 2019 IZE Ltd. and the project authors
// Licensed under MIT License
//
// See LICENSE.txt for license information.
//

import Foundation
import CryptoKit

extension Data {
  
  enum DecryptionError: Error {
    case authenticationError
  }
  
  public static var encryptionProtocolSalt =
    "company.ize.berkanancrypto.salt".data(using: .utf8)!
  
  public static func encrypt<A: KeyAgreementPublicKey, B: PrivateKeyProvider>(
    _ data: Data,
    to theirEncryptionKey: A,
    ourSigningKeyProvidedBy privateKeyProvider: B
  ) throws -> (
    ephemeralPublicKeyData: Data,
    ciphertext: Data,
    signature: Data
    ) {
      let ourSigningKey = try privateKeyProvider.signingPrivateKey()
      let ephemeralPrivateKey = try theirEncryptionKey.ephemeralPrivateKey()
      let ephemeralPublicKeyRawRepresentation =
        ephemeralPrivateKey.keyAgreementPublicKey.rawRepresentation
      let sharedSecret = try ephemeralPrivateKey
        .computeSharedSecretFromKeyAgreement(with: theirEncryptionKey)
      let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data.encryptionProtocolSalt,
        sharedInfo: ephemeralPublicKeyRawRepresentation +
          theirEncryptionKey.rawRepresentation +
          ourSigningKey.signingPublicKey.rawRepresentation,
        outputByteCount: 32
      )
      let ciphertext = try ChaChaPoly.seal(data, using: symmetricKey).combined
      let signature = try ourSigningKey.computeSignature(
        for: ciphertext + ephemeralPublicKeyRawRepresentation +
          theirEncryptionKey.rawRepresentation
      )
      return (ephemeralPublicKeyRawRepresentation, ciphertext, signature)
  }
  
  public static func decrypt<A: PrivateKeyProvider, B: SigningPublicKey>(
    _ sealedMessage: (
    ephemeralPublicKeyData: Data,
    ciphertext: Data,
    signature: Data
    ),
    usingOurEncryptionKeyProvidedBy privateKeyProvider: A,
    from theirSigningKey: B
  ) throws -> Data {
    let ourEncryptionKey = try privateKeyProvider.keyAgreementPrivateKey()
    let data = sealedMessage.ciphertext + sealedMessage.ephemeralPublicKeyData +
      ourEncryptionKey.keyAgreementPublicKey.rawRepresentation
    guard theirSigningKey.computeIsValidSignature(
      sealedMessage.signature,
      for: data
      ) else {
        throw DecryptionError.authenticationError
    }
    let ephemeralPublicKey = try type(of: ourEncryptionKey).createPublicKey(
      rawRepresentation: sealedMessage.ephemeralPublicKeyData
    )
    let sharedSecret = try ourEncryptionKey
      .computeSharedSecretFromKeyAgreement(with: ephemeralPublicKey)
    let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
      using: SHA256.self,
      salt: Data.encryptionProtocolSalt,
      sharedInfo: ephemeralPublicKey.rawRepresentation +
        ourEncryptionKey.keyAgreementPublicKey.rawRepresentation +
        theirSigningKey.rawRepresentation,
      outputByteCount: 32
    )
    let sealedBox = try ChaChaPoly.SealedBox(combined: sealedMessage.ciphertext)
    return try ChaChaPoly.open(sealedBox, using: symmetricKey)
  }
}
