//
// Copyright © 2019 IZE Ltd. and the project authors
// Licensed under MIT License
//
// See LICENSE.txt for license information.
//

import Foundation
import CryptoKit

public enum PrivateKeyType: String, CaseIterable, CustomStringConvertible {
  
  case p256 = "P-256"
  case p384 = "P-384"
  case p521 = "P-521"
  
  public var description: String {
    return self.rawValue
  }
}

public protocol SigningPrivateKey {
  
  var signingPublicKey: SigningPublicKey { get }
  
  func computeSignature<D>(for data: D) throws -> Data where D : DataProtocol
}

public struct AnySigningPrivateKey: SigningPrivateKey {
  
  public var signingPublicKey: SigningPublicKey {
    return base.signingPublicKey
  }
  
  public func computeSignature<D>(
    for data: D
  ) throws -> Data where D : DataProtocol {
    return try base.computeSignature(for: data)
  }
  
  private var base: SigningPrivateKey
  
  public init(_ base: SigningPrivateKey) {
    self.base = base
  }
}

public protocol SigningPublicKey {
  
  var rawRepresentation: Data { get }
  
  var compactRepresentation: Data? { get }
  
  func computeIsValidSignature<S, D>(
    _ signature: S,
    for data: D
  ) -> Bool where S : DataProtocol, D : DataProtocol
}

public struct AnySigningPublicKey: SigningPublicKey {
  
  public var rawRepresentation: Data {
    return base.rawRepresentation
  }
  
  public var compactRepresentation: Data? {
    return base.compactRepresentation
  }
  
  public func computeIsValidSignature<S, D>(
    _ signature: S,
    for data: D
  ) -> Bool where S : DataProtocol, D : DataProtocol {
    return base.computeIsValidSignature(signature, for: data)
  }
  
  private var base: SigningPublicKey
  
  public init(_ base: SigningPublicKey) {
    self.base = base
  }
}

public protocol KeyAgreementPrivateKey {
  
  var keyAgreementPublicKey: KeyAgreementPublicKey { get }
  
  func computeSharedSecretFromKeyAgreement(
    with publicKeyShare: KeyAgreementPublicKey
  ) throws -> SharedSecret
  
  static func createPublicKey<D>(
    rawRepresentation: D
  ) throws -> KeyAgreementPublicKey where D : ContiguousBytes
}

public protocol KeyAgreementPublicKey {
  
  func ephemeralPrivateKey() throws -> KeyAgreementPrivateKey
  
  var rawRepresentation: Data { get }
  
  var compactRepresentation: Data? { get }
}

public struct AnyKeyAgreementPublicKey: KeyAgreementPublicKey {
  
  public func ephemeralPrivateKey() throws -> KeyAgreementPrivateKey {
    return try base.ephemeralPrivateKey()
  }
  
  public var rawRepresentation: Data {
    return base.rawRepresentation
  }
  
  public var compactRepresentation: Data? {
    return base.compactRepresentation
  }
  
  private var base: KeyAgreementPublicKey
  
  public init(_ base: KeyAgreementPublicKey) {
    self.base = base
  }
}

extension P256.Signing.PrivateKey: SigningPrivateKey {
  
  public var signingPublicKey: SigningPublicKey {
    return publicKey
  }
  
  public func computeSignature<D>(
    for data: D
  ) throws -> Data where D : DataProtocol {
    return try signature(for: data).rawRepresentation
  }
}

extension P256.Signing.PublicKey: SigningPublicKey {
  
  public func computeIsValidSignature<S, D>(
    _ signature: S,
    for data: D
  ) -> Bool where S : DataProtocol, D : DataProtocol {
    do {
      let signature = try P256.Signing.ECDSASignature(
        rawRepresentation: signature
      )
      return isValidSignature(signature, for: data)
    }
    catch {
      return false
    }
  }
}

extension P256.KeyAgreement.PrivateKey: KeyAgreementPrivateKey {
  
  public var keyAgreementPublicKey: KeyAgreementPublicKey {
    return publicKey
  }
  
  public func computeSharedSecretFromKeyAgreement(
    with publicKeyShare: KeyAgreementPublicKey
  ) throws -> SharedSecret {
    let publicKey = try P256.KeyAgreement.PublicKey(
      rawRepresentation: publicKeyShare.rawRepresentation
    )
    return try sharedSecretFromKeyAgreement(with: publicKey)
  }
  
  public static func createPublicKey<D>(
    rawRepresentation: D
  ) throws -> KeyAgreementPublicKey where D : ContiguousBytes {
    return try P256.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation)
  }
}

extension P256.KeyAgreement.PublicKey: KeyAgreementPublicKey {
  
  public func ephemeralPrivateKey() throws -> KeyAgreementPrivateKey {
    return try P256.KeyAgreement.PrivateKey()
  }
}

extension SecureEnclave.P256.Signing.PrivateKey: SigningPrivateKey {
  
  public var signingPublicKey: SigningPublicKey {
    return publicKey
  }
  
  public func computeSignature<D>(
    for data: D
  ) throws -> Data where D : DataProtocol {
    return try signature(for: data).rawRepresentation
  }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: KeyAgreementPrivateKey {
  
  public var keyAgreementPublicKey: KeyAgreementPublicKey {
    return publicKey
  }
  
  public func computeSharedSecretFromKeyAgreement(
    with publicKeyShare: KeyAgreementPublicKey
  ) throws -> SharedSecret {
    let publicKey = try P256.KeyAgreement.PublicKey(
      rawRepresentation: publicKeyShare.rawRepresentation
    )
    return try sharedSecretFromKeyAgreement(with: publicKey)
  }
  
  public static func createPublicKey<D>(
    rawRepresentation: D
  ) throws -> KeyAgreementPublicKey where D : ContiguousBytes {
    return try P256.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation)
  }
}

extension P521.Signing.PrivateKey: SigningPrivateKey {
  
  public var signingPublicKey: SigningPublicKey {
    return publicKey
  }
  
  public func computeSignature<D>(
    for data: D
  ) throws -> Data where D : DataProtocol {
    return try signature(for: data).rawRepresentation
  }
}

extension P521.Signing.PublicKey: SigningPublicKey {
  
  public func computeIsValidSignature<S, D>(
    _ signature: S,
    for data: D) -> Bool where S : DataProtocol, D : DataProtocol {
    do {
      let signature = try P521.Signing.ECDSASignature(
        rawRepresentation: signature
      )
      return isValidSignature(signature, for: data)
    }
    catch {
      return false
    }
  }
}

extension P521.KeyAgreement.PrivateKey: KeyAgreementPrivateKey {
  
  public var keyAgreementPublicKey: KeyAgreementPublicKey {
    return publicKey
  }
  
  public func computeSharedSecretFromKeyAgreement(
    with publicKeyShare: KeyAgreementPublicKey
  ) throws -> SharedSecret {
    let publicKey = try P521.KeyAgreement.PublicKey(
      rawRepresentation: publicKeyShare.rawRepresentation
    )
    return try sharedSecretFromKeyAgreement(with: publicKey)
  }
  
  public static func createPublicKey<D>(
    rawRepresentation: D
  ) throws -> KeyAgreementPublicKey where D : ContiguousBytes {
    return try P521.KeyAgreement.PublicKey(rawRepresentation: rawRepresentation)
  }
}

extension P521.KeyAgreement.PublicKey: KeyAgreementPublicKey {
  
  public func ephemeralPrivateKey() throws -> KeyAgreementPrivateKey {
    return try P521.KeyAgreement.PrivateKey()
  }
}
