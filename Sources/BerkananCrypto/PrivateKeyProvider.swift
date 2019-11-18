//
// Copyright © 2019 IZE Ltd. and the project authors
// Licensed under MIT License
//
// See LICENSE.txt for license information.
//

import Foundation
import CryptoKit

public protocol PrivateKeyProvider {
  
  var privateKeyType: PrivateKeyType { get }
  
  func signingPrivateKey() throws -> SigningPrivateKey
  
  func keyAgreementPrivateKey() throws -> KeyAgreementPrivateKey
}

public struct AnyPrivateKeyProvider: PrivateKeyProvider {
  
  public var privateKeyType: PrivateKeyType {
    return base.privateKeyType
  }
  
  public func signingPrivateKey() throws -> SigningPrivateKey {
    return try base.signingPrivateKey()
  }
  
  public func keyAgreementPrivateKey() throws -> KeyAgreementPrivateKey {
    return try base.keyAgreementPrivateKey()
  }
  
  private var base: PrivateKeyProvider
  
  public init(_ base: PrivateKeyProvider) {
    self.base = base
  }
}

extension P256.KeyAgreement.PrivateKey: PrivateKeyProvider {
    
    public var privateKeyType: PrivateKeyType {
        return .p256
    }
    
    public func signingPrivateKey() throws -> SigningPrivateKey {
        throw CocoaError(.coderValueNotFound)
    }
    
    public func keyAgreementPrivateKey() throws -> KeyAgreementPrivateKey {
        return self
    }
}

extension P256.Signing.PrivateKey: PrivateKeyProvider {
    
    public var privateKeyType: PrivateKeyType {
        return .p256
    }
    
    public func signingPrivateKey() throws -> SigningPrivateKey {
        return self
    }
    
    public func keyAgreementPrivateKey() throws -> KeyAgreementPrivateKey {
        throw CocoaError(.coderValueNotFound)
    }
}
