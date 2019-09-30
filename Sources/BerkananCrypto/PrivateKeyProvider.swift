//
// Copyright © 2019 IZE Ltd. and the project authors
// Licensed under MIT License
//
// See LICENSE.txt for license information.
//

import Foundation

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
