//
// Copyright © 2019 Apple Inc., IZE Ltd. and the project authors
// Licensed under MIT License
//
// See LICENSE.txt for license information.
//

import Foundation
import CryptoKit

/// The interface needed for SecKey conversion.
public protocol SecKeyConvertible: CustomStringConvertible {
  /// Creates a key from an X9.63 representation.
  init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
  
  /// Creates a new key.
  init() throws
  
  /// An X9.63 representation of the key.
  var x963Representation: Data { get }
}

extension SecKeyConvertible {
  /// A string version of the key for visual inspection.
  /// IMPORTANT: Never log the actual key data.
  public var description: String {
    return self.x963Representation.withUnsafeBytes { bytes in
      return "Key representation contains \(bytes.count) bytes."
    }
  }
}

// Assert that the NIST keys are convertible.
extension P256.Signing.PrivateKey: SecKeyConvertible {
  public init() throws {
    self.init(compactRepresentable: true)
  }
}
extension P256.KeyAgreement.PrivateKey: SecKeyConvertible {
  public init() throws {
    self.init(compactRepresentable: true)
  }
}
extension P384.Signing.PrivateKey: SecKeyConvertible {
  public init() throws {
    self.init(compactRepresentable: true)
  }
}
extension P384.KeyAgreement.PrivateKey: SecKeyConvertible {
  public init() throws {
    self.init(compactRepresentable: true)
  }
}
extension P521.Signing.PrivateKey: SecKeyConvertible {
  public init() throws {
    self.init(compactRepresentable: true)
  }
}
extension P521.KeyAgreement.PrivateKey: SecKeyConvertible {
  public init() throws {
    self.init(compactRepresentable: true)
  }
}
