//
// Copyright © 2019 IZE Ltd. and the project authors
// Licensed under MIT License
//
// See LICENSE.txt for license information.
//

import Foundation
import CryptoKit

extension HashFunction {
  
  /// Computes a digest of the file at path.
  ///
  /// - Parameter fileAtPath: The path of the file to be hashed
  /// - Returns: The computed digest
  @inlinable public static func hash(
    fileAtPath: String,
    bufferCapacity: Int = 65536
  ) -> Self.Digest {
    var hasher = Self()
    let fileStream = InputStream(fileAtPath: fileAtPath)!
    fileStream.open()
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferCapacity)
    defer {
      buffer.deallocate()
      fileStream.close()
    }
    while fileStream.hasBytesAvailable {
      let read = fileStream.read(buffer, maxLength: bufferCapacity)
      let bufferPointer = UnsafeRawBufferPointer(start: buffer, count: read)
      hasher.update(bufferPointer: bufferPointer)
    }
    let digest = hasher.finalize()
    return digest
  }
}
