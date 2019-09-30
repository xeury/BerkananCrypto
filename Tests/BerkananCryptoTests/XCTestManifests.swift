//
// Copyright © 2019 Apple Inc., IZE Ltd. and the project authors
// Licensed under MIT License
//
// See LICENSE.txt for license information.
//

import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
  return [
    testCase(BerkananCryptoTests.allTests),
  ]
}
#endif
