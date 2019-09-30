// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to
// build this package.

import PackageDescription

let package = Package(
  name: "BerkananCrypto",
  platforms: [
    .iOS(.v13), .macOS(.v10_15), .tvOS(.v13), .watchOS(.v6),
  ],
  products: [
    .library(
      name: "BerkananCrypto",
      targets: ["BerkananCrypto"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.6.0"),
  ],
  targets: [
    .target(
      name: "BerkananCrypto",
      dependencies: ["SwiftProtobuf"]),
    .testTarget(
      name: "BerkananCryptoTests",
      dependencies: ["BerkananCrypto"]),
  ]
)
