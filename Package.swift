// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Kit25519",
    platforms: [
       .macOS(.v10_15), .iOS(.v13), .tvOS(.v15), .watchOS(.v8)
    ],
    products: [
        .library(
            name: "Kit25519",
            targets: ["Kit25519"]),
    ],
    dependencies: [
      .package(url: "https://github.com/hermanbanken/ASN1Parser.git", revision: "64f242bda54b7da542268fcba1569607b00e53ec")
    ],
    targets: [
        .target(
            name: "Kit25519",
            dependencies: [
                .product(name: "ASN1Parser", package: "ASN1Parser")
            ]),
        .testTarget(
            name: "Kit25519Tests",
            dependencies: [
                "Kit25519",
                .product(name: "ASN1Parser", package: "ASN1Parser")
            ]),
    ]
)
