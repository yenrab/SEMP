// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SEMP",
    platforms: [
            .macOS(.v12) // Set macOS 12.0 as the minimum deployment target
        ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SEMP",
            targets: ["SEMP"]),
    ],
    dependencies: [
        .package(url:"https://github.com/inter-erlang/SwErl.git", from: "0.9.20"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SEMP",
            dependencies: [.product(name: "SwErl", package: "SwErl")]),
        .testTarget(
            name: "SEMPTests",
            dependencies: ["SEMP"]
        ),
    ]
)
