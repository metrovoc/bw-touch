// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "bw-touch",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "BWTouchCore", targets: ["BWTouchCore"]),
        .executable(name: "bw-touch", targets: ["bw-touch"]),
    ],
    targets: [
        .target(name: "BWTouchCore"),
        .executableTarget(name: "bw-touch", dependencies: ["BWTouchCore"]),
        .testTarget(name: "BWTouchCoreTests", dependencies: ["BWTouchCore"]),
    ]
)
