// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "BlerpcProtocol",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "BlerpcProtocol", targets: ["BlerpcProtocol"]),
    ],
    targets: [
        .target(name: "BlerpcProtocol"),
        .testTarget(name: "BlerpcProtocolTests", dependencies: ["BlerpcProtocol"]),
    ]
)
