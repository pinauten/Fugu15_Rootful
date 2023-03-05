// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "stashd",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .executable(
            name: "stashd",
            targets: ["stashd"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/LinusHenze/SwiftXPC", branch: "master"),
        .package(path: "../OfflinePackages/KernelPatchfinder")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(name: "CBridge"),
        .executableTarget(
            name: "stashd",
            dependencies: ["CBridge", "SwiftXPC", "KernelPatchfinder"]),
    ]
)
