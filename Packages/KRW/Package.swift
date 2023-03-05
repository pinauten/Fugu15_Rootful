// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "KRW",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "KRW",
            targets: ["KRW"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        //.package(url: "https://github.com/pinauten/KernelPatchfinder", branch: "master"),
        .package(path: "../../OfflinePackages/KernelPatchfinder"),
        .package(url: "https://github.com/pinauten/iDownload", branch: "master"),
        .package(url: "https://github.com/LinusHenze/SwiftXPC", branch: "master"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(name: "KRWC"),
        .target(
            name: "KRW",
            dependencies: ["KRWC", "KernelPatchfinder", "iDownload", "SwiftXPC"]),
    ]
)
