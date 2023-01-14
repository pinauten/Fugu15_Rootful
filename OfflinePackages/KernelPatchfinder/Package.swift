// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "KernelPatchfinder",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "KernelPatchfinder",
            targets: ["KernelPatchfinder"]),
        .executable(name: "KernelPatchfinderTester", targets: ["KernelPatchfinderTester"])
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(name: "SwiftUtils", url: "https://github.com/pinauten/SwiftUtils", .branch("master")),
        .package(name: "SwiftMachO", url: "https://github.com/pinauten/SwiftMachO", .branch("master")),
        .package(name: "PatchfinderUtils", url: "https://github.com/pinauten/PatchfinderUtils", .branch("master"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "KernelPatchfinder",
            dependencies: ["SwiftUtils", "SwiftMachO", "PatchfinderUtils"]),
        .testTarget(
            name: "KernelPatchfinderTests",
            dependencies: ["KernelPatchfinder"]),
        .target(
            name: "KernelPatchfinderTester",
            dependencies: ["SwiftUtils", "SwiftMachO", "KernelPatchfinder"]),
    ]
)
