#!/usr/bin/env swift
// generate-spectral-tiffs.swift
// macOS CoreGraphics monochrome spectral TIFF generator
// Produces 5 image sets for iccSpecSepToTiff testing and CFL fuzzer seeding
//
// Usage: swift generate-spectral-tiffs.swift [output_dir]
// Default output: current directory

import Foundation
import CoreGraphics
import ImageIO
import CoreText

let outputDir: String
if CommandLine.arguments.count > 1 {
    outputDir = CommandLine.arguments[1]
} else {
    outputDir = FileManager.default.currentDirectoryPath
}

func ensureDir(_ path: String) {
    try? FileManager.default.createDirectory(
        atPath: path, withIntermediateDirectories: true)
}

ensureDir(outputDir)

// MARK: - Set A: 16-bit 4x4 wavelength TIFFs (81 files)
func generateSetA() {
    print("Set A: 81 CoreGraphics 16-bit 4×4 wavelength TIFFs...")
    let width = 4, height = 4, bps = 16
    let bytesPerRow = width * 2  // 16-bit = 2 bytes per pixel

    for wl in stride(from: 380, through: 780, by: 5) {
        let filename = String(format: "cg_wl_%03d.tif", wl)
        let path = (outputDir as NSString).appendingPathComponent(filename)
        let url = URL(fileURLWithPath: path)

        // Gradient value based on wavelength
        let v = UInt16(clamping: (wl - 380) * 800 / 10)

        var pixels = [UInt16](repeating: 0, count: width * height)
        for y in 0..<height {
            for x in 0..<width {
                // Create a simple gradient: base + position offset
                let offset = UInt16(clamping: Int(v) + y * 200 + x * 50)
                pixels[y * width + x] = offset
            }
        }

        let colorSpace = CGColorSpaceCreateDeviceGray()
        pixels.withUnsafeMutableBufferPointer { buf in
            guard let ctx = CGContext(
                data: buf.baseAddress,
                width: width, height: height,
                bitsPerComponent: bps,
                bytesPerRow: bytesPerRow,
                space: colorSpace,
                bitmapInfo: CGImageAlphaInfo.none.rawValue
            ) else {
                print("  ERROR: Failed to create context for \(filename)")
                return
            }

            guard let image = ctx.makeImage() else {
                print("  ERROR: Failed to make image for \(filename)")
                return
            }

            let props: [CFString: Any] = [
                kCGImagePropertyDPIWidth: 72.0,
                kCGImagePropertyDPIHeight: 72.0,
                kCGImagePropertyTIFFDictionary: [
                    kCGImagePropertyTIFFCompression: 1,  // No compression
                    kCGImagePropertyTIFFSoftware: "CoreGraphics-SpectralGen-1.0",
                ] as [CFString: Any],
            ]

            guard let dest = CGImageDestinationCreateWithURL(
                url as CFURL, "public.tiff" as CFString, 1, nil)
            else {
                print("  ERROR: Failed to create destination for \(filename)")
                return
            }

            CGImageDestinationAddImage(dest, image, props as CFDictionary)
            if !CGImageDestinationFinalize(dest) {
                print("  ERROR: Failed to finalize \(filename)")
            }
        }
    }
    print("  Set A complete: 81 files")
}

// MARK: - Set B: 8-bit 32x32 TIFFs (31 files)
func generateSetB() {
    print("Set B: 31 CoreGraphics 8-bit 32×32 TIFFs...")
    let width = 32, height = 32, bps = 8
    let bytesPerRow = width

    for wl in stride(from: 400, through: 700, by: 10) {
        let filename = String(format: "cg_8b_%03d.tif", wl)
        let path = (outputDir as NSString).appendingPathComponent(filename)
        let url = URL(fileURLWithPath: path)

        let baseVal = UInt8(clamping: (wl - 400) * 255 / 300)

        var pixels = [UInt8](repeating: 0, count: width * height)
        for y in 0..<height {
            for x in 0..<width {
                let v = Int(baseVal) + (x * 4) + (y * 2)
                pixels[y * width + x] = UInt8(clamping: v)
            }
        }

        let colorSpace = CGColorSpaceCreateDeviceGray()
        pixels.withUnsafeMutableBufferPointer { buf in
            guard let ctx = CGContext(
                data: buf.baseAddress,
                width: width, height: height,
                bitsPerComponent: bps,
                bytesPerRow: bytesPerRow,
                space: colorSpace,
                bitmapInfo: CGImageAlphaInfo.none.rawValue
            ),
                let image = ctx.makeImage()
            else {
                print("  ERROR: \(filename)")
                return
            }

            let props: [CFString: Any] = [
                kCGImagePropertyDPIWidth: 72.0,
                kCGImagePropertyDPIHeight: 72.0,
                kCGImagePropertyTIFFDictionary: [
                    kCGImagePropertyTIFFCompression: 1,
                    kCGImagePropertyTIFFSoftware: "CoreGraphics-SpectralGen-1.0",
                ] as [CFString: Any],
            ]

            guard let dest = CGImageDestinationCreateWithURL(
                url as CFURL, "public.tiff" as CFString, 1, nil)
            else { return }
            CGImageDestinationAddImage(dest, image, props as CFDictionary)
            CGImageDestinationFinalize(dest)
        }
    }
    print("  Set B complete: 31 files")
}

// MARK: - Set C: 256x256 16-bit large TIFFs (10 files)
func generateSetC() {
    print("Set C: 10 CoreGraphics 256×256 16-bit TIFFs...")
    let width = 256, height = 256, bps = 16
    let bytesPerRow = width * 2

    for i in 1...10 {
        let filename = String(format: "cg_lg_%03d.tif", i)
        let path = (outputDir as NSString).appendingPathComponent(filename)
        let url = URL(fileURLWithPath: path)

        var pixels = [UInt16](repeating: 0, count: width * height)
        for y in 0..<height {
            for x in 0..<width {
                // Varied pattern per file: diagonal gradient + file-specific offset
                let v = (x * 256 + y * 128 + i * 3000) % 65536
                pixels[y * width + x] = UInt16(v)
            }
        }

        let colorSpace = CGColorSpaceCreateDeviceGray()
        pixels.withUnsafeMutableBufferPointer { buf in
            guard let ctx = CGContext(
                data: buf.baseAddress,
                width: width, height: height,
                bitsPerComponent: bps,
                bytesPerRow: bytesPerRow,
                space: colorSpace,
                bitmapInfo: CGImageAlphaInfo.none.rawValue
            ),
                let image = ctx.makeImage()
            else {
                print("  ERROR: \(filename)")
                return
            }

            let props: [CFString: Any] = [
                kCGImagePropertyDPIWidth: 72.0,
                kCGImagePropertyDPIHeight: 72.0,
                kCGImagePropertyTIFFDictionary: [
                    kCGImagePropertyTIFFCompression: 1,
                    kCGImagePropertyTIFFSoftware: "CoreGraphics-SpectralGen-1.0",
                ] as [CFString: Any],
            ]

            guard let dest = CGImageDestinationCreateWithURL(
                url as CFURL, "public.tiff" as CFString, 1, nil)
            else { return }
            CGImageDestinationAddImage(dest, image, props as CFDictionary)
            CGImageDestinationFinalize(dest)
        }
    }
    print("  Set C complete: 10 files")
}

// MARK: - Set D: 32x32 16-bit with embedded ICC profiles (10 files)
func generateSetD() {
    print("Set D: 10 CoreGraphics 32×32 16-bit TIFFs with ICC profiles...")
    let width = 32, height = 32, bps = 16
    let bytesPerRow = width * 2

    let iccPaths = [
        "/System/Library/ColorSync/Profiles/Generic Gray Gamma 2.2 Profile.icc",
        "/System/Library/ColorSync/Profiles/sRGB Profile.icc",
        "/System/Library/ColorSync/Profiles/Generic Gray Profile.icc",
        "/System/Library/ColorSync/Profiles/Adobe RGB (1998).icc",
        "/System/Library/ColorSync/Profiles/Display P3.icc",
    ]

    for i in 1...10 {
        let filename = String(format: "cg_icc_%03d.tif", i)
        let path = (outputDir as NSString).appendingPathComponent(filename)
        let url = URL(fileURLWithPath: path)

        var pixels = [UInt16](repeating: 0, count: width * height)
        for y in 0..<height {
            for x in 0..<width {
                let v = (x * 2048 + y * 1024 + i * 5000) % 65536
                pixels[y * width + x] = UInt16(v)
            }
        }

        // Try to load a system ICC profile for the gray color space
        let iccPath = iccPaths[(i - 1) % iccPaths.count]
        var colorSpace: CGColorSpace

        if let iccData = NSData(contentsOfFile: iccPath) as Data?,
            let iccSpace = CGColorSpace(iccProfileData: iccData as CFData)
        {
            // Only use if it's actually a gray color space (1 component)
            if iccSpace.numberOfComponents == 1 {
                colorSpace = iccSpace
            } else {
                colorSpace = CGColorSpaceCreateDeviceGray()
            }
        } else {
            colorSpace = CGColorSpaceCreateDeviceGray()
        }

        pixels.withUnsafeMutableBufferPointer { buf in
            guard let ctx = CGContext(
                data: buf.baseAddress,
                width: width, height: height,
                bitsPerComponent: bps,
                bytesPerRow: bytesPerRow,
                space: colorSpace,
                bitmapInfo: CGImageAlphaInfo.none.rawValue
            ),
                let image = ctx.makeImage()
            else {
                // Fallback to device gray if ICC color space didn't work
                let fallbackCS = CGColorSpaceCreateDeviceGray()
                guard let ctx2 = CGContext(
                    data: buf.baseAddress,
                    width: width, height: height,
                    bitsPerComponent: bps,
                    bytesPerRow: bytesPerRow,
                    space: fallbackCS,
                    bitmapInfo: CGImageAlphaInfo.none.rawValue
                ),
                    let image2 = ctx2.makeImage()
                else {
                    print("  ERROR: \(filename)")
                    return
                }
                writeTIFF(image: image2, url: url)
                return
            }
            writeTIFF(image: image, url: url)
        }
    }
    print("  Set D complete: 10 files")
}

func writeTIFF(image: CGImage, url: URL) {
    let props: [CFString: Any] = [
        kCGImagePropertyDPIWidth: 72.0,
        kCGImagePropertyDPIHeight: 72.0,
        kCGImagePropertyTIFFDictionary: [
            kCGImagePropertyTIFFCompression: 1,
            kCGImagePropertyTIFFSoftware: "CoreGraphics-SpectralGen-1.0",
        ] as [CFString: Any],
    ]
    guard let dest = CGImageDestinationCreateWithURL(
        url as CFURL, "public.tiff" as CFString, 1, nil)
    else { return }
    CGImageDestinationAddImage(dest, image, props as CFDictionary)
    CGImageDestinationFinalize(dest)
}

// MARK: - Set E: 64x64 8-bit digit images (10 files)
func generateSetE() {
    print("Set E: 10 CoreGraphics 64×64 8-bit digit TIFFs...")
    let width = 64, height = 64, bps = 8
    let bytesPerRow = width

    for digit in 0...9 {
        let filename = String(format: "cg_digit_%d.tif", digit)
        let path = (outputDir as NSString).appendingPathComponent(filename)
        let url = URL(fileURLWithPath: path)

        let colorSpace = CGColorSpaceCreateDeviceGray()
        guard let ctx = CGContext(
            data: nil,
            width: width, height: height,
            bitsPerComponent: bps,
            bytesPerRow: bytesPerRow,
            space: colorSpace,
            bitmapInfo: CGImageAlphaInfo.none.rawValue
        ) else {
            print("  ERROR: \(filename)")
            continue
        }

        // Fill background with white
        ctx.setFillColor(gray: 1.0, alpha: 1.0)
        ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))

        // Draw digit in black using CoreText
        ctx.setFillColor(gray: 0.0, alpha: 1.0)

        let digitStr = "\(digit)" as CFString
        let font = CTFontCreateWithName("Helvetica-Bold" as CFString, 48, nil)
        let attrs: [CFString: Any] = [
            kCTFontAttributeName: font,
            kCTForegroundColorFromContextAttributeName: true,
        ]
        let attrStr = CFAttributedStringCreate(nil, digitStr, attrs as CFDictionary)!
        let line = CTLineCreateWithAttributedString(attrStr)

        // Center the digit
        let bounds = CTLineGetBoundsWithOptions(line, [])
        let xPos = (CGFloat(width) - bounds.width) / 2 - bounds.origin.x
        let yPos = (CGFloat(height) - bounds.height) / 2 - bounds.origin.y

        ctx.textPosition = CGPoint(x: xPos, y: yPos)
        CTLineDraw(line, ctx)

        guard let image = ctx.makeImage() else {
            print("  ERROR: makeImage for \(filename)")
            continue
        }

        writeTIFF(image: image, url: url)
    }
    print("  Set E complete: 10 files")
}

// MARK: - Main
print("CoreGraphics Spectral TIFF Generator")
print("Output: \(outputDir)")
print("---")

generateSetA()
generateSetB()
generateSetC()
generateSetD()
generateSetE()

let total =
    (try? FileManager.default.contentsOfDirectory(atPath: outputDir)
        .filter { $0.hasSuffix(".tif") }.count) ?? 0
print("---")
print("Total TIFF files: \(total)")
print("Done.")
