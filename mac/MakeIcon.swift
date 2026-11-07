import AppKit

let destination = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        let image = NSImage(size: NSSize(width: pixels, height: pixels))
        image.lockFocus()
        let factor = CGFloat(pixels) / 1024
        let transform = NSAffineTransform()
        transform.scale(by: factor)
        transform.concat()
        NSColor(calibratedRed: 0.055, green: 0.105, blue: 0.14, alpha: 1).setFill()
        NSBezierPath(roundedRect: NSRect(x: 62, y: 62, width: 900, height: 900), xRadius: 202, yRadius: 202).fill()
        NSColor(calibratedRed: 0.16, green: 0.27, blue: 0.32, alpha: 1).setStroke()
        for y in [CGFloat(300), 510, 720] {
            let grid = NSBezierPath()
            grid.move(to: NSPoint(x: 198, y: y)); grid.line(to: NSPoint(x: 828, y: y))
            grid.lineWidth = 10; grid.stroke()
        }
        let pulse = NSBezierPath()
        pulse.move(to: NSPoint(x: 192, y: 440))
        for point in [NSPoint(x: 335, y: 440), NSPoint(x: 414, y: 650), NSPoint(x: 512, y: 310),
                      NSPoint(x: 605, y: 566), NSPoint(x: 670, y: 440), NSPoint(x: 828, y: 440)] { pulse.line(to: point) }
        pulse.lineWidth = 54; pulse.lineJoinStyle = .round; pulse.lineCapStyle = .round
        NSColor(calibratedRed: 0.35, green: 0.88, blue: 0.73, alpha: 1).setStroke(); pulse.stroke()
        NSColor(calibratedRed: 0.96, green: 0.77, blue: 0.35, alpha: 1).setFill()
        NSBezierPath(ovalIn: NSRect(x: 747, y: 706, width: 70, height: 70)).fill()
        image.unlockFocus()
        let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
        let data = bitmap.representation(using: .png, properties: [:])!
        let name = "icon_\(size)x\(size)\(scale == 2 ? "@2x" : "").png"
        try data.write(to: destination.appendingPathComponent(name))
    }
}
