# Temperature interface references

The read-only Python SMC adapter uses the protocol documented in macmon source at 6300c4f89bc73c9e2dba505bc61bc0ffc27cface.

Source: https://github.com/vladkens/macmon/blob/6300c4f89bc73c9e2dba505bc61bc0ffc27cface/src/sources.rs

MIT License

Copyright (c) 2024 vladkens

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


M2-family sensor key facts were cross-checked against Stats at d51378c2238d1c4148792a914b220d6ca1eca466, Modules/Sensors/values.swift. No Stats implementation code is included.

https://github.com/exelban/stats/blob/d51378c2238d1c4148792a914b220d6ca1eca466/Modules/Sensors/values.swift

## Standalone Mac app runtime

The app bundles CPython 3.14.6, psutil 7.2.2 and the PyInstaller 6.22.3 bootloader. Full runtime and packaging license texts are copied into `Contents/Resources/Licenses` when building. PyInstaller's bootloader distribution exception permits bundling the generated executable; the packaging dependency is not a metrics collector or privileged helper. System AppKit, WebKit, IOKit and Foundation frameworks are supplied by macOS.

Packaging reference: https://pyinstaller.org/en/stable/operating-mode.html
Native web view reference: https://developer.apple.com/documentation/webkit/wkwebview
