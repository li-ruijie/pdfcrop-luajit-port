# pdfcrop-luajit-port

A LuaJIT port of the [pdfcrop](https://ctan.org/pkg/pdfcrop) tool by Heiko Oberdiek.

## Description

`pdfcrop` calculates and removes page margins from PDF files. This port rewrites the original Perl script in LuaJIT, leveraging FFI for efficient system calls and Windows Registry access.

## Features

- LuaJIT implementation with FFI for native system calls
- Cross-platform support (Windows and Unix)
- Direct Windows Registry access for Ghostscript detection (no shell commands)
- Native process ID and executable search via FFI
- Support for pdfTeX, XeTeX, and LuaTeX backends
- Per-page or global bounding box overrides
- Margin adjustment with optional clipping
- PDF version control

## Requirements

- LuaJIT 2.0+ (or LuaJIT-compatible runtime)
- Ghostscript
- A TeX engine (pdfTeX, XeTeX, or LuaTeX)

## Usage

```
luajit pdfcrop.lua [options] <input.pdf> [output.pdf]
```

### Options

| Option | Description |
|--------|-------------|
| `--help` | Print usage information |
| `--version` | Print version number |
| `--verbose` / `--noverbose` | Enable/disable verbose output |
| `--quiet` / `--noquiet` | Enable/disable normal output |
| `--debug` / `--nodebug` | Enable/disable debug information |
| `--gscmd <name>` | Specify Ghostscript command |
| `--pdftex` / `--xetex` / `--luatex` | Select TeX engine |
| `--margins "<l> <t> <r> <b>"` | Add extra margins (in bp) |
| `--clip` / `--noclip` | Enable/disable clipping |
| `--hires` / `--nohires` | Use HiResBoundingBox |
| `--ini` / `--noini` | Use iniTeX variant |

### Expert Options

| Option | Description |
|--------|-------------|
| `--restricted` | Enable restricted mode |
| `--papersize <size>` | Set Ghostscript paper size |
| `--resolution <dpi>` | Set Ghostscript resolution |
| `--bbox "<l> <b> <r> <t>"` | Override bounding box for all pages |
| `--bbox-odd "<l> <b> <r> <t>"` | Override bounding box for odd pages |
| `--bbox-even "<l> <b> <r> <t>"` | Override bounding box for even pages |
| `--pdfversion <ver>` | Set PDF version (e.g., 1.4, auto, none) |
| `--uncompress` | Create uncompressed PDF |

## Examples

Basic cropping:
```bash
luajit pdfcrop.lua input.pdf output.pdf
```

Add 10bp margins on all sides:
```bash
luajit pdfcrop.lua --margins 10 input.pdf output.pdf
```

Crop with clipping and custom margins:
```bash
luajit pdfcrop.lua --clip --margins "5 10 5 10" input.pdf output.pdf
```

Use XeTeX backend:
```bash
luajit pdfcrop.lua --xetex input.pdf output.pdf
```

## LuaJIT vs Lua 5.4 Version

This LuaJIT version uses FFI for:
- Direct Windows API calls (`GetCurrentProcessId`, `SearchPathA`, Registry APIs)
- Unix system calls (`getpid`, `access`)

For a pure Lua 5.4 version without FFI dependencies, see [pdfcrop-lua5-port](https://github.com/li-ruijie/pdfcrop-lua5-port).

## Credits

- Original pdfcrop: Heiko Oberdiek, Oberdiek Package Support Group
- Lua port: Li Ruijie

## License

This work is licensed under the LaTeX Project Public License (LPPL) version 1.3c or later.
See the [LICENSE](LICENSE) file for details.
