# nstrip - Advanced ELF Binary Size Optimizer

## Overview

nstrip is a powerful utility written in Nim that reduces the size of ELF executables and shared libraries by removing unnecessary data. Unlike standard tools like `strip`, nstrip goes further by eliminating all data not referenced by the program headers, potentially achieving much greater size reductions.

## Features

- **Deep Stripping**: Removes all data not referenced by program headers
- **Zero Stripping**: Optional removal of trailing zero bytes
- **Non-destructive Mode**: Can save optimized results to a new file while preserving the original
- **Colorful Output**: Clear visual feedback with detailed size reduction statistics
- **Batch Processing**: Process multiple files in a single command

## Installation

Install nstrip easily using Nimble, Nim's package manager:

```
nimble install nstrip
```

This will download, compile, and install the latest version of nstrip to your system.

## How It Works

nstrip performs several sophisticated operations on ELF binaries:

1. **ELF Structure Analysis**: Reads and validates the ELF header and program headers.
2. **Minimum Size Calculation**: Determines the smallest possible file size that preserves all data needed at runtime by analyzing program segments.
3. **Optional Zero Removal**: Can scan for and remove trailing zero bytes for additional size reduction.
4. **Header Updates**: Modifies ELF header and program headers to reflect the new file size and structure.
5. **File Truncation**: Safely resizes the file to remove unnecessary data.

### Technical Details

nstrip operates based on a key insight about ELF files: at runtime, the dynamic loader/kernel only needs data explicitly referenced by program headers. This includes:

- The ELF header
- The program header table
- All segments referenced by program headers

Other data, including:
- Section header table
- Section headers
- Symbol tables
- String tables
- Debugging information

...can be safely removed without affecting the binary's execution.

## Usage

```
nstrip [OPTIONS] FILE...

Options:
  -z, --zeros        Also discard trailing zero bytes
  -o, --output FILE  Save compressed result to new file, keeping original intact
      --help         Display this help and exit
      --version      Display version information and exit
```

### Examples

Strip a single executable, modifying it in place:
```
nstrip myprogram
```

Strip multiple files, with additional zero byte removal:
```
nstrip -z file1 file2 file3
```

Process a file and save the result to a new location:
```
nstrip --output optimized_binary original_binary
```

## Performance Considerations

- **Size Reduction**: Typically achieves 10-20% reduction beyond standard strip tools
- **File Types**: Works on executables and shared libraries (ET_EXEC and ET_DYN ELF types)
- **Integrity**: Preserves all data needed for execution while removing unused data
- **Compatibility**: Works with standard ELF binaries on Linux/Unix systems

## Implementation Notes

nstrip is implemented in Nim and uses:
- Native ELF structure parsing with no external dependencies
- POSIX file operations for efficient file handling
- Optimized buffer-based I/O for handling large files
- Comprehensive error handling with informative error messages

## Limitations

- Only works with ELF format binaries
- Removes information needed for debugging
- Not recommended for use on system libraries that may require section headers

## Credits

Based on the original sstrip concept by Brian Raiter.
 - https://github.com/BR903/ELFkickers/blob/master/sstrip/sstrip.c
Created by Sultan Al-Isaiee (foxoman).
