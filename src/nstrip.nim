# nstrip.nim
# A Nim utility to strip nonessential bytes from ELF binary files
# Based on sstrip by Brian Raiter <breadbox@muppetlabs.com>
# - https://github.com/BR903/ELFkickers/blob/master/sstrip/sstrip.c
# Created in Nim by Sultan Al-Isaiee aka foxoman
# Copyright (C) 2025
#
# License: GPLv2+: GNU GPL version 2 or later.
# This is free software; you are free to change and redistribute it.
# There is NO WARRANTY, to the extent permitted by law.

import std/[os, strutils, parseopt, strformat, posix]

type
  # Program options
  Options = object
    stripZeros: bool
    files: seq[string]
    outputFile: string

  # ELF structures
  Elf64_Half = uint16
  Elf64_Word = uint32
  Elf64_Addr = uint64
  Elf64_Off = uint64
  Elf64_Xword = uint64

  Elf64_Ehdr = object
    e_ident: array[16, uint8]
    e_type: Elf64_Half
    e_machine: Elf64_Half
    e_version: Elf64_Word
    e_entry: Elf64_Addr
    e_phoff: Elf64_Off
    e_shoff: Elf64_Off
    e_flags: Elf64_Word
    e_ehsize: Elf64_Half
    e_phentsize: Elf64_Half
    e_phnum: Elf64_Half
    e_shentsize: Elf64_Half
    e_shnum: Elf64_Half
    e_shstrndx: Elf64_Half

  Elf64_Phdr = object
    p_type: Elf64_Word
    p_flags: Elf64_Word
    p_offset: Elf64_Off
    p_vaddr: Elf64_Addr
    p_paddr: Elf64_Addr
    p_filesz: Elf64_Xword
    p_memsz: Elf64_Xword
    p_align: Elf64_Xword

  StripError = object of CatchableError

const
  # ELF constants
  ET_EXEC = 2.Elf64_Half # Executable file
  ET_DYN = 3.Elf64_Half # Shared object file
  PT_NULL = 0.Elf64_Word # Unused program segment

  # ELF identification constants
  EI_MAG0 = 0
  EI_MAG1 = 1
  EI_MAG2 = 2
  EI_MAG3 = 3
  ELFMAG0 = 0x7f.uint8
  ELFMAG1 = 'E'.uint8
  ELFMAG2 = 'L'.uint8
  ELFMAG3 = 'F'.uint8

  # I/O constants
  BufferSize = 8192 # Read buffer size - increased for better performance

  # ANSI Colors
  ColorReset = "\e[0m"
  ColorBold = "\e[1m"
  ColorRed = "\e[31m"
  ColorGreen = "\e[32m"
  ColorYellow = "\e[33m"
  ColorBlue = "\e[34m"
  ColorMagenta = "\e[35m"
  ColorCyan = "\e[36m"
  ColorWhite = "\e[37m"

  # Program text
  HelpText =
    """
🔧 nstrip - Remove nonessential bytes from ELF binary files

Usage: nstrip [OPTIONS] FILE...

Options:
  -z, --zeros        Also discard trailing zero bytes
  -o, --output FILE  Save compressed result to new file, keeping original intact
      --help         Display this help and exit
      --version      Display version information and exit
"""

  VersionText =
    """
nstrip version 1.0.0
Created by Sultan Al-Isaiee aka foxoman

License GPLv2+: GNU GPL version 2 or later.
This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
"""

proc colorPrint(msg: string, color: string) =
  ## Print colorful message
  stdout.write(color & msg & ColorReset)
  stdout.flushFile()

proc colorPrintLn(msg: string, color: string) =
  ## Print colorful message with newline
  echo color & msg & ColorReset

proc log(msg: string) =
  ## Log message - now always verbose
  colorPrintLn(msg, ColorCyan)

proc isValidElf(header: Elf64_Ehdr): bool =
  ## Check if the file has a valid ELF header
  result =
    header.e_ident[EI_MAG0] == ELFMAG0 and header.e_ident[EI_MAG1] == ELFMAG1 and
    header.e_ident[EI_MAG2] == ELFMAG2 and header.e_ident[EI_MAG3] == ELFMAG3

proc isExecutable(header: Elf64_Ehdr): bool =
  ## Check if the ELF file is an executable or shared library
  result = header.e_type == ET_EXEC or header.e_type == ET_DYN

proc hasProgramHeaders(header: Elf64_Ehdr): bool =
  ## Check if the ELF file has program headers
  result = header.e_phoff > 0 and header.e_phnum > 0

proc readElfFile(f: File): tuple[header: Elf64_Ehdr, segments: seq[Elf64_Phdr]] =
  ## Read ELF header and program segments from a file

  # Read ELF header
  var header: Elf64_Ehdr
  if f.readBuffer(addr header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr):
    raise newException(StripError, "failed to read ELF header")

  # Validate ELF file
  if not isValidElf(header):
    raise newException(StripError, "not a valid ELF file")

  if not isExecutable(header):
    raise newException(StripError, "not an executable or shared-object library")

  if not hasProgramHeaders(header):
    raise newException(StripError, "ELF file has no program header table")

  # Read program headers
  var segments = newSeq[Elf64_Phdr](header.e_phnum)

  try:
    f.setFilePos(int(header.e_phoff))
  except IOError:
    raise newException(StripError, "cannot seek to program header table")

  let phdrSize = int(header.e_phnum) * sizeof(Elf64_Phdr)
  if f.readBuffer(addr segments[0], phdrSize) != phdrSize:
    raise newException(StripError, "failed to read program header table")

  result = (header, segments)

proc findMinimumSize(header: Elf64_Ehdr, segments: seq[Elf64_Phdr]): uint64 =
  ## Calculate the minimum file size needed to preserve all referenced data

  # Start with ELF header and program header table size
  result = max(
    header.e_phoff + header.e_phnum.uint64 * sizeof(Elf64_Phdr).uint64,
    header.e_ehsize.uint64,
  )

  # Include all referenced segment data
  for segment in segments:
    if segment.p_type != PT_NULL:
      let segmentEnd = segment.p_offset + segment.p_filesz
      result = max(result, segmentEnd)

proc findLastNonZeroByte(f: File, startSize: uint64): uint64 =
  ## Find the position of the last non-zero byte in the file

  result = startSize
  var buffer = newSeq[byte](BufferSize)

  while result > 0:
    let chunkSize = min(result, BufferSize.uint64)
    let position = result - chunkSize

    try:
      f.setFilePos(int(position))
    except IOError:
      raise newException(StripError, "seek error while scanning for trailing zeros")

    if f.readBuffer(addr buffer[0], int(chunkSize)) != int(chunkSize):
      raise newException(StripError, "read error while scanning for trailing zeros")

    # Scan buffer backwards for non-zero bytes
    for i in countdown(int(chunkSize) - 1, 0):
      if buffer[i] != 0:
        return position + i.uint64 + 1

    result = position

  # If we get here, the file is all zeros
  raise newException(StripError, "ELF file contains no non-zero bytes")

proc updateElfHeaders(
    header: var Elf64_Ehdr, segments: var seq[Elf64_Phdr], newSize: uint64
) =
  ## Update ELF headers to reflect the new file size

  # Remove section header table if it's beyond the new file size
  if header.e_shoff >= newSize:
    header.e_shoff = 0
    header.e_shnum = 0
    header.e_shstrndx = 0

  # Update program segments
  for i in 0 ..< int(header.e_phnum):
    if segments[i].p_offset >= newSize:
      # Segment is completely outside new file size
      segments[i].p_offset = newSize
      segments[i].p_filesz = 0
    elif segments[i].p_offset + segments[i].p_filesz > newSize:
      # Segment extends beyond new file size - truncate it
      segments[i].p_filesz = newSize - segments[i].p_offset

proc writeElfChanges(
    f: File,
    header: Elf64_Ehdr,
    segments: seq[Elf64_Phdr],
    filename: string,
    newSize: uint64,
) =
  ## Write updated headers and truncate the file

  # Write ELF header
  try:
    f.setFilePos(0)
  except IOError:
    raise newException(StripError, "failed to seek to start of file")

  if f.writeBuffer(unsafeAddr header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr):
    raise newException(StripError, "failed to write ELF header")

  # Write program header table
  try:
    f.setFilePos(int(header.e_phoff))
  except IOError:
    raise newException(StripError, "failed to seek to program header table")

  let phdrSize = int(header.e_phnum) * sizeof(Elf64_Phdr)
  if f.writeBuffer(unsafeAddr segments[0], phdrSize) != phdrSize:
    raise newException(StripError, "failed to write program header table")

  # Make sure we never truncate before the end of the program header table
  let minSize = header.e_phoff + header.e_phnum.uint64 * header.e_phentsize.uint64
  let finalSize = max(newSize, minSize)

  # Truncate the file using POSIX truncate
  let result = posix.truncate(filename.cstring, Off(finalSize))
  if result != 0:
    let errMsg = osErrorMsg(osLastError())
    raise newException(StripError, fmt"failed to resize file: {errMsg}")

proc copyFile(source, dest: string, size: uint64) =
  ## Copy a file with a specific size
  var
    sourceFile = open(source, fmRead)
    destFile = open(dest, fmWrite)
    buffer = newSeq[byte](BufferSize)

  defer:
    close(sourceFile)
    close(destFile)

  var remaining = size
  while remaining > 0:
    let chunkSize = min(BufferSize.uint64, remaining)
    let bytesRead = sourceFile.readBuffer(addr buffer[0], int(chunkSize))
    if bytesRead <= 0:
      break

    if destFile.writeBuffer(addr buffer[0], bytesRead) != bytesRead:
      raise newException(StripError, fmt"failed to write to output file: {dest}")

    remaining -= bytesRead.uint64

proc formatSize(bytes: uint64): string =
  ## Format size in human-readable format (bytes, KB, MB)
  if bytes < 1024:
    return fmt"{bytes} bytes"
  elif bytes < 1024 * 1024:
    return fmt"{float(bytes)/1024.0:.2f} KB ({bytes} bytes)"
  else:
    return fmt"{float(bytes)/(1024.0*1024.0):.2f} MB ({bytes} bytes)"

proc stripFile(filename: string, options: Options): bool =
  ## Process a single ELF file, stripping unnecessary bytes
  let programName = getAppFilename().extractFilename()
  let targetFile = if options.outputFile.len > 0: options.outputFile else: filename

  try:
    # Open file for reading
    var f = open(filename, fmRead)

    # Get initial file size
    let originalSize = getFileSize(filename)
    log(fmt"Processing: {filename} (original size: {formatSize(uint64(originalSize))})")

    # Read ELF file
    let (header, segments) = readElfFile(f)
    var modifiedHeader = header
    var modifiedSegments = segments

    # Calculate minimum required size
    var newSize = findMinimumSize(header, segments)
    log(fmt"Minimum required size: {formatSize(newSize)}")

    # Optionally find and remove trailing zeros
    if options.stripZeros:
      let sizeBeforeZeroStrip = newSize
      newSize = findLastNonZeroByte(f, newSize)
      log(
        fmt"Size after zero stripping: {formatSize(newSize)} (removed {sizeBeforeZeroStrip - newSize} bytes)"
      )

    # Update headers
    updateElfHeaders(modifiedHeader, modifiedSegments, newSize)

    # Close the input file
    close(f)

    if options.outputFile.len > 0:
      # When using output file option, we first create a copy of the original file
      copyFile(filename, targetFile, uint64(originalSize))

      # Then modify the output file
      var outFile = open(targetFile, fmReadWriteExisting)
      defer:
        close(outFile)

      # Write updated headers
      outFile.setFilePos(0)
      if outFile.writeBuffer(unsafeAddr modifiedHeader, sizeof(Elf64_Ehdr)) !=
          sizeof(Elf64_Ehdr):
        raise newException(StripError, "failed to write ELF header to output file")

      outFile.setFilePos(int(modifiedHeader.e_phoff))
      let phdrSize = int(modifiedHeader.e_phnum) * sizeof(Elf64_Phdr)
      if outFile.writeBuffer(unsafeAddr modifiedSegments[0], phdrSize) != phdrSize:
        raise newException(
          StripError, "failed to write program header table to output file"
        )

      # Truncate the output file
      let minSize =
        modifiedHeader.e_phoff +
        modifiedHeader.e_phnum.uint64 * modifiedHeader.e_phentsize.uint64
      let finalSize = max(newSize, minSize)
      let truncResult = posix.truncate(targetFile.cstring, Off(finalSize))
      if truncResult != 0:
        let errMsg = osErrorMsg(osLastError())
        raise newException(StripError, fmt"failed to resize output file: {errMsg}")
    else:
      # When modifying the original file
      var origFile = open(filename, fmReadWriteExisting)
      defer:
        close(origFile)

      # Write ELF changes directly to the original file
      writeElfChanges(origFile, modifiedHeader, modifiedSegments, filename, newSize)

    # Calculate stats for display
    let bytesRemoved = uint64(originalSize) - newSize
    let percentRemoved =
      (float(originalSize) - float(newSize)) / float(originalSize) * 100

    # Print colorful success message
    colorPrint("✅ ", ColorGreen)
    colorPrint(filename, ColorBold)
    if options.outputFile.len > 0:
      colorPrint(" → ", ColorWhite)
      colorPrint(targetFile, ColorBold)
    colorPrint(": ", ColorWhite)
    colorPrint(formatSize(uint64(originalSize)), ColorYellow)
    colorPrint(" → ", ColorWhite)
    colorPrint(formatSize(newSize), ColorGreen)
    colorPrint(" ", ColorWhite)
    colorPrint("(−" & $bytesRemoved & " bytes, ", ColorMagenta)
    colorPrintLn(fmt"{percentRemoved:0.2f}%)", ColorMagenta)

    return true
  except StripError, IOError, OSError:
    colorPrint("❌ ", ColorRed)
    colorPrint(programName & ": ", ColorBold)
    colorPrint(filename & ": ", ColorYellow)
    colorPrintLn(getCurrentExceptionMsg(), ColorRed)
    return false

proc parseCommandLine(): Options =
  ## Parse command line options

  var p = initOptParser()
  result.outputFile = ""

  for kind, key, val in p.getopt():
    case kind
    of cmdArgument:
      result.files.add(key)
    of cmdLongOption, cmdShortOption:
      case key
      of "z", "zeros":
        result.stripZeros = true
      of "o", "output":
        if val.len > 0:
          result.outputFile = val
        else:
          # Get the next argument as the output file
          if p.remainingArgs().len > 0:
            p.next() # Move to the next option
            if p.kind == cmdArgument:
              result.outputFile = p.key
          else:
            colorPrintLn("Error: -o/--output option requires a filename", ColorRed)
            quit(QuitFailure)
      of "help":
        echo HelpText
        quit(QuitSuccess)
      of "version":
        echo VersionText
        quit(QuitSuccess)
      else:
        colorPrintLn("Unknown option: " & key, ColorRed)
        colorPrintLn("Try --help for more information.", ColorYellow)
        quit(QuitFailure)
    of cmdEnd:
      discard

  if result.files.len == 0:
    echo HelpText
    quit(QuitSuccess)

  if result.outputFile.len > 0 and result.files.len > 1:
    colorPrintLn(
      "Error: -o/--output option can only be used with a single input file", ColorRed
    )
    quit(QuitFailure)

proc main() =
  ## Main program entry point
  let options = parseCommandLine()
  var
    failures = 0
    successes = 0

  for filename in options.files:
    if stripFile(filename, options):
      inc successes
    else:
      inc failures

  if successes > 0 or failures > 0:
    echo ""
    colorPrint("📊 ", ColorBlue)
    colorPrint("Summary: ", ColorBold)
    colorPrint($successes, ColorGreen)
    colorPrint(" files successfully processed, ", ColorWhite)
    colorPrint($failures, if failures > 0: ColorRed else: ColorWhite)
    colorPrintLn(" failures", ColorWhite)

  quit(if failures > 0: QuitFailure else: QuitSuccess)

when isMainModule:
  main()
