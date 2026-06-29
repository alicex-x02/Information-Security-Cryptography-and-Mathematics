# 2025-Digital-Forensic
2025 디지털포렌식개론

# FAT32 File Recovery Parser

A simple FAT32 parsing and file recovery project.

## Overview

This project parses a FAT32 disk image and recovers files by reading FAT32 header information, directory entries, cluster locations, and file size metadata.

The program provides a simple GUI for selecting the input file and output directory.

## Files

```text
.
├── FAT_파일_시스템_과제.pdf
├── 파싱프로그램.py
├── dokidoki_parsing.exe
├── README.md
├── 중간_디지털포렌식개론_2조_세션_복호화.pdf
├── 중간_디지털포렌식개론_2조_세션_복호화.pptx
├── 최종_디지털포렌식개론_2조_세션_복호화.pdf
└── 최종_디지털포렌식개론_2조_세션_복호화.pptx
```

## Main Features

- FAT32 header parsing
- Cluster and sector location calculation
- Directory entry parsing
- Long file name parsing
- File recovery based on file size and cluster information
- Simple Tkinter GUI
- Output folder auto-open after recovery

## Tech Stack

- Python
- Tkinter
- FAT32 File System Parsing
- Binary File Processing
- Digital Forensics

## How to Run

### Python Script

```bash
python 파싱프로그램.py
```

### Executable File

```bash
dokidoki_parsing.exe
```

## Usage

1. Run the program.
2. Enter the path of the FAT32 image or target file.
3. Enter the directory path where recovered files will be saved.
4. Click the confirm button.
5. The program parses the FAT32 structure and restores files to the selected directory.

## Notes

- This project was created for a digital forensics assignment.
- The parser focuses on FAT32 structure analysis and simple file recovery.
- Some recovery results may depend on the condition of the FAT32 image.
