# PDF Security Scanner

## NOTE: 🚧 Still under development 🚧

A Python-based security tool for analyzing PDF files and detecting potential security issues, malicious content, and suspicious elements.

## Features

- Detection of suspicious keywords and malicious code patterns
- Analysis of PDF structure and embedded content
- Identification of JavaScript, forms, and embedded files
- Context extraction around suspicious elements
- Support for both single file and directory scanning
- Detailed CSV report generation
- Multiple security checks including:
  - Multiple EOF markers
  - Encryption status
  - Large file detection
  - Form elements
  - Embedded files
  - Metadata analysis

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd static_pdf_scanner
```

2. Install required dependencies:
```bash
uv sync
```

## Usage

### Scan a Single PDF File
```bash
python src/scanner.py document.pdf
```

### Scan an Entire Directory
```bash
python src/scanner.py ./pdfs/
```

### Export Results to CSV
```bash
python src/scanner.py document.pdf --export results.csv
```

## Output

The scanner generates two types of outputs:
1. Console output with real-time scan results
2. CSV reports (when using --export):
   - Main results file (scan_results.csv)
   - Detailed findings file (scan_details.csv)

## Risk Levels

The scanner classifies findings into four risk levels:
- HIGH: Active security issues detected
- MEDIUM: Multiple warnings detected
- LOW: Minor warnings detected
- CLEAN: No issues detected

## Requirements

- Python 3.6+
- PyPDF2 library

## License

[Add your license information here]
