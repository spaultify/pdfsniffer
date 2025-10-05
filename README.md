# PDFSniffer 🐕

**Sniffing out PDF threats since 2025**

PDFSniffer is a powerful Python-based PDF security scanner that detects malware, suspicious JavaScript, embedded files, and other security threats in PDF documents.

```
██████╗ ██████╗ ███████╗███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝██║  ██║█████╗  ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
██╔═══╝ ██║  ██║██╔══╝  ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║     ██████╔╝██║     ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚═╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
🐕 Sniffing out PDF threats since 2025
```

## Quick Reference

### Interactive Mode (Easiest)
```bash
python pdfsniffer.py
```

### Command-Line Mode
```bash
# Basic scan
python pdfsniffer.py file.pdf

# Scan directory with export
python pdfsniffer.py ./pdfs/ --export

# Custom export filename
python pdfsniffer.py document.pdf --export report.csv
```

## Features

- **Malware Detection**: Scans for suspicious keywords like JavaScript, Launch actions, embedded files
- **Code Extraction**: Extracts actual JavaScript code, action values, and embedded content
- **Structured Reporting**: Exports detailed JSON-formatted results to CSV
- **Batch Scanning**: Scan entire directories of PDFs at once
- **Risk Assessment**: Automatically categorizes files as HIGH, MEDIUM, LOW, or CLEAN risk
- **Detailed Context**: Shows surrounding code context for each finding

## What It Detects

### Suspicious Keywords
- `/JavaScript` - JavaScript code execution
- `/JS` - Abbreviated JavaScript
- `/AA` - Additional Actions (auto-execute)
- `/OpenAction` - Actions triggered on document open
- `/Launch` - External file/program execution
- `/SubmitForm` - Data submission to external URLs
- `/ImportData` - Data import operations
- `/GoToR`, `/GoToE` - Remote/embedded file actions
- `/RichMedia`, `/Flash` - Multimedia content

### Security Issues
- Embedded files (potential malware containers)
- PDF encryption (may hide malicious content)
- Forms (data collection risk)
- Multiple EOF markers (content appended after legitimate PDF)
- Large file sizes (>50MB)
- PDF structure errors

## Installation

### Requirements
- Python 3.6 or higher
- PyPDF2 library

### Setup
```bash
# Install PyPDF2
pip install PyPDF2

# Download PDFSniffer
# Save pdfsniffer.py to your desired location

# Make it executable (optional, Unix/Mac)
chmod +x pdfsniffer.py
```

## Usage

### Interactive Menu Mode (Recommended)

Simply run PDFSniffer without arguments to enter interactive mode:

```bash
python pdfsniffer.py
```

You'll see a menu with options:
1. Scan a single PDF file
2. Scan a directory (includes subdirectories)
3. Exit

The tool will guide you through:
- Entering file/directory paths
- Viewing scan results
- Exporting to CSV
- Scanning additional files

### Command-Line Mode (Advanced)

**Scan a single PDF:**
```bash
python pdfsniffer.py document.pdf
```

**Scan all PDFs in a directory:**
```bash
python pdfsniffer.py ./my_pdfs/
```

**Scan recursively (includes subdirectories):**
```bash
python pdfsniffer.py ./documents/
```

### Export Results

**Export with auto-generated filename:**
```bash
python pdfsniffer.py ./my_pdfs/ --export
# Creates: pdfsniffer_results_20250105_143052.csv
```

**Export with custom filename:**
```bash
python pdfsniffer.py document.pdf --export my_scan.csv
```

## Understanding the Output

### Console Output
```
⚠️  SECURITY ISSUES FOUND (2):
  ❌ Suspicious keyword found: /JavaScript
     Found 3 occurrence(s):
       [1] Type: string
           Value: app.launchURL("http://malicious-site.com")...
       [2] Type: object_reference
           Value: 5 0 R

⚡ WARNINGS (1):
  ⚠️  PDF is encrypted

ℹ️  INFO:
  • File size: 1,234,567 bytes
  • Pages: 25
  • Creator: Adobe Acrobat
```

### CSV Export Structure

The CSV contains the following columns:

| Column | Description |
|--------|-------------|
| **File Path** | Full path to the scanned PDF |
| **Scan Date** | Timestamp of the scan |
| **Issue Count** | Number of security issues found |
| **Warning Count** | Number of warnings |
| **Issues JSON** | Structured JSON with all issues and extracted code |
| **Warnings JSON** | Structured JSON with all warnings |
| **Info JSON** | Structured JSON with file metadata |
| **Risk Level** | HIGH, MEDIUM, LOW, or CLEAN |

### JSON Structure Example

**Issues JSON:**
```json
[
  {
    "type": "suspicious_keyword",
    "keyword": "/JavaScript",
    "message": "Suspicious keyword found: /JavaScript",
    "count": 3,
    "total_occurrences": 3,
    "extracted_values": [
      {
        "position": 1234,
        "value_type": "string",
        "extracted_value": "app.launchURL('http://evil.com')",
        "context": "...surrounding PDF code...",
        "referenced_object": "...full object if reference..."
      }
    ]
  }
]
```

## Threat Indicators to Look For

### High-Risk JavaScript Functions
- `app.launchURL()` - Opens URLs (phishing)
- `exportDataObject()` - Exports files to disk
- `app.exec()` - Executes system commands
- `eval()` - Code execution
- `submitForm()` - Data exfiltration

### Suspicious Patterns
- `.exe`, `.bat`, `.cmd`, `.ps1` file extensions
- `cmd.exe`, `powershell.exe` references
- Long hex strings (obfuscation)
- `String.fromCharCode()` (hiding malicious strings)
- Non-HTTPS URLs
- IP addresses instead of domains

### Red Flags
- Encoded content (Base64, hex)
- Multiple layers of obfuscation
- `heap spray`, `shellcode` keywords
- Urgent/social engineering language

## Risk Levels Explained

- **HIGH**: Security issues detected (JavaScript, Launch, embedded files)
- **MEDIUM**: Multiple warnings (3+) but no confirmed threats
- **LOW**: Minor warnings (1-2)
- **CLEAN**: No issues or warnings detected

## Best Practices

1. **Always scan PDFs from untrusted sources** before opening
2. **Review extracted JavaScript code** in the CSV for malicious functions
3. **Check URLs** in the extracted values for phishing
4. **Quarantine HIGH risk files** until verified safe
5. **Use PDFSniffer alongside antivirus** for comprehensive protection
6. **Keep PyPDF2 updated** for latest PDF format support

## Important Notes

- PDFSniffer detects **indicators** of threats, not confirmed malware
- Flagged PDFs aren't necessarily malicious (many legitimate PDFs use JavaScript)
- This tool is for **analysis and triage**, not replacement for antivirus
- For suspicious files, use sandbox environments or dedicated malware analysis tools
- Always maintain updated antivirus software

## 🔧 Troubleshooting

### "PyPDF2 not found" error
```bash
pip install PyPDF2
# or
pip3 install PyPDF2
```

### "Permission denied" error
- Check file/folder permissions
- Run with appropriate user privileges
- Ensure PDF files aren't open in another application

### Encrypted PDFs
- PDFniffer can detect encryption but may not analyze encrypted content
- Consider decrypting legitimate PDFs before scanning

### Large batch scans
- For 1000+ PDFs, consider splitting into smaller batches
- Use `--export` to save results periodically
- Or use interactive mode to scan in sessions

## 📈 Example Workflow

### Interactive Mode:
```bash
# Run PDFSniffer
python pdfsniffer.py

# Select option 2 (Scan directory)
# Enter: ./downloads/
# Choose to export: y
# Review results in CSV
```

### Command-Line Mode:
```bash
# 1. Scan a directory
python pdfsniffer.py ./downloads/ --export scan_results.csv

# 2. Open scan_results.csv in Excel/LibreOffice

# 3. Filter by Risk Level = "HIGH"

# 4. Review "Issues JSON" column for extracted code

# 5. Search for keywords like:
#    - launchURL
#    - exec
#    - cmd.exe
#    - eval

# 6. Quarantine suspicious files

# 7. Submit confirmed malware to antivirus vendor
```

## 🤝 Contributing

Suggestions and improvements are welcome! Common enhancements:
- Additional detection patterns
- Support for other file formats
- Integration with VirusTotal API
- Machine learning-based detection
- GUI interface

## 📜 License

This tool is provided as-is for educational and security research purposes.

## 🐕 About the Name

PDFSniffer = PDF + Sniffer. Like a detection dog sniffing out threats, PDFSniffer hunts for malware hiding in your PDF files!

---

**Version:** 0.2.0  
**Last Updated:** 2025  
**Stay Safe! 🛡️**