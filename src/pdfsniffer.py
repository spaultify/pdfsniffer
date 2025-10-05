#!/usr/bin/env python3
"""
PDFSniffer - PDF Security Scanner
Sniffs out malware and security threats in PDF files
Version: 0.2.0
"""

import os
import sys
import re
import csv
import json
from datetime import datetime
from pathlib import Path

try:
    import PyPDF2
except ImportError:
    print("Error: PyPDF2 is required. Install it with: pip install PyPDF2")
    sys.exit(1)


def print_logo():
    """Display PDFSniffer ASCII art logo"""
    logo = r"""
██████╗ ██████╗ ███████╗███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝██║  ██║█████╗  ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
██╔═══╝ ██║  ██║██╔══╝  ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║     ██████╔╝██║     ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚═╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
🐕 Sniffing out PDF threats since 2025
    """
    print(logo)
    print("=" * 70)


class PDFScanner:
    def __init__(self):
        self.suspicious_keywords = [
            b"/JavaScript",
            b"/JS",
            b"/AA",
            b"/OpenAction",
            b"/Launch",
            b"/SubmitForm",
            b"/ImportData",
            b"/GoToR",
            b"/GoToE",
            b"/RichMedia",
            b"/Flash",
        ]

    def extract_keyword_value(self, content, keyword, position):
        """Extract the value/code associated with a suspicious keyword"""
        try:
            # Look for the value after the keyword
            # PDF values can be in parentheses (string), angle brackets (hex), or objects
            snippet = content[position : position + 500]  # Look ahead 500 bytes

            # Try to extract string in parentheses: /Keyword (value)
            paren_match = re.search(rb"\(([^)]{0,400})\)", snippet)
            if paren_match:
                value = paren_match.group(1).decode("latin-1", errors="replace")
                return {"type": "string", "value": value}

            # Try to extract hex string: /Keyword <value>
            hex_match = re.search(rb"<([0-9a-fA-F\s]{0,400})>", snippet)
            if hex_match:
                hex_str = hex_match.group(1).decode("ascii", errors="replace")
                return {"type": "hex_string", "value": hex_str}

            # Try to extract object reference: /Keyword 123 0 R
            ref_match = re.search(rb"(\d+\s+\d+\s+R)", snippet)
            if ref_match:
                ref = ref_match.group(1).decode("ascii", errors="replace")
                return {"type": "object_reference", "value": ref}

            # If nothing specific found, return the raw snippet
            raw = snippet[:200].decode("latin-1", errors="replace")
            return {"type": "raw", "value": raw}

        except Exception as e:
            return {"type": "error", "value": f"Could not extract: {str(e)}"}

    def extract_pdf_object_by_reference(self, content, obj_ref):
        """Extract a PDF object by its reference number (e.g., '5 0 R')"""
        try:
            # Parse the reference
            parts = obj_ref.split()
            if len(parts) >= 2:
                obj_num = parts[0]
                gen_num = parts[1]

                # Look for the object definition
                pattern = (
                    obj_num.encode()
                    + b"\\s+"
                    + gen_num.encode()
                    + b"\\s+obj(.*?)endobj"
                )
                match = re.search(pattern, content, re.DOTALL)

                if match:
                    obj_content = match.group(1).decode("latin-1", errors="replace")
                    # Limit size
                    if len(obj_content) > 1000:
                        obj_content = obj_content[:1000] + "... [truncated]"
                    return obj_content

            return None
        except Exception as e:
            return f"Error extracting object: {str(e)}"

    def get_context_around_keyword(self, content, position, context_size=150):
        """Get text context before and after the keyword position"""
        try:
            start = max(0, position - context_size)
            end = min(len(content), position + context_size)
            context = content[start:end].decode("latin-1", errors="replace")
            # Clean up
            context = context.replace("\x00", "").replace("\r", " ").replace("\n", " ")
            context = " ".join(context.split())
            return context
        except:
            return ""

    def scan_file(self, filepath):
        """Scan a single PDF file for security issues"""
        results = {"file": filepath, "issues": [], "warnings": [], "info": []}

        try:
            # Check file size (very large files can be suspicious)
            file_size = os.path.getsize(filepath)
            results["info"].append(
                {
                    "type": "file_size",
                    "value": file_size,
                    "display": f"File size: {file_size:,} bytes",
                }
            )

            if file_size > 50 * 1024 * 1024:  # 50 MB
                results["warnings"].append(
                    {
                        "type": "large_file",
                        "message": "Large file size (>50MB)",
                        "value": file_size,
                    }
                )

            # Read raw PDF content for keyword scanning
            with open(filepath, "rb") as f:
                raw_content = f.read()

            # Check for suspicious keywords
            for keyword in self.suspicious_keywords:
                positions = []
                start = 0
                # Find all occurrences
                while True:
                    pos = raw_content.find(keyword, start)
                    if pos == -1:
                        break
                    positions.append(pos)
                    start = pos + 1

                if positions:
                    keyword_str = keyword.decode("latin-1")

                    # Extract values for each occurrence (limit to first 5)
                    extracted_values = []
                    for pos in positions[:5]:
                        value_info = self.extract_keyword_value(
                            raw_content, keyword, pos
                        )
                        context = self.get_context_around_keyword(raw_content, pos)

                        extracted_values.append(
                            {
                                "position": pos,
                                "value_type": value_info["type"],
                                "extracted_value": value_info["value"],
                                "context": context,
                            }
                        )

                        # If it's an object reference, try to get the actual object
                        if value_info["type"] == "object_reference":
                            obj_content = self.extract_pdf_object_by_reference(
                                raw_content, value_info["value"]
                            )
                            if obj_content:
                                extracted_values[-1]["referenced_object"] = obj_content

                    results["issues"].append(
                        {
                            "type": "suspicious_keyword",
                            "keyword": keyword_str,
                            "message": f"Suspicious keyword found: {keyword_str}",
                            "count": len(positions),
                            "total_occurrences": len(positions),
                            "extracted_values": extracted_values,
                        }
                    )

            # Use PyPDF2 for structure analysis
            with open(filepath, "rb") as f:
                try:
                    reader = PyPDF2.PdfReader(f)

                    # Check encryption
                    if reader.is_encrypted:
                        results["warnings"].append(
                            {"type": "encryption", "message": "PDF is encrypted"}
                        )

                    # Get metadata
                    metadata = reader.metadata
                    if metadata:
                        page_count = len(reader.pages)
                        results["info"].append(
                            {
                                "type": "page_count",
                                "value": page_count,
                                "display": f"Pages: {page_count}",
                            }
                        )
                        if metadata.creator:
                            results["info"].append(
                                {
                                    "type": "creator",
                                    "value": str(metadata.creator),
                                    "display": f"Creator: {metadata.creator}",
                                }
                            )
                        if metadata.producer:
                            results["info"].append(
                                {
                                    "type": "producer",
                                    "value": str(metadata.producer),
                                    "display": f"Producer: {metadata.producer}",
                                }
                            )

                    # Check for forms
                    if "/AcroForm" in str(reader.trailer.get("/Root", {})):
                        results["warnings"].append(
                            {
                                "type": "forms",
                                "message": "PDF contains forms (potential data collection)",
                            }
                        )

                except PyPDF2.errors.PdfReadError as e:
                    results["issues"].append(
                        {
                            "type": "pdf_read_error",
                            "message": f"PDF structure error: {str(e)}",
                            "error": str(e),
                        }
                    )
                except Exception as e:
                    results["warnings"].append(
                        {
                            "type": "analysis_error",
                            "message": f"Analysis error: {str(e)}",
                            "error": str(e),
                        }
                    )

            # Check for embedded files
            if b"/EmbeddedFile" in raw_content:
                results["issues"].append(
                    {"type": "embedded_files", "message": "PDF contains embedded files"}
                )

            # Check for multiple EOF markers (can indicate malicious content appended)
            eof_count = raw_content.count(b"%%EOF")
            if eof_count > 1:
                results["warnings"].append(
                    {
                        "type": "multiple_eof",
                        "message": f"Multiple EOF markers found ({eof_count})",
                        "count": eof_count,
                    }
                )

        except FileNotFoundError:
            results["issues"].append(
                {"type": "file_not_found", "message": "File not found"}
            )
        except PermissionError:
            results["issues"].append(
                {"type": "permission_denied", "message": "Permission denied"}
            )
        except Exception as e:
            results["issues"].append(
                {
                    "type": "unexpected_error",
                    "message": f"Unexpected error: {str(e)}",
                    "error": str(e),
                }
            )

        return results

    def print_results(self, results):
        """Pretty print scan results"""
        print(f"\n{'='*70}")
        print(f"Scanning: {results['file']}")
        print(f"{'='*70}")

        if results["issues"]:
            print(f"\n⚠️  SECURITY ISSUES FOUND ({len(results['issues'])}):")
            for issue in results["issues"]:
                if isinstance(issue, dict):
                    print(f"  ❌ {issue['message']}")

                    # Show extracted values if available
                    if "extracted_values" in issue and issue["extracted_values"]:
                        print(
                            f"     Found {len(issue['extracted_values'])} occurrence(s):"
                        )
                        for i, val in enumerate(
                            issue["extracted_values"][:2], 1
                        ):  # Show first 2
                            print(f"       [{i}] Type: {val['value_type']}")
                            if val["extracted_value"]:
                                preview = val["extracted_value"][:80]
                                print(f"           Value: {preview}...")
                else:
                    print(f"  ❌ {issue}")

        if results["warnings"]:
            print(f"\n⚡ WARNINGS ({len(results['warnings'])}):")
            for warning in results["warnings"]:
                if isinstance(warning, dict):
                    print(f"  ⚠️  {warning['message']}")
                else:
                    print(f"  ⚠️  {warning}")

        if results["info"]:
            print(f"\nℹ️  INFO:")
            for info in results["info"]:
                if isinstance(info, dict):
                    print(f"  • {info['display']}")
                else:
                    print(f"  • {info}")

        if not results["issues"] and not results["warnings"]:
            print("\n✅ No obvious security issues detected")

        print()

    def scan_directory(self, directory):
        """Scan all PDFs in a directory"""
        pdf_files = list(Path(directory).rglob("*.pdf"))

        if not pdf_files:
            print(f"No PDF files found in {directory}")
            return []

        print(f"Found {len(pdf_files)} PDF file(s) to scan")

        all_results = []
        for pdf_file in pdf_files:
            results = self.scan_file(str(pdf_file))
            self.print_results(results)
            all_results.append(results)

        # Summary
        total_issues = sum(len(r["issues"]) for r in all_results)
        total_warnings = sum(len(r["warnings"]) for r in all_results)

        print(f"\n{'='*70}")
        print("SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"Files scanned: {len(all_results)}")
        print(f"Total issues: {total_issues}")
        print(f"Total warnings: {total_warnings}")
        print()

        return all_results

    def export_to_csv(self, results_list, output_file=None):
        """Export scan results to a CSV file"""
        if not results_list:
            print("No results to export")
            return None

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"pdfniffer_results_{timestamp}.csv"

        try:
            with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
                fieldnames = [
                    "File Path",
                    "Scan Date",
                    "Issue Count",
                    "Warning Count",
                    "Issues JSON",
                    "Warnings JSON",
                    "Info JSON",
                    "Risk Level",
                ]

                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for results in results_list:
                    # Determine risk level
                    issue_count = len(results["issues"])
                    warning_count = len(results["warnings"])

                    if issue_count > 0:
                        risk_level = "HIGH"
                    elif warning_count > 2:
                        risk_level = "MEDIUM"
                    elif warning_count > 0:
                        risk_level = "LOW"
                    else:
                        risk_level = "CLEAN"

                    writer.writerow(
                        {
                            "File Path": results["file"],
                            "Scan Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "Issue Count": issue_count,
                            "Warning Count": warning_count,
                            "Issues JSON": json.dumps(
                                results["issues"], ensure_ascii=False
                            ),
                            "Warnings JSON": json.dumps(
                                results["warnings"], ensure_ascii=False
                            ),
                            "Info JSON": json.dumps(
                                results["info"], ensure_ascii=False
                            ),
                            "Risk Level": risk_level,
                        }
                    )

            print(f"✅ Results exported to: {output_file}")
            return output_file

        except Exception as e:
            print(f"❌ Error exporting to CSV: {str(e)}")
            import traceback

            traceback.print_exc()
            return None


def display_menu():
    """Display the main menu"""
    print("\n" + "=" * 70)
    print("MAIN MENU")
    print("=" * 70)
    print("1. Scan a single PDF file")
    print("2. Scan a directory (includes subdirectories)")
    print("3. Exit")
    print("=" * 70)


def get_user_choice():
    """Get and validate user menu choice"""
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        if choice in ["1", "2", "3"]:
            return choice
        print("❌ Invalid choice. Please enter 1, 2, or 3.")


def get_file_path():
    """Get and validate file path from user"""
    while True:
        path = input("\n📄 Enter the PDF file path: ").strip()
        # Remove quotes if user wrapped path in quotes
        path = path.strip('"').strip("'")

        if os.path.isfile(path):
            if path.lower().endswith(".pdf"):
                return path
            else:
                print("❌ File must be a PDF (.pdf extension)")
        else:
            print("❌ File not found. Please check the path and try again.")
            retry = input("Try again? (y/n): ").strip().lower()
            if retry != "y":
                return None


def get_directory_path():
    """Get and validate directory path from user"""
    while True:
        path = input("\n📁 Enter the directory path: ").strip()
        # Remove quotes if user wrapped path in quotes
        path = path.strip('"').strip("'")

        if os.path.isdir(path):
            return path
        else:
            print("❌ Directory not found. Please check the path and try again.")
            retry = input("Try again? (y/n): ").strip().lower()
            if retry != "y":
                return None


def ask_export():
    """Ask user if they want to export results"""
    while True:
        choice = input("\n💾 Export results to CSV? (y/n): ").strip().lower()
        if choice in ["y", "yes"]:
            filename = input(
                "Enter filename (press Enter for auto-generated): "
            ).strip()
            return True, filename if filename else None
        elif choice in ["n", "no"]:
            return False, None
        else:
            print("❌ Please enter 'y' or 'n'")


def main():
    print_logo()
    scanner = PDFScanner()

    # Check if running with command line arguments (legacy support)
    if len(sys.argv) > 1:
        # Legacy command-line mode
        target = sys.argv[1]

        export_csv = False
        csv_filename = None

        if "--export" in sys.argv:
            export_csv = True
            export_index = sys.argv.index("--export")
            if len(sys.argv) > export_index + 1 and not sys.argv[
                export_index + 1
            ].startswith("--"):
                csv_filename = sys.argv[export_index + 1]

        all_results = []

        if os.path.isfile(target):
            results = scanner.scan_file(target)
            scanner.print_results(results)
            all_results.append(results)
        elif os.path.isdir(target):
            all_results = scanner.scan_directory(target)
        else:
            print(f"Error: '{target}' is not a valid file or directory")
            sys.exit(1)

        if export_csv and all_results:
            scanner.export_to_csv(all_results, csv_filename)

        return

    # Interactive menu mode
    while True:
        display_menu()
        choice = get_user_choice()

        if choice == "3":
            print("\n👋 Thank you for using PDFniffer! Stay safe!")
            print("=" * 70)
            break

        all_results = []

        if choice == "1":
            # Scan single file
            file_path = get_file_path()
            if file_path:
                print(f"\n🔍 Scanning file: {file_path}")
                results = scanner.scan_file(file_path)
                scanner.print_results(results)
                all_results.append(results)

        elif choice == "2":
            # Scan directory
            dir_path = get_directory_path()
            if dir_path:
                print(f"\n🔍 Scanning directory: {dir_path}")
                all_results = scanner.scan_directory(dir_path)

        # Ask about export if we have results
        if all_results:
            export, filename = ask_export()
            if export:
                scanner.export_to_csv(all_results, filename)

        # Ask if user wants to continue
        print("\n" + "=" * 70)
        continue_choice = input("🔄 Scan more files? (y/n): ").strip().lower()
        if continue_choice not in ["y", "yes"]:
            print("\n👋 Thank you for using PDFniffer! Stay safe!")
            print("=" * 70)
            break


if __name__ == "__main__":
    main()
