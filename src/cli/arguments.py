import argparse

def setup_argparse():
    parser = argparse.ArgumentParser(description="AI-Assisted Penetration Testing Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a target for vulnerabilities")
    target_group = scan_parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-H", "--host", help="IP address or hostname to scan")
    target_group.add_argument("-u", "--url", help="URL to scan for web vulnerabilities") 
    scan_parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (e.g., 1-1000, 80,443)")
    scan_parser.add_argument("-T", "--scan-type", choices=['tcp', 'syn', 'udp'], default='tcp', help="Type of scan (tcp, syn, udp)")
    scan_parser.add_argument("--thorough", action="store_true", help="Perform a more thorough scan (may take longer)")
    scan_parser.add_argument("-o", "--output", choices=['text', 'json', 'csv'], default='text', help="Output format")
    scan_parser.add_argument("-O", "--output-dir", default="scan_results", help="Directory to save scan results") 
    scan_parser.add_argument("-S", "--skip-save", action="store_true", help="Do not save output to a file")
    scan_parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase output verbosity")

    # Suggest command
    suggest_parser = subparsers.add_parser("suggest", help="Generate exploitation suggestions")
    suggest_parser.add_argument("cve_id", help="CVE ID to search for exploits")  # Correctly placed here

    return parser  # Return the parser
