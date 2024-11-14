import argparse
from cli.arguments import setup_argparse
from core.scanner import run_scan
from utils.output_formatter import save_results
from utils.vulnerability_database import VulnerabilityDatabase
from urllib.parse import urlparse

def main():
    parser = setup_argparse()
    args = parser.parse_args()

    if args.command == 'scan':
        if args.host is None and args.url:
            try:
                parsed_url = urlparse(args.url)
                args.host = parsed_url.hostname  # Extract hostname from URL
            except ValueError:
                print("Error: Invalid URL format.")
                return
        print(f"Scanning target: {args.host}")
        results = run_scan(args.host, args.ports, args.thorough, args.scan_type, args.url)
        if results is None:  # Check if results is None
            print("Scan failed. Exiting.")
            return  # Exit the main function
        if not args.skip_save:
            output_dir = args.output_dir
            save_results(results, args.output, output_dir)

        vulnerability_database = VulnerabilityDatabase()
        open_ports = []
        services = []

        for port_info in results['open_ports']:
            open_ports.append(port_info['port'])
            services.append(port_info['banner'])

        matched_vulnerabilities = vulnerability_database.match_vulnerabilities(open_ports, services)

        # Print vulnerability information (including exploit details)
        if matched_vulnerabilities:
            for vulnerability in matched_vulnerabilities:
                print(f"CVE ID: {vulnerability[0]}")
                print(f"Title: {vulnerability[1]}")
                print(f"URL: {vulnerability[2]}")
                print(f"Path: {vulnerability[3]}")
                print(f"Type: {vulnerability[4]}")
                print(f"Platform: {vulnerability[5]}")
                print(f"Date: {vulnerability[6]}")
                print("-" * 20)  # Separator between vulnerabilities
        else:
            print("No vulnerabilities found.")

    elif args.command == 'suggest':
        vulnerability_database = VulnerabilityDatabase()
        cve_id = args.cve_id

        exploits = vulnerability_database.fetch_exploit_from_exploitdb(cve_id)
        if exploits:
            for exploit in exploits:
                print("Exploit Found:")
                print(f"  Title: {exploit['title']}")
                print(f"  URL: {exploit['url']}")
                print(f"  Path: {exploit['path']}")
                print(f"  Type: {exploit['type']}")
                print(f"  Platform: {exploit['platform']}")
                print(f"  Date: {exploit['date']}")
        else:
            print(f"No exploits found for CVE ID: {cve_id}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()