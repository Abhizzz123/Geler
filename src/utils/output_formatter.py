import os
import json
import csv
from datetime import datetime

def save_results(results, output_format='text', output_dir='scan_results'):
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_results_{timestamp}.{output_format}"

    if output_format == 'json':
        save_json(results, os.path.join(output_dir, filename))
    elif output_format == 'csv':
        save_csv(results, os.path.join(output_dir, filename))
    else:  # default to text
        save_text(results, os.path.join(output_dir, filename))

    print(f"Results saved to {os.path.join(output_dir, filename)}")
    return os.path.join(output_dir, filename)

def save_json(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)

def save_csv(results, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Target', 'IP', 'Open Ports', 'Scanned Ports', 'Thorough'])
        writer.writerow([
            results['target'],
            results['ip'],
            ','.join(map(str, results['open_ports'])),
            results['scanned_ports'],
            results['thorough']
        ])

def save_text(results, filename):
    with open(filename, 'w') as f:
        f.write(f"Scan Results:\n")
        f.write(f"Target: {results['target']} ({results['ip']})\n")
        f.write(f"Open ports: {', '.join(map(str, results['open_ports']))}\n")
        f.write(f"Scanned port range: {results['scanned_ports']}\n")
        f.write(f"Thorough scan: {'Yes' if results['thorough'] else 'No'}\n")
