import json
import csv

def export_results(findings, export_path, export_format):
    if export_format == 'json':
        with open(export_path, 'w') as f:
            json.dump(findings, f, indent=2)
    elif export_format == 'csv':
        with open(export_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Severity', 'Description'])
            for ftype, items in findings.items():
                for item in items:
                    writer.writerow([ftype, item.get('severity', ''), item['desc']])
    print(f"[+] Results exported to {export_path}")
