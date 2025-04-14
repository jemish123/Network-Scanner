import csv
import json


def save_as_json(data, filename="scan_results.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Results saved to {filename}")


def save_as_csv(data, filename="save_results.csv"):
    with open(filename, "w") as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'MAC', 'Port', 'Service'])
        for device in data:
            for port in device.get('open_ports', []):
                writer.writerow([device['ip'], device.get('mac', ''), port['port'], port['service']])

    print(f"[+] Results saved to {filename}")
