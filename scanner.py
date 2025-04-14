from scapy.all import srp
from scapy.layers.l2 import ARP, Ether
from utils import get_ip_range, scan_ports
from output import save_as_csv, save_as_json

import argparse


def scan(ip_range):
    print(f"[+] Scanning {ip_range} ...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")          # returns MAC address
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--public", help="Scan a public IP", type=str)
    args = parser.parse_args()

    results = []
    if args.public:
        print(f"[+] Scanning Public IP: {args.public}")
        ports = scan_ports(args.public)
        for p in ports:
            print(f"  {p['port']}  ({p['service']})")

        results.append({'ip': args.public, 'open_ports': ports})
    else:
        ips = get_ip_range()
        if ips:
            targets = scan(ips)
            for device in targets:
                ports = scan_ports(device['ip'])
                print(f"{device['ip']} - {device['mac']} - Open Ports: {ports}")
                for p in ports:
                    print(f"  {p['port']}  ({p['service']})")
                device['open_ports'] = ports
                results.append(device)
        else:
            print("[!] Ip Range not found. Exiting.")
    if results:
        save_as_json(results)
        save_as_csv(results)