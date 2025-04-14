import tkinter as tk
from tkinter import ttk, messagebox
from utils import get_ip_range, scan_ports
from output import save_as_json, save_as_csv
from scapy.layers.l2 import ARP, Ether
from scapy.all import srp


class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.result = []

        # scan type
        self.scan_type = tk.StringVar(value="local")
        tk.Label(root, text="Scan Type:").grid(row=0, column=0, sticky="w")
        tk.Radiobutton(root, text="Local Network", variable=self.scan_type, value="local", command=self.toggle_input).grid(row=0, column=1, sticky="w")
        tk.Radiobutton(root, text="Public IP", variable=self.scan_type, value="public", command=self.toggle_input).grid(row=0, column=2, sticky="w")

        # Public IP Entry
        tk.Label(root, text="Public IP Address: ").grid(row=1, column=0, sticky="w")
        self.public_ip_entry = tk.Entry(root, width=25, state='disabled')
        self.public_ip_entry.grid(row=1, column=1, columnspan=2, sticky="w")

        # Custom Port Entry
        tk.Label(root, text="Ports (e.g 22,80 or 20-25): ").grid(row=2, column=0, sticky="w", pady=20)
        self.port_entry = tk.Entry(root, width=25)
        self.port_entry.insert(0, "22,80,443")              #default ports
        self.port_entry.grid(row=2, column=1, columnspan=2, sticky="w")

        # Buttons
        tk.Button(root, text="Start Scan", command=self.start_scan).grid(row=4, column=0, pady=10)
        tk.Button(root, text="Export to JSON", command=self.export_json).grid(row=4, column=1)
        tk.Button(root, text="Export to CSV", command=self.export_csv).grid(row=4, column=2)

        # Results Table
        columns = ["IP", "MAC", "Port", "Service"]
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.grid(row=5, column=0, columnspan=3, sticky="nsew")

        self.scroll = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scroll.set)
        self.scroll.grid(row=5, column=3, sticky="ns")

        # Logging Area
        self.logbox = tk.Text(root, height=8, wrap="word")
        self.logbox.grid(row=6, column=0, columnspan=3, sticky="nsew")
        self.logbox.insert("end", "[*] Ready to scan...\n")
        self.logbox.config(state="disabled")

    def log(self, message):
        self.logbox.config(state="normal")
        self.logbox.insert("end", message + "\n")
        self.logbox.see("end")
        self.logbox.config(state="disabled")

    def toggle_input(self):
        if self.scan_type.get() == "public":
            self.public_ip_entry.config(state='normal')
        else:
            self.public_ip_entry.config(state='disabled')

    def start_scan(self):
        print("Scanning Started ...")
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.logbox.config(state="normal")
        self.logbox.delete("1.0", tk.END)
        self.log("[*] Starting scan ...")

        try:
            ports = self.parse_ports()
        except Exception as e:
            messagebox.showerror("Error", "Invalid port number.")
            return

        if self.scan_type.get() == "local":
            ip_range = get_ip_range()
            if not ip_range:
                self.log("[!] Failed to get local IP range.")
                return
            devices = self.scan_local(ip_range, ports)
            self.results = devices
        else:
            ip = self.public_ip_entry.get().strip()
            if not ip:
                messagebox.showerror("Error", "Please enter a valid IP Address.")
                return
            self.log(f"[+] Scanning public IP: {ip}")
            ports = scan_ports(ip, ports, self.log)
            result = {'ip': ip, 'mac': '', 'open_ports': ports}
            self.results = [{'ip': ip, 'mac': '', 'open_ports': ports}]

        for device in self.results:
            for port in device.get('open_ports', []):
                self.tree.insert("", "end", values=(device['ip'], device.get('mac', ''), port['port'], port['service']))

        self.log("[+] Scanning Completed.")

    def scan_local(self, ip_range, ports):
        self.log(f"[*] Performing ARP scan on {ip_range}...")

        # Making ARP scan for local devices
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # returns MAC address
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]

        self.log(f"[+] Found {len(result)} active devices.")

        devices = []
        for sent, received in result:
            ip = received.psrc
            open_ports = scan_ports(ip)
            devices.append({'ip': ip, 'mac': received.hwsrc, 'open_ports': open_ports})

        return devices

    def parse_ports(self):
        port_str = self.port_entry.get()
        ports = []
        parts = port_str.split(',')

        for part in parts:
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end+1)))
            else:
                ports.append(int(part.strip()))

        return sorted(set(ports))

    def export_json(self):
        if self.results:
            print(self.results)
            save_as_json(self.results)
        else:
            messagebox.showinfo("Info", "No scan results to export.")

    def export_csv(self):
        if self.results:
            save_as_csv(self.results)
        else:
            messagebox.showinfo("Info", "No scan results to export.")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()