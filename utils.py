import socket


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except Exception as e:
        return "Unknown"


def get_ip_range():
    try:
        # open the dummy connection to get the active network interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))          # Google's DNS (No Data actually sent)
        local_ip = s.getsockname()[0]       # returns a tuple containing local IP and port connected to.

        s.close()
        base_ip = '.'.join(local_ip.split('.')[:-1])
        return f'{base_ip}.0/24'
    except Exception as e:
        print("[!] could not detect local IP Range: ", e)
        return None


def scan_ports(ip, ports=[22, 80, 443, 8080, 3306], logger=None):
    open_ports = []
    for port in ports:
        try:
            if logger:
                logger(f"[*] Scanning {ip}: {port}")
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.settimeout(1)
            result = soc.connect_ex((ip, port))
            if result == 0:
                open_ports.append({
                    'port': port,
                    'service': get_service_name(port)
                })
            soc.close()
        except Exception as e:
            if logger:
                logger(f"[!] Error on port {port}: {e}")

    return open_ports
