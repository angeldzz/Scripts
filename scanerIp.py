import subprocess
import re
import socket
import sys
import time
import concurrent.futures
import urllib.request
import urllib.error
import ssl

# --- Colores y Estilos ANSI ---
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def print_banner():
    banner = f"""
{C.CYAN}{C.BOLD}╔═══════════════════════════════════════════════════════════════╗
║ 📡  DETECTIVE DE RED CLI - ESCÁNER NATIVO ULTRARRÁPIDO       ║
╚═══════════════════════════════════════════════════════════════╝{C.RESET}
    """
    print(banner)

# Puertos más comunes para escanear
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMPTRAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog",
    515: "LPD", 548: "AFP", 587: "SMTP", 631: "IPP", 853: "DNS-over-TLS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1434: "MSSQL", 1521: "Oracle", 1701: "L2TP", 1723: "PPTP", 1883: "MQTT",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel", 2181: "ZooKeeper", 2222: "SSH-Alt",
    3128: "Squid", 3306: "MySQL", 3389: "RDP", 3690: "SVN", 4333: "mSQL",
    4444: "Metasploit", 4500: "IPSec", 5000: "UPnP/Flask", 5060: "SIP", 5353: "mDNS",
    5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB", 6000: "X11",
    6379: "Redis", 6667: "IRC", 7000: "Cassandra", 8000: "HTTP-Alt", 8008: "HTTP",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "SonarQube",
    9090: "Prometheus", 9092: "Kafka", 9200: "Elasticsearch", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 50000: "SAP"
}

def get_local_subnets():
    subnets = set()
    print(f"{C.YELLOW}[*] Detectando interfaces de red...{C.RESET}")
    
    try:
        output = subprocess.getoutput("ip -4 route")
        for line in output.split('\n'):
            if 'dev' in line and 'default' not in line:
                match = re.search(r'^([0-9\.]+/[0-9]+)\s+dev', line)
                if match:
                    subnets.add(match.group(1))
    except Exception:
        pass
    
    if not subnets:
        try:
            output = subprocess.getoutput("ifconfig")
            lines = output.split('\n')
            for line in lines:
                if 'inet ' in line and '127.0.0.1' not in line:
                    ip_match = re.search(r'inet (?:addr:)?([0-9\.]+)', line)
                    mask_match = re.search(r'(?:Mask:|netmask )([0-9\.]+)', line)
                    if ip_match and mask_match:
                        ip = ip_match.group(1)
                        mask = mask_match.group(1)
                        try:
                            cidr = sum([bin(int(x)).count('1') for x in mask.split('.')])
                            parts = ip.split('.')
                            if 0 < cidr <= 32:
                                if cidr >= 24:
                                    subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/{cidr}")
                                elif cidr >= 16:
                                    subnets.add(f"{parts[0]}.{parts[1]}.0.0/{cidr}")
                                else:
                                    subnets.add(f"{ip}/{cidr}")
                        except Exception:
                            pass
        except Exception:
            pass

    if not subnets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            parts = ip.split('.')
            subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
        except Exception:
            subnets.add("192.168.1.0/24")
            
    return list(subnets)

def guess_os(ttl):
    if not ttl:
        return "Desconocido"
    ttl = int(ttl)
    if ttl <= 64:
        return "Linux / macOS / iOS / Android"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 254:
        return "Dispositivo de Red (Router/Switch/IoT)"
    return "Desconocido"

mac_vendor_cache = {}
def get_mac_vendor(mac):
    if not mac or mac == "00:00:00:00:00:00":
        return "N/A"
    oui = mac[:8].upper()
    if oui in mac_vendor_cache:
        return mac_vendor_cache[oui]
        
    try:
        url = f"https://api.macvendors.com/{mac}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.5, context=ctx) as response:
            vendor = response.read().decode('utf-8')
            mac_vendor_cache[oui] = vendor
            return vendor
    except:
        pass
        
    local_vendors = {
        "00:50:56": "VMware", "08:00:27": "Oracle VirtualBox",
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
        "B4:F1:DA": "Apple", "F0:9F:C2": "Apple", "8C:85:90": "Apple", "18:AF:61": "Apple",
        "00:25:9C": "Cisco", "00:14:22": "Dell", "00:1A:11": "Google",
        "CC:50:E3": "Samsung", "24:4B:FE": "Samsung",
        "E8:94:F6": "TP-Link", "C0:25:E9": "TP-Link",
    }
    
    first_byte = int(mac.split(':')[0], 16)
    if first_byte & 2:
        vendor = "MAC Privada/Aleatoria"
    else:
        vendor = local_vendors.get(oui, "Desconocido")
        
    mac_vendor_cache[oui] = vendor
    return vendor

def ping_and_get_info(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=1.5)
        if result.returncode == 0:
            match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
            ttl = int(match.group(1)) if match else None
            return ip, True, ttl
    except:
        pass
    return ip, False, None

def discover_hosts(subnets):
    active_hosts = {}
    
    for subnet in subnets:
        print(f"{C.YELLOW}[*] Escaneando subred {subnet} (Sweep ICMP/ARP)...{C.RESET}")
        try:
            ip_base, cidr = subnet.split('/')
            parts = ip_base.split('.')
            base_ip = f"{parts[0]}.{parts[1]}.{parts[2]}."
            
            ips_to_ping = [f"{base_ip}{i}" for i in range(1, 255)]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                results = executor.map(ping_and_get_info, ips_to_ping)
                
            for ip, is_active, ttl in results:
                if is_active:
                    active_hosts[ip] = {'ttl': ttl, 'mac': None, 'vendor': None}
                    
        except Exception as e:
            pass

    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3]
                    if mac != '00:00:00:00:00:00':
                        if ip not in active_hosts:
                            active_hosts[ip] = {'ttl': None, 'mac': mac, 'vendor': None}
                        else:
                            active_hosts[ip]['mac'] = mac
    except:
        pass
        
    for ip, info in active_hosts.items():
        if info['mac']:
            info['vendor'] = get_mac_vendor(info['mac'])
        info['os'] = guess_os(info['ttl'])

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self_ip = s.getsockname()[0]
        s.close()
        if self_ip not in active_hosts:
            active_hosts[self_ip] = {'ttl': 64, 'mac': None, 'vendor': 'Self', 'os': 'Local'}
    except:
        pass
        
    return active_hosts

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        
        if port in [80, 8080, 443, 8443, 8000, 8888, 5000]:
            if port in [443, 8443]:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=ip)
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            s.sendall(b"\r\n")
            
        data = s.recv(1024)
        s.close()
        
        if data:
            try:
                decoded = data.decode('utf-8', errors='ignore').strip()
            except:
                decoded = str(data[:50])
                
            text = decoded.split('\r\n')[0].strip()
            
            if text.startswith('HTTP/'):
                headers = decoded.split('\r\n')
                server = ""
                for h in headers:
                    if h.lower().startswith('server:'):
                        server = h.split(':', 1)[1].strip()
                        break
                if server:
                    return f"{text} | Server: {server}"
            return text[:60]
    except:
        pass
    return ""

def scan_single_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            banner = grab_banner(ip, port)
            return port, banner
    except:
        pass
    return None

def scan_host_ports(ip):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_single_port, ip, port): port for port in COMMON_PORTS.keys()}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
    return sorted(open_ports, key=lambda x: x[0])

def display_results(active_hosts, elapsed):
    print(f"{C.GREEN}{C.BOLD}✅ Auditoría finalizada en {elapsed:.1f} segundos.{C.RESET}\n")
    
    if not active_hosts:
        print(f"{C.YELLOW}No se detectaron dispositivos en la red.{C.RESET}")
        return
        
    for ip, info in sorted(active_hosts.items(), key=lambda x: tuple(map(int, x[0].split('.')))):
        mac_str = info.get('mac') or "Desconocida"
        vendor_str = info.get('vendor') or "Desconocido"
        os_str = info.get('os') or "Desconocido"
        
        print(f"{C.CYAN}🖥️  Dispositivo: {C.BOLD}{ip}{C.RESET}")
        print(f"    {C.DIM}├─ MAC:{C.RESET} {mac_str} ({vendor_str})")
        print(f"    {C.DIM}├─ SO Estimado:{C.RESET} {os_str}")
        
        open_ports = info.get('ports', [])
        if open_ports:
            print(f"    {C.GREEN}└─ Puertos Abiertos ({len(open_ports)}):{C.RESET}")
            for i, (port, banner) in enumerate(open_ports):
                branch = "   └─" if i == len(open_ports) - 1 else "   ├─"
                svc = COMMON_PORTS.get(port, "desconocido")
                
                banner_clean = ""
                if banner:
                    banner_clean = banner.replace('\n', ' ').replace('\r', '')
                    banner_str = f" {C.DIM}[{banner_clean}]{C.RESET}"
                else:
                    banner_str = ""
                    
                print(f"    {C.GREEN}{branch}{C.RESET} Puerto {C.BOLD}{port}{C.RESET} ({svc}){banner_str}")
        else:
            print(f"    {C.DIM}└─ 🔴 0 puertos abiertos o bloqueados por Firewall.{C.RESET}")
        print()

def main():
    print_banner()
    subnets = get_local_subnets()
    
    if not subnets:
        print(f"{C.RED}No se pudo determinar la subred local.{C.RESET}")
        sys.exit(1)
        
    active_hosts = discover_hosts(subnets)
    
    if active_hosts:
        print(f"\n{C.BLUE}[*] Iniciando escaneo de puertos y extracción de banners nativo...{C.RESET}")
        print(f"{C.DIM}⏳ Esto será rápido al ejecutarse multihilo en Python puro.{C.RESET}\n")
        
        start_time = time.time()
        for ip in active_hosts.keys():
            active_hosts[ip]['ports'] = scan_host_ports(ip)
        elapsed = time.time() - start_time
        
        display_results(active_hosts, elapsed)
    else:
        print(f"{C.YELLOW}No se detectaron hosts activos en la red.{C.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Escaneo cancelado por el usuario.{C.RESET}")
        sys.exit(0)