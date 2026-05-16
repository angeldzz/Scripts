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
    81: "HTTP-Alt", 82: "HTTP-Alt", 88: "Kerberos",
    110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMPTRAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog",
    515: "LPD", 548: "AFP", 587: "SMTP", 593: "RPC", 631: "IPP", 636: "LDAPS",
    853: "DNS-over-TLS", 990: "FTPS", 993: "IMAPS", 995: "POP3S", 
    1025: "NFS-or-IIS", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1434: "MSSQL", 1521: "Oracle", 1701: "L2TP", 1720: "H.323", 1723: "PPTP", 
    1883: "MQTT", 2000: "Cisco-SCCP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel", 
    2181: "ZooKeeper", 2222: "SSH-Alt", 3128: "Squid", 32400: "Plex",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4333: "mSQL",
    4444: "Metasploit", 4500: "IPSec", 5000: "UPnP/Flask", 5001: "Synology",
    5060: "SIP", 5061: "SIPS", 5222: "XMPP", 5353: "mDNS",
    5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC", 5901: "VNC-1", 5902: "VNC-2",
    5984: "CouchDB", 6000: "X11", 6379: "Redis", 6667: "IRC", 
    7000: "Cassandra", 7001: "WebLogic", 8000: "HTTP-Alt", 8008: "HTTP",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 
    9000: "SonarQube/Portainer", 9001: "Tor", 9090: "Prometheus/Zeus", 
    9092: "Kafka", 9200: "Elasticsearch", 9443: "Tungsten", 10000: "Webmin", 
    11211: "Memcached", 27017: "MongoDB", 50000: "SAP"
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
        
    local_vendors = {
        "00:50:56": "VMware", "08:00:27": "Oracle VirtualBox",
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
        "B4:F1:DA": "Apple", "F0:9F:C2": "Apple", "8C:85:90": "Apple", "18:AF:61": "Apple",
        "00:25:9C": "Cisco", "00:14:22": "Dell", "00:1A:11": "Google",
        "CC:50:E3": "Samsung", "24:4B:FE": "Samsung",
        "E8:94:F6": "TP-Link", "C0:25:E9": "TP-Link",
        "00:0C:29": "VMware", "00:1C:42": "Parallels", "08:00:20": "Sun",
        "00:1E:06": "Wibrain", "00:24:E4": "Withings", "00:26:B0": "Apple",
        "00:1D:4F": "Apple", "00:1C:B3": "Apple", "00:1B:63": "Apple",
        "E0:CB:4E": "Asustek", "BC:EE:7B": "Asustek", "00:1A:2B": "Ayecka",
        "00:25:82": "Cisco", "00:24:97": "Cisco", "00:1F:CA": "Cisco",
        "00:1D:D8": "Microsoft", "00:15:5D": "Microsoft", "00:50:F2": "Microsoft",
        "00:01:42": "Cisco", "00:0B:86": "Aruba", "00:1A:1E": "Aruba",
        "00:14:BF": "Linksys", "00:16:B6": "Linksys", "00:1E:E3": "Nintendo",
        "00:1F:32": "Nintendo", "00:22:D7": "Nintendo", "00:22:4C": "Sony",
        "00:1D:BA": "Sony", "00:19:C5": "Sony", "00:1F:E1": "Sony",
        "00:24:BE": "Sony", "00:04:4B": "Nvidia", "00:1A:A0": "Dell",
        "00:1D:09": "Dell", "00:21:70": "Dell", "00:22:19": "Dell",
        "00:23:5A": "Dell", "00:24:E8": "Dell", "00:25:64": "Dell",
        "00:1A:79": "HUAWEI", "00:1E:10": "HUAWEI", "00:22:A1": "HUAWEI",
        "00:25:68": "HUAWEI", "00:25:9E": "HUAWEI"
    }
    
    vendor = local_vendors.get(oui)
    
    if not vendor:
        try:
            url = f"https://api.macvendors.com/{mac}"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            # Se usa un retraso ligero para evitar el error 429 Too Many Requests
            time.sleep(0.5)
            with urllib.request.urlopen(req, timeout=1.5, context=ctx) as response:
                vendor = response.read().decode('utf-8')
        except:
            pass
            
    if not vendor:
        first_byte = int(mac.split(':')[0], 16)
        if first_byte & 2:
            vendor = "MAC Privada/Aleatoria"
        else:
            vendor = "Desconocido"
            
    mac_vendor_cache[oui] = vendor
    return vendor

def discover_hosts(subnets):
    active_hosts = {}
    
    for subnet in subnets:
        print(f"{C.YELLOW}[*] Escaneando subred {subnet} (Sweep ICMP y TCP para forzar ARP)...{C.RESET}")
        try:
            ip_base, cidr = subnet.split('/')
            parts = ip_base.split('.')
            base_ip = f"{parts[0]}.{parts[1]}.{parts[2]}."
            
            ips_to_scan = [f"{base_ip}{i}" for i in range(1, 255)]
            
            def check_host(ip):
                ttl = None
                is_active = False
                
                # 1. Ping
                try:
                    result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=1.5)
                    # Comprobación estricta de TTL para evitar falsos positivos "Destination Unreachable"
                    match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
                    if match:
                        ttl = int(match.group(1))
                        is_active = True
                except:
                    pass
                    
                # 2. Forzar petición ARP vía TCP para dispositivos que bloquean ICMP
                if not is_active:
                    for port in [80, 445, 139, 443]:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(0.3)
                            res = s.connect_ex((ip, port))
                            s.close()
                            if res == 0:
                                is_active = True
                                break
                        except:
                            pass
                            
                return ip, is_active, ttl

            with concurrent.futures.ThreadPoolExecutor(max_workers=150) as executor:
                results = executor.map(check_host, ips_to_scan)
                
            for ip, is_active, ttl in results:
                if is_active:
                    active_hosts[ip] = {'ttl': ttl, 'mac': None, 'vendor': None}
                    
        except Exception as e:
            pass

    # Recolectar MACs usando 3 métodos distintos porque en iSH las tablas ARP varían
    arp_macs = {}
    
    # Método 1
    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3].lower()
                    if mac != '00:00:00:00:00:00' and ':' in mac:
                        arp_macs[ip] = mac
    except:
        pass
        
    # Método 2
    if not arp_macs:
        try:
            out = subprocess.getoutput("ip neigh show")
            for line in out.split('\n'):
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    idx = parts.index("lladdr")
                    mac = parts[idx+1].lower()
                    if ':' in mac and mac != '00:00:00:00:00:00':
                        arp_macs[ip] = mac
        except:
            pass

    # Método 3
    if not arp_macs:
        try:
            out = subprocess.getoutput("arp -a")
            for line in out.split('\n'):
                ip_match = re.search(r'\(([\d\.]+)\)', line)
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(0).lower().replace('-', ':')
                    if mac != '00:00:00:00:00:00' and mac != 'ff:ff:ff:ff:ff:ff':
                        arp_macs[ip] = mac
        except:
            pass

    for ip, mac in arp_macs.items():
        if ip not in active_hosts:
            active_hosts[ip] = {'ttl': None, 'mac': mac, 'vendor': None}
        else:
            active_hosts[ip]['mac'] = mac
        
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
        s.settimeout(1.5)
        s.connect((ip, port))
        
        is_http = False
        if port in [80, 8080, 8000, 8888, 5000, 8443, 443]:
            if port in [443, 8443]:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=ip)
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            is_http = True
        else:
            s.sendall(b"\r\n")
            
        data = s.recv(2048)
        s.close()
        
        if data:
            decoded = data.decode('utf-8', errors='ignore')
            
            if is_http or decoded.startswith('HTTP/'):
                headers_part = decoded.split('\r\n\r\n')[0]
                lines = headers_part.split('\r\n')
                
                status_line = lines[0].strip()
                server = ""
                for h in lines:
                    if h.lower().startswith('server:'):
                        server = h.split(':', 1)[1].strip()
                        break
                        
                title = ""
                title_match = re.search(r'<title>(.*?)</title>', decoded, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip().replace('\n', ' ')
                    
                info_parts = []
                if status_line: info_parts.append(status_line[:40])
                if server: info_parts.append(f"Servidor: {server}")
                if title: info_parts.append(f"Sitio: '{title[:45]}'")
                
                return " | ".join(info_parts)
            else:
                text = decoded.split('\n')[0].strip()
                text = "".join(c for c in text if c.isprintable())
                return text[:80]
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