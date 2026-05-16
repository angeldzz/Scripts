import subprocess
import re
import socket
import sys
import time
import concurrent.futures
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET

# --- Colores y Estilos ANSI ---
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

COMMON_MAC_VENDORS = {
    "00:1E:C2": "Apple", "00:1F:5B": "Apple", "18:AF:61": "Apple", "2C:F0:EE": "Apple", "F8:FF:C2": "Apple",
    "00:24:D7": "Samsung", "00:15:99": "Samsung",
    "00:1E:10": "Huawei", "28:6C:07": "Huawei",
    "00:04:4B": "Nvidia", "00:09:BF": "Nintendo",
    "00:1D:BD": "Sony", "00:1E:45": "Sony",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "00:1A:11": "Google", "E4:F0:42": "Google",
    "00:22:61": "Motorola", "00:17:88": "Philips",
    "00:1A:22": "Cisco", "00:14:22": "Dell", "00:26:B9": "Dell",
    "00:1A:4B": "HP", "00:10:83": "HP", "00:1E:68": "Intel"
}

def print_banner():
    banner = f"""
{C.CYAN}{C.BOLD}╔═══════════════════════════════════════════════════════════════╗
║ 📡  DETECTIVE DE RED CLI - ESCÁNER INTELIGENTE E IDENTIFICADOR║
╚═══════════════════════════════════════════════════════════════╝{C.RESET}
    """
    print(banner)

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
                            cidr = sum([bin(int(x)).count('1') for x in mask.split('.') if x.isdigit()])
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

def populate_arp_and_get_ips(subnet):
    print(f"{C.YELLOW}[*] Despertando dispositivos en {subnet} (Sweep ARP)...{C.RESET}")
    arp_table = {}
    
    try:
        ip_base, cidr = subnet.split('/')
        parts = ip_base.split('.')
        base_ip = f"{parts[0]}.{parts[1]}.{parts[2]}."
        
        ips_to_ping = [f"{base_ip}{i}" for i in range(1, 255)]
        
        def ping_ip(target_ip):
            subprocess.run(["ping", "-c", "1", "-W", "1", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(ping_ip, ips_to_ping)
    except Exception:
        pass
        
    # Extraer ARP
    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3]
                    if mac != '00:00:00:00:00:00':
                        arp_table[ip] = mac
    except Exception:
        pass
        
    try:
        arp_output = subprocess.getoutput("arp -a")
        for line in arp_output.split('\n'):
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
            if ip_match:
                ip = ip_match.group(0)
                if not ip.endswith('.255') and ip != '127.0.0.1':
                    mac = mac_match.group(0).replace('-', ':') if mac_match else "Desconocida"
                    if ip not in arp_table or arp_table[ip] == "Desconocida":
                        arp_table[ip] = mac
    except Exception:
        pass
            
    # IP local
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        own_ip = s.getsockname()[0]
        s.close()
        if own_ip not in arp_table:
            arp_table[own_ip] = "Dispositivo Local"
    except Exception:
        pass
        
    return arp_table

def run_nmap_scan(targets):
    targets_str = " ".join(targets)
    if len(targets_str) > 70:
        targets_str = targets_str[:70] + f"... ({len(targets)} activos)"
        
    print(f"{C.BLUE}[*] Forzando escaneo profundo en:{C.RESET} {C.BOLD}{targets_str}{C.RESET}")
    print(f"{C.DIM}⏳ Identificando servicios y versiones (Nmap)... esto puede tardar unos minutos.{C.RESET}\n")
    
    # -sT: Connect scan (compatible con iSH sin raw sockets)
    # -sV: Identificación de versiones de servicios
    # --version-light: Rapidez en la identificación
    # -F: Top 100 puertos (suficiente para heurísticas)
    cmd = ["nmap", "--unprivileged", "-T4", "-F", "-Pn", "-sT", "-sV", "--version-light", "-oX", "-"] + targets
    
    try:
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        elapsed = time.time() - start_time
        return result.stdout, elapsed
        
    except FileNotFoundError:
        print(f"{C.RED}[!] ERROR: Nmap no instalado. Usa: apk add nmap{C.RESET}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"{C.RED}[!] ERROR: Tiempo de espera agotado (10 minutos).{C.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{C.RED}[!] Error inesperado:{C.RESET} {e}")
        sys.exit(1)

def parse_nmap_xml(xml_string, arp_table):
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return {}

    hosts_info = {}
    for host in root.findall('host'):
        status = host.find('status')
        if status is not None and status.get('state') != 'up':
            continue
            
        ip = ""
        for addr in host.findall('address'):
            if addr.get('addrtype') == 'ipv4':
                ip = addr.get('addr')
                
        if not ip: continue
        
        mac = arp_table.get(ip, "Desconocida")
        
        hostname = ""
        hostnames = host.find('hostnames')
        if hostnames is not None:
            hn = hostnames.find('hostname')
            if hn is not None:
                hostname = hn.get('name')
                
        ports = []
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    service_elem = port.find('service')
                    service_name = service_elem.get('name') if service_elem is not None else "unknown"
                    service_product = service_elem.get('product') if service_elem is not None else ""
                    service_version = service_elem.get('version') if service_elem is not None else ""
                    extrainfo = service_elem.get('extrainfo') if service_elem is not None else ""
                    
                    version_info = service_product
                    if service_version: version_info += f" {service_version}"
                    if extrainfo: version_info += f" ({extrainfo})"
                    
                    ports.append({
                        'port_id': port_id,
                        'protocol': protocol,
                        'service': service_name,
                        'version': version_info.strip()
                    })
                    
        hosts_info[ip] = {
            'mac': mac,
            'hostname': hostname,
            'ports': ports
        }
        
    return hosts_info

def get_mac_vendor(mac):
    if not mac or mac == "Desconocida" or mac == "Dispositivo Local":
        return "Desconocido"
    try:
        url = f"https://api.macvendors.com/{urllib.parse.quote(mac)}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.read().decode('utf-8').strip()
    except Exception:
        return "Desconocido"

def get_device_type(info, vendor):
    ports = info['ports']
    hostname = info.get('hostname', '').lower()
    vendor_lower = vendor.lower()
    port_list = [p['port_id'] for p in ports]
    services = [p['service'].lower() for p in ports]
    
    # 1. Por Hostname
    if 'iphone' in hostname or 'ipad' in hostname: return "📱 iPhone / iPad (iOS)"
    if 'macbook' in hostname or 'imac' in hostname or 'mac-mini' in hostname: return "💻 Mac (macOS)"
    if 'desktop' in hostname or 'laptop' in hostname: return "🪟 PC Windows"
    if 'android' in hostname or 'galaxy' in hostname or 'pixel' in hostname: return "📱 Smartphone Android"
    if 'tv' in hostname: return "📺 Smart TV"
    if 'hp' in hostname and 'print' in hostname: return "🖨️ Impresora"

    # 2. Por Fabricante (MAC) + Puertos
    if "apple" in vendor_lower:
        if '62078' in port_list: return "📱 iPhone / iPad (iOS)"
        if '5000' in port_list or '7000' in port_list: return "📺 Apple TV / AirPlay"
        if '22' in port_list or '548' in port_list or '5900' in port_list: return "💻 Mac (macOS)"
        return "🍏 Dispositivo Apple"
        
    # 3. Impresoras
    if '631' in port_list or '9100' in port_list or '515' in port_list or 'ipp' in services or 'printer' in services:
        return "🖨️ Impresora de Red"
        
    # 4. Routers / Gateways
    if '53' in port_list and ('80' in port_list or '443' in port_list):
        return "🌐 Router / Gateway / Firewall"
        
    # 5. Windows
    if '445' in port_list or '139' in port_list or '3389' in port_list:
        return "🪟 PC / Servidor Windows"
        
    # 6. Servidores Linux / RPi
    if '22' in port_list and len(port_list) <= 5:
        return "🐧 Servidor Linux / Raspberry Pi"
        
    # 7. Cámaras de Seguridad
    if '554' in port_list or '3702' in port_list or 'rtsp' in services:
        return "📷 Cámara IP / Vigilancia"
        
    # 8. Smart TV / Cast
    if '8009' in port_list or '8008' in port_list:
        return "📺 Chromecast / Dispositivo Cast"
    if "samsung" in vendor_lower or "lg" in vendor_lower or "sony" in vendor_lower or "nintendo" in vendor_lower:
        return "📺 Smart TV / Consola / Multimedia"
        
    # 9. Smartphones Genéricos
    if "xiaomi" in vendor_lower or "huawei" in vendor_lower or "motorola" in vendor_lower:
        return "📱 Smartphone Android"
        
    # 10. Fallback
    if not ports:
        return "👻 Dispositivo Oculto (Solo responde a ping/ARP)"

    return "🖥️ Dispositivo Desconocido"

def main():
    print_banner()
    subnets = get_local_subnets()
    
    if not subnets:
        print(f"{C.RED}No se pudo determinar la subred local.{C.RESET}")
        sys.exit(1)
        
    all_targets = {}
    for subnet in subnets:
        arp_data = populate_arp_and_get_ips(subnet)
        all_targets.update(arp_data)
        
    if not all_targets:
        targets = subnets
    else:
        targets = list(all_targets.keys())
        
    xml_data, elapsed = run_nmap_scan(targets)
    
    print(f"{C.DIM}🔍 Analizando datos y consultando fabricantes...{C.RESET}")
    hosts_info = parse_nmap_xml(xml_data, all_targets)
    
    # Consultar MAC vendors
    mac_cache = {}
    for ip, info in hosts_info.items():
        mac = info.get('mac', 'Desconocida')
        if mac and mac != 'Desconocida' and mac != 'Dispositivo Local':
            if mac not in mac_cache:
                mac_prefix = mac.upper()[:8]
                if mac_prefix in COMMON_MAC_VENDORS:
                    mac_cache[mac] = COMMON_MAC_VENDORS[mac_prefix]
                else:
                    vendor = get_mac_vendor(mac)
                    mac_cache[mac] = vendor
                    if vendor != "Desconocido":
                        time.sleep(1) # Prevenir ban de API
            info['vendor'] = mac_cache[mac]
        else:
            info['vendor'] = 'Desconocido'
            
    print(f"{C.GREEN}{C.BOLD}✅ Auditoría finalizada en {elapsed:.1f} segundos.{C.RESET}\n")
    
    if not hosts_info:
        print(f"{C.YELLOW}No se detectaron hosts activos.{C.RESET}")
        return
        
    for ip, info in sorted(hosts_info.items(), key=lambda x: tuple(map(int, x[0].split('.')))):
        hostname_str = f" ({info['hostname']})" if info['hostname'] else ""
        device_type = get_device_type(info, info['vendor'])
        mac_str = info['mac']
        vendor_str = f" [{info['vendor']}]" if info['vendor'] != "Desconocido" else ""
        
        print(f"{C.CYAN}📍 {C.BOLD}{ip}{C.RESET}{C.YELLOW}{hostname_str}{C.RESET}")
        print(f"    {C.DIM}├─ MAC:{C.RESET} {mac_str}{C.MAGENTA}{vendor_str}{C.RESET}")
        print(f"    {C.DIM}├─ Tipo:{C.RESET} {C.BOLD}{device_type}{C.RESET}")
        
        open_ports = info['ports']
        if open_ports:
            print(f"    {C.GREEN}└─ Puertos Abiertos ({len(open_ports)}):{C.RESET}")
            for i, p in enumerate(open_ports):
                branch = "   └─" if i == len(open_ports) - 1 else "   ├─"
                svc = p['service'] if p['service'] else "desconocido"
                ver = f" ({p['version']})" if p['version'] else ""
                print(f"    {C.DIM}{branch}{C.RESET} [{p['port_id']}/{p['protocol']}] {C.BOLD}{svc}{C.RESET}{C.DIM}{ver}{C.RESET}")
        else:
            print(f"    {C.DIM}└─ 🔴 0 puertos abiertos (Firewall activo).{C.RESET}")
        print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Escaneo cancelado por el usuario.{C.RESET}")
        sys.exit(0)