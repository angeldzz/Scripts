import subprocess
import re
import socket
import sys
import time
import concurrent.futures

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
║ 📡  DETECTIVE DE RED CLI - ESCÁNER MULTI-RANGO ACTIVO        ║
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

def populate_arp_and_get_ips(subnet):
    print(f"{C.YELLOW}[*] Despertando dispositivos ocultos en {subnet} (Sweep ARP)...{C.RESET}")
    active_ips = set()
    
    try:
        ip_base, cidr = subnet.split('/')
        parts = ip_base.split('.')
        base_ip = f"{parts[0]}.{parts[1]}.{parts[2]}."
        
        # Intentaremos despertar a las primeras 254 IPs en milisegundos
        ips_to_ping = [f"{base_ip}{i}" for i in range(1, 255)]
        
        def ping_ip(target_ip):
            subprocess.run(["ping", "-c", "1", "-W", "1", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        # Pings concurrentes masivos (tardará 1-2 segundos)
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(ping_ip, ips_to_ping)
    except Exception:
        pass
        
    # Extraer los que respondieron o dejaron rastro en el Caché ARP del sistema
    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3]
                    if mac != '00:00:00:00:00:00':
                        active_ips.add(ip)
    except Exception:
        pass
        
    if not active_ips:
        try:
            arp_output = subprocess.getoutput("arp -a")
            for line in arp_output.split('\n'):
                match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if match:
                    ip = match.group(0)
                    if not ip.endswith('.255') and ip != '127.0.0.1':
                        active_ips.add(ip)
        except Exception:
            pass
            
    # Añadir siempre la IP propia
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        active_ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
        
    return list(active_ips)

def run_nmap_scan(targets):
    targets_str = " ".join(targets)
    if len(targets_str) > 70:
        targets_str = targets_str[:70] + f"... ({len(targets)} activos)"
        
    print(f"{C.BLUE}[*] Forzando escaneo profundo en:{C.RESET} {C.BOLD}{targets_str}{C.RESET}")
    print(f"{C.DIM}⏳ Extrayendo puertos (Nmap directo)... esto puede tardar un momento.{C.RESET}\n")
    
    # -Pn es la clave mágica aquí: le dice a nmap que NO descarte ninguna de las IPs, 
    # ya que le hemos confirmado mediante ARP que sí existen físicamente en el router.
    cmd = ["nmap", "--unprivileged", "-T4", "-F", "-Pn", "-oG", "-"] + targets
    
    try:
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        elapsed = time.time() - start_time
        
        output = result.stdout.decode('utf-8', errors='ignore')
        return output, elapsed
        
    except FileNotFoundError:
        print(f"{C.RED}[!] ERROR: Nmap no instalado. Usa: apk add nmap{C.RESET}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"{C.RED}[!] ERROR: Tiempo de espera agotado (5 minutos).{C.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{C.RED}[!] Error inesperado:{C.RESET} {e}")
        sys.exit(1)

def parse_and_display(output, elapsed):
    lines = output.split('\n')
    hosts_info = {}
    
    for line in lines:
        if line.startswith('Host: '):
            parts = line.split('\t')
            if not parts:
                continue
                
            host_part = parts[0]
            host_match = re.search(r'Host: ([0-9\.]+)\s*(?:\(([^)]*)\))?', host_part)
            if not host_match:
                continue
                
            ip = host_match.group(1)
            hostname = host_match.group(2) if host_match.group(2) else ""
            
            if ip not in hosts_info:
                hosts_info[ip] = {'hostname': hostname, 'ports': []}
                
            for part in parts[1:]:
                if part.startswith('Ports: '):
                    ports_str = part[len('Ports: '):]
                    port_entries = ports_str.split(',')
                    for pe in port_entries:
                        pe = pe.strip()
                        if not pe: continue
                        pe_parts = pe.split('/')
                        if len(pe_parts) >= 5:
                            if pe_parts[1] == 'open':
                                hosts_info[ip]['ports'].append({
                                    'port_id': pe_parts[0],
                                    'protocol': pe_parts[2],
                                    'service': pe_parts[4]
                                })
    
    print(f"{C.GREEN}{C.BOLD}✅ Auditoría finalizada en {elapsed:.1f} segundos.{C.RESET}\n")
    
    if not hosts_info:
        print(f"{C.YELLOW}No se detectaron puertos abiertos en los dispositivos.{C.RESET}")
        return
        
    # Ordenar por IP
    for ip, info in sorted(hosts_info.items(), key=lambda x: tuple(map(int, x[0].split('.')))):
        hostname_str = f" ({info['hostname']})" if info['hostname'] else ""
        print(f"{C.CYAN}🖥️  Dispositivo: {C.BOLD}{ip}{C.RESET}{C.YELLOW}{hostname_str}{C.RESET}")
        
        open_ports = info['ports']
        if open_ports:
            print(f"    {C.GREEN}🟢 Puertos Abiertos ({len(open_ports)}):{C.RESET}")
            for i, p in enumerate(open_ports):
                branch = "└─" if i == len(open_ports) - 1 else "├─"
                svc = p['service'] if p['service'] else "desconocido"
                print(f"       {C.DIM}{branch}{C.RESET} [{p['port_id']}/{p['protocol']}] {C.BOLD}{svc}{C.RESET}")
        else:
            print(f"    {C.DIM}🔴 0 puertos abiertos (Firewall cerrado o invisible).{C.RESET}")
        print()

def main():
    print_banner()
    subnets = get_local_subnets()
    
    if not subnets:
        print(f"{C.RED}No se pudo determinar la subred local.{C.RESET}")
        sys.exit(1)
        
    all_targets = set()
    for subnet in subnets:
        ips = populate_arp_and_get_ips(subnet)
        all_targets.update(ips)
        
    if len(all_targets) <= 1:
        # Fallback si ARP falla completamente
        targets = subnets
    else:
        targets = list(all_targets)
        
    output_data, elapsed = run_nmap_scan(targets)
    parse_and_display(output_data, elapsed)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Escaneo cancelado por el usuario.{C.RESET}")
        sys.exit(0)