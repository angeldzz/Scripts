package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Colores ANSI ---
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[91m"
	Green   = "\033[92m"
	Yellow  = "\033[93m"
	Blue    = "\033[94m"
	Magenta = "\033[35m"
	Cyan    = "\033[96m"
)

// --- Base de datos local de Fabricantes ---
var commonMacVendors = map[string]string{
	"00:1E:C2": "Apple", "00:1F:5B": "Apple", "18:AF:61": "Apple", "2C:F0:EE": "Apple", "F8:FF:C2": "Apple",
	"00:24:D7": "Samsung", "00:15:99": "Samsung",
	"00:1E:10": "Huawei", "28:6C:07": "Huawei",
	"00:04:4B": "Nvidia", "00:09:BF": "Nintendo",
	"00:1D:BD": "Sony", "00:1E:45": "Sony",
	"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
	"00:1A:11": "Google", "E4:F0:42": "Google",
	"00:22:61": "Motorola", "00:17:88": "Philips",
	"00:1A:22": "Cisco", "00:14:22": "Dell", "00:26:B9": "Dell",
	"00:1A:4B": "HP", "00:10:83": "HP", "00:1E:68": "Intel",
}

// --- Servicios comunes por puerto ---
var portServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
	443: "https", 445: "microsoft-ds", 515: "printer", 548: "afp", 554: "rtsp",
	631: "ipp", 993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
	3389: "ms-wbt-server", 3702: "ws-discovery", 5000: "upnp/http", 5001: "iperf",
	5900: "vnc", 62078: "apple-sync", 7000: "afs3-bos", 8000: "http-alt",
	8008: "chromecast", 8009: "chromecast", 8080: "http-proxy", 8443: "https-alt", 9100: "jetdirect",
}

type HostInfo struct {
	IP       string
	MAC      string
	Vendor   string
	Hostname string
	Ports    []int
}

func printBanner() {
	banner := fmt.Sprintf(`
%s%s╔═══════════════════════════════════════════════════════════════╗
║ 🚀 DETECTIVE DE RED - ESCÁNER ULTRARRÁPIDO NATIVO EN GO       ║
╚═══════════════════════════════════════════════════════════════╝%s`, Cyan, Bold, Reset)
	fmt.Println(banner)
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}
	return ""
}

func getLocalSubnets() []string {
	subnets := make(map[string]bool)

	// Método 1: Interfaces de red nativas de Go
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, i := range ifaces {
			if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := i.Addrs()
			if err == nil {
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
						_, network, _ := net.ParseCIDR(ipnet.String())
						if network != nil {
							subnets[network.String()] = true
						}
					}
				}
			}
		}
	}

	// Método 2: Fallback utilizando comandos del sistema (útil en iSH)
	out, err := exec.Command("ip", "-4", "route").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "dev") && !strings.Contains(line, "default") {
				parts := strings.Fields(line)
				if len(parts) > 0 && strings.Contains(parts[0], "/") {
					subnets[parts[0]] = true
				}
			}
		}
	}

	var result []string
	for k := range subnets {
		result = append(result, k)
	}

	// Fallback final si no se detecta nada
	if len(result) == 0 {
		ip := getLocalIP()
		if ip != "" {
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				result = append(result, fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2]))
			}
		}
	}

	return result
}

func getIPsFromCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1] // Excluir red y broadcast
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// arpSweepDial envía una petición TCP rápida al puerto 80.
// Esto obliga al kernel a resolver la IP por ARP, poblando la tabla
// sin necesidad de hacer forks para ejecutar comandos ping (mucho más ligero en iSH).
func arpSweepDial(ips []string) {
	fmt.Printf("%s[*] Descubriendo dispositivos activos (Sweep ARP ultrarrápido)...%s\n", Yellow, Reset)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100) // Máx 100 goroutines para no agotar FDs en iSH

	for _, ip := range ips {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			conn, _ := net.DialTimeout("tcp", target+":80", 400*time.Millisecond)
			if conn != nil {
				conn.Close()
			}
			<-sem
		}(ip)
	}
	wg.Wait()
}

func getARPCache() map[string]string {
	arpTable := make(map[string]string)

	file, err := os.Open("/proc/net/arp")
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 {
				ip := fields[0]
				mac := strings.ToLower(fields[3])
				if mac != "00:00:00:00:00:00" && mac != "(incomplete)" {
					arpTable[ip] = mac
				}
			}
		}
		file.Close()
	}

	out, err := exec.Command("arp", "-a").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
		macRegex := regexp.MustCompile(`([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})`)

		for _, line := range lines {
			ipMatch := ipRegex.FindString(line)
			macMatch := macRegex.FindString(line)
			if ipMatch != "" && macMatch != "" {
				mac := strings.ToLower(strings.ReplaceAll(macMatch, "-", ":"))
				if arpTable[ipMatch] == "" && mac != "ff:ff:ff:ff:ff:ff" {
					arpTable[ipMatch] = mac
				}
			}
		}
	}
	return arpTable
}

func portScan(activeIPs []string) map[string][]int {
	fmt.Printf("%s[*] Escaneando puertos concurrentemente (sin dependencias externas)...%s\n", Blue, Reset)
	results := make(map[string][]int)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 80)

	portsToScan := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 515, 548,
		554, 631, 993, 995, 1723, 3306, 3389, 3702, 5000, 5001, 5900, 62078,
		7000, 8000, 8008, 8009, 8080, 8443, 9100,
	}

	for _, ip := range activeIPs {
		mu.Lock()
		results[ip] = []int{}
		mu.Unlock()
		for _, port := range portsToScan {
			wg.Add(1)
			go func(targetIP string, targetPort int) {
				defer wg.Done()
				sem <- struct{}{}

				target := fmt.Sprintf("%s:%d", targetIP, targetPort)
				conn, err := net.DialTimeout("tcp", target, 500*time.Millisecond)
				if err == nil {
					conn.Close()
					mu.Lock()
					results[targetIP] = append(results[targetIP], targetPort)
					mu.Unlock()
				}
				<-sem
			}(ip, port)
		}
	}
	wg.Wait()

	for k := range results {
		sort.Ints(results[k])
	}
	return results
}

func fetchVendor(mac string) string {
	urlStr := "https://api.macvendors.com/" + url.QueryEscape(mac)
	client := http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("GET", urlStr, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := ioutil.ReadAll(resp.Body)
			return strings.TrimSpace(string(body))
		}
	}
	return "Desconocido"
}

func getHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}

func getDeviceType(info *HostInfo) string {
	hostname := strings.ToLower(info.Hostname)
	vendorLower := strings.ToLower(info.Vendor)

	portSet := make(map[int]bool)
	for _, p := range info.Ports {
		portSet[p] = true
	}

	if strings.Contains(hostname, "iphone") || strings.Contains(hostname, "ipad") { return "📱 iPhone / iPad (iOS)" }
	if strings.Contains(hostname, "macbook") || strings.Contains(hostname, "imac") || strings.Contains(hostname, "mac-mini") { return "💻 Mac (macOS)" }
	if strings.Contains(hostname, "desktop") || strings.Contains(hostname, "laptop") { return "🪟 PC Windows" }
	if strings.Contains(hostname, "android") || strings.Contains(hostname, "galaxy") || strings.Contains(hostname, "pixel") { return "📱 Smartphone Android" }
	if strings.Contains(hostname, "tv") { return "📺 Smart TV" }
	if strings.Contains(hostname, "hp") && strings.Contains(hostname, "print") { return "🖨️ Impresora" }

	if strings.Contains(vendorLower, "apple") {
		if portSet[62078] { return "📱 iPhone / iPad (iOS)" }
		if portSet[5000] || portSet[7000] { return "📺 Apple TV / AirPlay" }
		if portSet[22] || portSet[548] || portSet[5900] { return "💻 Mac (macOS)" }
		return "🍏 Dispositivo Apple"
	}

	if portSet[631] || portSet[9100] || portSet[515] { return "🖨️ Impresora de Red" }
	if portSet[53] && (portSet[80] || portSet[443]) { return "🌐 Router / Gateway / Firewall" }
	if portSet[445] || portSet[139] || portSet[3389] { return "🪟 PC / Servidor Windows" }
	if portSet[22] && len(info.Ports) <= 5 { return "🐧 Servidor Linux / Raspberry Pi" }
	if portSet[554] || portSet[3702] { return "📷 Cámara IP / Vigilancia" }
	if portSet[8009] || portSet[8008] { return "📺 Chromecast / Dispositivo Cast" }

	if strings.Contains(vendorLower, "samsung") || strings.Contains(vendorLower, "lg") || strings.Contains(vendorLower, "sony") || strings.Contains(vendorLower, "nintendo") { return "📺 Smart TV / Consola / Multimedia" }
	if strings.Contains(vendorLower, "xiaomi") || strings.Contains(vendorLower, "huawei") || strings.Contains(vendorLower, "motorola") { return "📱 Smartphone Android" }

	if len(info.Ports) == 0 { return "👻 Dispositivo Oculto (Solo responde a ARP)" }
	return "🖥️ Dispositivo Desconocido"
}

func sortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		p1 := strings.Split(ips[i], ".")
		p2 := strings.Split(ips[j], ".")
		if len(p1) != 4 || len(p2) != 4 {
			return ips[i] < ips[j]
		}
		for k := 0; k < 4; k++ {
			n1, _ := strconv.Atoi(p1[k])
			n2, _ := strconv.Atoi(p2[k])
			if n1 != n2 {
				return n1 < n2
			}
		}
		return false
	})
}

func main() {
	startTime := time.Now()
	printBanner()

	subnets := getLocalSubnets()
	if len(subnets) == 0 {
		fmt.Printf("%s[!] No se detectó ninguna subred local.%s\n", Red, Reset)
		os.Exit(1)
	}

	var allIPs []string
	for _, sub := range subnets {
		fmt.Printf("%s[*] Analizando subred: %s%s\n", Dim, sub, Reset)
		allIPs = append(allIPs, getIPsFromCIDR(sub)...)
	}

	// 1. ARP Dial Sweep
	arpSweepDial(allIPs)

	// 2. Extraer Caché ARP
	arpTable := getARPCache()
	localIP := getLocalIP()
	if localIP != "" {
		if _, exists := arpTable[localIP]; !exists {
			arpTable[localIP] = "Dispositivo Local"
		}
	}

	var activeIPs []string
	for ip := range arpTable {
		activeIPs = append(activeIPs, ip)
	}

	if len(activeIPs) == 0 {
		fmt.Printf("%s[!] No se encontraron dispositivos activos en la red.%s\n", Yellow, Reset)
		os.Exit(0)
	}

	// 3. Escaneo de Puertos a IPs Activas
	openPorts := portScan(activeIPs)

	fmt.Printf("%s🔍 Analizando %d hosts y consultando OUI...%s\n\n", Dim, len(activeIPs), Reset)

	// 4. Procesar y Mostrar Resultados
	vendorCache := make(map[string]string)
	sortIPs(activeIPs)

	for _, ip := range activeIPs {
		mac := arpTable[ip]
		vendor := "Desconocido"

		if mac != "" && mac != "Dispositivo Local" {
			prefix := strings.ToUpper(mac)
			if len(prefix) >= 8 {
				prefix = prefix[:8]
			}
			if v, ok := commonMacVendors[prefix]; ok {
				vendor = v
			} else if v, ok := vendorCache[mac]; ok {
				vendor = v
			} else {
				vendor = fetchVendor(mac)
				vendorCache[mac] = vendor
				if vendor != "Desconocido" {
					time.Sleep(1 * time.Second) // Evitar ban de API
				}
			}
		} else if mac == "Dispositivo Local" {
			vendor = "Este Equipo"
		}

		hostname := getHostname(ip)
		info := &HostInfo{
			IP:       ip,
			MAC:      mac,
			Vendor:   vendor,
			Hostname: hostname,
			Ports:    openPorts[ip],
		}

		deviceType := getDeviceType(info)
		hostStr := ""
		if hostname != "" {
			hostStr = fmt.Sprintf(" (%s)", hostname)
		}
		vendorStr := ""
		if vendor != "Desconocido" {
			vendorStr = fmt.Sprintf(" [%s]", vendor)
		}

		fmt.Printf("%s📍 %s%s%s%s%s\n", Cyan, Bold, info.IP, Reset, Yellow, hostStr, Reset)
		fmt.Printf("    %s├─ MAC:%s %s%s%s%s\n", Dim, Reset, info.MAC, Magenta, vendorStr, Reset)
		fmt.Printf("    %s├─ Tipo:%s %s%s%s\n", Dim, Reset, Bold, deviceType, Reset)

		if len(info.Ports) > 0 {
			fmt.Printf("    %s└─ Puertos Abiertos (%d):%s\n", Green, len(info.Ports), Reset)
			for i, p := range info.Ports {
				branch := "   ├─"
				if i == len(info.Ports)-1 {
					branch = "   └─"
				}
				svc := "desconocido"
				if s, ok := portServices[p]; ok {
					svc = s
				}
				fmt.Printf("    %s%s%s [%d/tcp] %s%s%s\n", Dim, branch, Reset, p, Bold, svc, Reset)
			}
		} else {
			fmt.Printf("    %s└─ 🔴 0 puertos abiertos (Firewall cerrado/activo).%s\n", Dim, Reset)
		}
		fmt.Println()
	}

	elapsed := time.Since(startTime)
	fmt.Printf("%s%s✅ Auditoría finalizada en %.1f segundos.%s\n", Green, Bold, elapsed.Seconds(), Reset)
}
