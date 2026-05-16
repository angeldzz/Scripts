package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
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

// --- Base de datos local de Fabricantes (OUI) ---
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

// --- Top Puertos a Escanear (Expandido) ---
var portsToScan = []int{
	21, 22, 23, 25, 53, 79, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445,
	465, 515, 548, 554, 587, 631, 873, 993, 995, 1080, 1433, 1521, 1723, 2049,
	2121, 3128, 3306, 3389, 3690, 3702, 4899, 5000, 5001, 5009, 5060, 5432,
	5900, 5901, 6000, 62078, 6379, 6667, 7000, 8000, 8008, 8009, 8080, 8081,
	8443, 8888, 9000, 9090, 9100, 9200, 10000, 11211, 27017,
}

var portServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	81: "http-alt", 88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc",
	139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds",
	465: "smtps", 515: "printer", 548: "afp", 554: "rtsp", 587: "submission",
	631: "ipp", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
	1433: "ms-sql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 3128: "squid",
	3306: "mysql", 3389: "rdp", 3702: "ws-discovery", 5000: "upnp/http",
	5001: "iperf", 5432: "postgresql", 5900: "vnc", 62078: "apple-sync",
	6379: "redis", 7000: "afs3", 8000: "http-alt", 8008: "chromecast",
	8009: "chromecast", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
	9000: "cslistener", 9100: "jetdirect", 9200: "elasticsearch", 10000: "webmin",
	27017: "mongodb",
}

type PortInfo struct {
	Port    int
	Service string
	Banner  string
}

type HostInfo struct {
	IP       string
	MAC      string
	Vendor   string
	Hostname string
	Ports    []PortInfo
	OSGuess  string
}

func printBanner() {
	banner := fmt.Sprintf(`
%s%s╔═══════════════════════════════════════════════════════════════╗
║ 🚀 DETECTIVE DE RED - ESCÁNER ULTIMATE NATIVO EN GO           ║
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
		return ips[1 : len(ips)-1]
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

func arpSweepDial(ips []string) {
	fmt.Printf("%s[*] Descubriendo dispositivos activos (Sweep ARP ultrarrápido)...%s\n", Yellow, Reset)
	
	jobs := make(chan string, len(ips))
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	var wg sync.WaitGroup
	// IMPORTANTE: En iSH/emuladores x86, usar un Pool de Workers (ej. 20)
	// previene el error "runtime: split stack overflow" limitando el n. de goroutines simultáneas.
	numWorkers := 20 

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				// Dial a puerto 80 (Web)
				conn1, _ := net.DialTimeout("tcp", target+":80", 300*time.Millisecond)
				if conn1 != nil { conn1.Close() }
				
				// Dial a puerto 445 (SMB, común en Windows firewalleados)
				conn2, _ := net.DialTimeout("tcp", target+":445", 300*time.Millisecond)
				if conn2 != nil { conn2.Close() }
			}
		}()
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

// OS Fingerprinting usando TTL de ping
func getPingTTL(ip string) int {
	out, err := exec.Command("ping", "-c", "1", "-W", "1", ip).Output()
	if err != nil {
		return 0
	}
	ttlRegex := regexp.MustCompile(`(?i)ttl=(\d+)`)
	matches := ttlRegex.FindStringSubmatch(string(out))
	if len(matches) > 1 {
		ttl, _ := strconv.Atoi(matches[1])
		return ttl
	}
	return 0
}

func guessOSFromTTL(ttl int) string {
	if ttl == 0 { return "" }
	if ttl > 0 && ttl <= 64 {
		return "Linux / Unix / macOS"
	} else if ttl > 64 && ttl <= 128 {
		return "Windows"
	} else if ttl > 128 && ttl <= 255 {
		return "Cisco / Network Gear"
	}
	return ""
}

func gatherOSGuess(activeIPs []string) map[string]string {
	fmt.Printf("%s[*] Analizando firmas de red (OS Fingerprinting)...%s\n", Dim, Reset)
	results := make(map[string]string)
	var mu sync.Mutex

	jobs := make(chan string, len(activeIPs))
	for _, ip := range activeIPs {
		jobs <- ip
	}
	close(jobs)

	var wg sync.WaitGroup
	numWorkers := 30 // Worker Pool

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				ttl := getPingTTL(target)
				osGuess := guessOSFromTTL(ttl)
				if osGuess != "" {
					mu.Lock()
					results[target] = osGuess
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return results
}

// Banner Grabbing: Lee versiones de servicios y <titles> HTTP
func grabBanner(ip string, port int) string {
	target := fmt.Sprintf("%s:%d", ip, port)
	
	// HTTP/HTTPS Specific Extraction
	if port == 80 || port == 8080 || port == 8000 || port == 81 || port == 8888 || port == 443 || port == 8443 {
		scheme := "http"
		if port == 443 || port == 8443 {
			scheme = "https"
		}
		
		client := &http.Client{
			Timeout: 1500 * time.Millisecond,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s://%s/", scheme, target), nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		
		if err == nil {
			defer resp.Body.Close()
			server := resp.Header.Get("Server")
			
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			bodyStr := string(body)
			
			title := ""
			titleRegex := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
			matches := titleRegex.FindStringSubmatch(bodyStr)
			if len(matches) > 1 {
				title = strings.TrimSpace(matches[1])
			}
			
			var details []string
			if server != "" { details = append(details, server) }
			if title != "" { details = append(details, `"`+title+`"`) }
			
			if len(details) > 0 {
				return strings.Join(details, " | ")
			}
			return fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
	}
	
	// Generic TCP Banner Grab
	conn, err := net.DialTimeout("tcp", target, 800*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		banner := string(buf[:n])
		banner = strings.ReplaceAll(banner, "\r", "")
		banner = strings.ReplaceAll(banner, "\n", " ")
		banner = strings.TrimSpace(banner)
		
		if len(banner) > 60 {
			banner = banner[:57] + "..."
		}
		return banner
	}
	
	return ""
}

type scanJob struct {
	IP   string
	Port int
}

func portScan(activeIPs []string) map[string][]PortInfo {
	fmt.Printf("%s[*] Escaneando puertos y extrayendo Banners/Títulos HTTP...%s\n", Blue, Reset)
	results := make(map[string][]PortInfo)
	var mu sync.Mutex

	for _, ip := range activeIPs {
		results[ip] = []PortInfo{}
	}

	jobs := make(chan scanJob, len(activeIPs)*len(portsToScan))
	for _, ip := range activeIPs {
		for _, port := range portsToScan {
			jobs <- scanJob{IP: ip, Port: port}
		}
	}
	close(jobs)

	var wg sync.WaitGroup
	numWorkers := 80 // 80 acelera el escaneo ciego sin saturar los FDs en iSH

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				target := fmt.Sprintf("%s:%d", job.IP, job.Port)
				conn, err := net.DialTimeout("tcp", target, 500*time.Millisecond)
				if err == nil {
					conn.Close()
					
					// Puerto abierto, extraer banner
					banner := grabBanner(job.IP, job.Port)
					svc := portServices[job.Port]
					if svc == "" {
						svc = "desconocido"
					}

					mu.Lock()
					results[job.IP] = append(results[job.IP], PortInfo{
						Port:    job.Port,
						Service: svc,
						Banner:  banner,
					})
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	for k := range results {
		sort.Slice(results[k], func(i, j int) bool {
			return results[k][i].Port < results[k][j].Port
		})
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
			body, _ := io.ReadAll(resp.Body)
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
	var bannersStr string
	for _, p := range info.Ports {
		portSet[p.Port] = true
		bannersStr += strings.ToLower(p.Banner) + " "
	}

	// Heurísticas avanzadas usando Banners
	if strings.Contains(bannersStr, "synology") || strings.Contains(hostname, "diskstation") { return "🗄️ NAS Synology" }
	if strings.Contains(bannersStr, "qnap") { return "🗄️ NAS QNAP" }
	if strings.Contains(bannersStr, "ubuntu") { return "🐧 Servidor Ubuntu" }
	if strings.Contains(bannersStr, "debian") { return "🐧 Servidor Debian" }
	if strings.Contains(bannersStr, "raspbian") { return "🍓 Raspberry Pi" }
	if strings.Contains(bannersStr, "routeros") || strings.Contains(bannersStr, "mikrotik") { return "🌐 Router MikroTik" }
	if strings.Contains(bannersStr, "openwrt") { return "🌐 Router OpenWrt" }
	if strings.Contains(bannersStr, "apache") || strings.Contains(bannersStr, "nginx") || strings.Contains(bannersStr, "lighttpd") { 
		if portSet[53] || portSet[80] { return "🌐 Router / Servidor Web" }
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

	if info.OSGuess == "Windows" && (portSet[139] || portSet[445]) { return "🪟 PC Windows" }
	if info.OSGuess == "Linux / Unix / macOS" && portSet[22] { return "🐧 Servidor Linux / Unix" }

	if len(info.Ports) == 0 { return "👻 Dispositivo Oculto (Solo responde a ARP/Ping)" }
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
	// --- FIX CRÍTICO PARA EL EMULADOR iSH ---
	// Restringir el runtime a 1 solo hilo del Sistema Operativo evita por completo
	// la corrupción de memoria y el error "runtime: split stack overflow".
	// Las goroutines seguirán siendo concurrentes y ultrarrápidas sobre este único hilo.
	runtime.GOMAXPROCS(1)
	os.Setenv("GODEBUG", "asyncpreemptoff=1")

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

	// 1. ARP Sweep (Con Worker Pool para evitar Split Stack Overflow en iSH)
	arpSweepDial(allIPs)

	// 2. Extracción de Caché ARP
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

	if len(activeIPs) <= 1 {
		fmt.Printf("%s[!] Caché ARP inaccesible en iSH. Cambiando a Escaneo Ciego Profundo (Tomará ~1-2 min)...%s\n", Yellow, Reset)
		activeIPs = allIPs
	} else {
		fmt.Printf("%s[*] Se descubrieron %d dispositivos mediante Caché ARP.%s\n", Green, len(activeIPs), Reset)
	}

	// 3. OS Fingerprinting y Port Scanning (Concurrentes)
	var wg sync.WaitGroup
	var osGuesses map[string]string
	var openPorts map[string][]PortInfo

	wg.Add(2)
	go func() {
		defer wg.Done()
		osGuesses = gatherOSGuess(activeIPs)
	}()
	go func() {
		defer wg.Done()
		openPorts = portScan(activeIPs)
	}()
	wg.Wait()

	fmt.Printf("\n%s🔍 Cruzando datos heurísticos (MAC OUI, Banners, OS, Puertos)...%s\n\n", Dim, Reset)

	// 4. Mostrar Resultados
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
					time.Sleep(1 * time.Second) // Prevención de rate-limit
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
			OSGuess:  osGuesses[ip],
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
		// Si el host no responde absolutamente a nada (completamente muerto/filtrado), lo ocultamos
		if len(info.Ports) == 0 && (info.MAC == "Desconocida" || info.MAC == "") && info.OSGuess == "" && vendor == "Desconocido" && vendor != "Este Equipo" {
			continue
		}

		osStr := ""
		if info.OSGuess != "" {
			osStr = fmt.Sprintf(" %s| OS: %s%s", Dim, info.OSGuess, Reset)
		}

		fmt.Printf("%s📍 %s%s%s%s%s\n", Cyan, Bold, info.IP, Reset, Yellow, hostStr, Reset)
		fmt.Printf("    %s├─ MAC:%s %s%s%s%s\n", Dim, Reset, info.MAC, Magenta, vendorStr, Reset)
		fmt.Printf("    %s├─ Tipo:%s %s%s%s%s\n", Dim, Reset, Bold, deviceType, Reset, osStr)

		if len(info.Ports) > 0 {
			fmt.Printf("    %s└─ Puertos Abiertos (%d):%s\n", Green, len(info.Ports), Reset)
			for i, p := range info.Ports {
				branch := "   ├─"
				if i == len(info.Ports)-1 {
					branch = "   └─"
				}
				
				bannerStr := ""
				if p.Banner != "" {
					bannerStr = fmt.Sprintf("%s ➜ %s%s", Dim, p.Banner, Reset)
				}
				
				fmt.Printf("    %s%s%s [%d/tcp] %s%s%s%s\n", Dim, branch, Reset, p.Port, Bold, p.Service, Reset, bannerStr)
			}
		} else {
			fmt.Printf("    %s└─ 🔴 0 puertos abiertos (Firewall cerrado/activo).%s\n", Dim, Reset)
		}
		fmt.Println()
	}

	elapsed := time.Since(startTime)
	fmt.Printf("%s%s✅ Escaneo Ultimate finalizado en %.1f segundos.%s\n", Green, Bold, elapsed.Seconds(), Reset)
}
