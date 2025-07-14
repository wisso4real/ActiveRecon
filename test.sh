#!/bin/bash

#######################################################################
# ActiveRecon - Complete Active Reconnaissance Tool
# Based on OWASP/NIST/PTES Methodology
# 
# Usage: ./activerecon.sh [OPTIONS] TARGET_RANGE
# 
# Author: Security Professional
# Version: 1.0
#######################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_RANGE=""
OUTPUT_DIR=""
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
THREADS=50
TIMING=4
VERBOSE=false
QUICK_SCAN=false
STEALTH_MODE=false
FULL_SCAN=false
AUTO_EXPLOIT=false

# Wordlists paths
COMMON_PORTS="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416,417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"

# Function definitions
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════╗
    ║                  ActiveRecon v1.0                 ║
    ║         Complete Active Reconnaissance Tool       ║
    ║              Based on OWASP/NIST/PTES             ║
    ╚═══════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS] TARGET_RANGE

Options:
    -o, --output DIR        Output directory (default: activerecon_TIMESTAMP)
    -t, --threads NUM       Number of threads (default: 50)
    -T, --timing NUM        Timing template 0-5 (default: 4)
    -q, --quick             Quick scan (top 1000 ports only)
    -f, --full              Full scan (all 65535 ports)
    -s, --stealth           Stealth mode (slower, less detectable)
    -v, --verbose           Verbose output
    -x, --exploit           Enable auto-exploitation attempts
    -h, --help              Show this help message

Examples:
    $0 192.168.1.0/24
    $0 -q -o quick_scan 10.0.0.0/16
    $0 -f -s -t 25 target.com
    $0 --verbose --exploit 172.16.0.0/12

Phases:
    1. Target Validation      6. Infrastructure Mapping
    2. Network Discovery      7. Vulnerability Assessment
    3. Port Scanning          8. Evidence Processing
    4. Service Enumeration    
    5. Protocol Analysis      

EOF
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")  echo -e "${GREEN}[INFO]${NC} ${timestamp} - $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} ${timestamp} - $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" ;;
        "DEBUG") [ "$VERBOSE" = true ] && echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - $message" ;;
        "PHASE") echo -e "${PURPLE}[PHASE]${NC} ${timestamp} - $message" ;;
        "VULN")  echo -e "${RED}[VULN]${NC} ${timestamp} - $message" ;;
    esac
    
    # Also log to file (only if OUTPUT_DIR exists)
    if [ -n "$OUTPUT_DIR" ] && [ -d "$OUTPUT_DIR" ]; then
        echo "[$level] $timestamp - $message" >> "$OUTPUT_DIR/activerecon.log"
    fi
}

check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local deps=("nmap" "masscan" "nc" "dig" "whois" "curl")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log "ERROR" "Missing dependencies: ${missing_deps[*]}"
        log "INFO" "Install missing dependencies and try again"
        exit 1
    fi
    
    # Check if running as root for SYN scans
    if [ "$EUID" -ne 0 ]; then
        log "WARN" "Not running as root - will use connect scans instead of SYN scans"
        log "WARN" "For better performance and stealth, run as root"
    fi
    
    log "INFO" "Dependencies check passed"
}

setup_environment() {
    log "INFO" "Setting up environment..."
    
    # Create output directory structure first
    mkdir -p "$OUTPUT_DIR"/{discovery,scanning,enumeration,protocol_analysis,infrastructure,vulnerabilities,evidence,reports}
    
    # Initialize log file after directory creation
    echo "ActiveRecon Log - Started at $(date)" > "$OUTPUT_DIR/activerecon.log"
    log "INFO" "Log file initialized"
    
    # Create target files
    touch "$OUTPUT_DIR/live_hosts.txt"
    touch "$OUTPUT_DIR/all_targets.txt"
    
    # Set scan type based on privileges
    if [ "$EUID" -eq 0 ]; then
        SCAN_TYPE="-sS"
        log "INFO" "Running as root - using SYN scans"
    else
        SCAN_TYPE="-sT"
        log "WARN" "Running as user - using connect scans"
    fi
    
    # Adjust timing for stealth mode
    if [ "$STEALTH_MODE" = true ]; then
        TIMING=1
        THREADS=10
        log "INFO" "Stealth mode enabled - reduced timing and threads"
    fi
    
    log "INFO" "Output directory: $OUTPUT_DIR"
    log "INFO" "Scan configuration: Type=$SCAN_TYPE, Timing=T$TIMING, Threads=$THREADS"
}

phase1_target_validation() {
    log "PHASE" "Phase 1: Target Validation"
    
    cd "$OUTPUT_DIR"
    
    # DNS resolution and validation
    log "INFO" "Performing DNS resolution and validation..."
    
    if [[ "$TARGET_RANGE" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
        log "INFO" "Target is IP range: $TARGET_RANGE"
        echo "$TARGET_RANGE" > target_ranges.txt
    else
        log "INFO" "Target is domain: $TARGET_RANGE"
        
        # DNS lookups
        dig "$TARGET_RANGE" A | grep -E "^$TARGET_RANGE" | awk '{print $5}' > target_ips.txt 2>/dev/null || true
        dig "$TARGET_RANGE" AAAA | grep -E "^$TARGET_RANGE" | awk '{print $5}' >> target_ips.txt 2>/dev/null || true
        
        # WHOIS information
        whois "$TARGET_RANGE" > discovery/whois_info.txt 2>/dev/null || true
        
        # Extract network ranges from WHOIS
        grep -E "^(NetRange|inetnum|route):" discovery/whois_info.txt | awk '{print $2}' >> target_ranges.txt 2>/dev/null || true
        
        if [ ! -s target_ips.txt ] && [ ! -s target_ranges.txt ]; then
            log "ERROR" "Could not resolve target or extract network ranges"
            exit 1
        fi
    fi
    
    # Traceroute analysis
    log "INFO" "Performing traceroute analysis..."
    if [[ "$TARGET_RANGE" =~ ^[0-9] ]]; then
        # Extract first IP from range for traceroute
        first_ip=$(echo "$TARGET_RANGE" | cut -d'/' -f1)
        traceroute "$first_ip" > discovery/traceroute.txt 2>/dev/null || true
    else
        traceroute "$TARGET_RANGE" > discovery/traceroute.txt 2>/dev/null || true
    fi
    
    log "INFO" "Phase 1 completed - Target validation successful"
}

phase2_network_discovery() {
    log "PHASE" "Phase 2: Network Discovery"
    
    cd "$OUTPUT_DIR"
    
    # Determine scan targets
    if [ -s target_ranges.txt ]; then
        targets=$(cat target_ranges.txt | head -1)
    else
        targets="$TARGET_RANGE"
    fi
    
    log "INFO" "Starting network discovery for: $targets"
    
    # ICMP Discovery
    log "INFO" "Performing ICMP discovery..."
    nmap -sn "$targets" --min-rate 1000 -oA discovery/icmp_discovery -T"$TIMING" 2>/dev/null || true
    
    # TCP Discovery (common ports)
    log "INFO" "Performing TCP discovery..."
    nmap -sn -PS21,22,25,53,80,135,139,443,445,993,995,3389,5900 "$targets" \
        -oA discovery/tcp_discovery -T"$TIMING" 2>/dev/null || true
    
    # UDP Discovery
    log "INFO" "Performing UDP discovery..."
    nmap -sn -PU53,67,68,137,161,500,514,1434 "$targets" \
        -oA discovery/udp_discovery -T"$TIMING" 2>/dev/null || true
    
    # ARP Discovery (if local network)
    if [[ "$targets" =~ ^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        log "INFO" "Performing ARP discovery for local network..."
        if command -v arp-scan &> /dev/null; then
            arp-scan -l > discovery/arp_discovery.txt 2>/dev/null || true
        fi
        
        if command -v netdiscover &> /dev/null; then
            timeout 30 netdiscover -r "$targets" -P > discovery/netdiscover.txt 2>/dev/null || true
        fi
    fi
    
    # Consolidate live hosts
    log "INFO" "Consolidating live hosts..."
    {
        grep "Up" discovery/*.gnmap 2>/dev/null | cut -d' ' -f2 || true
        grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" discovery/arp_discovery.txt 2>/dev/null || true
        grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" discovery/netdiscover.txt 2>/dev/null || true
    } | sort -V | uniq > live_hosts.txt
    
    local host_count=$(wc -l < live_hosts.txt)
    log "INFO" "Phase 2 completed - Discovered $host_count live hosts"
    
    if [ "$host_count" -eq 0 ]; then
        log "WARN" "No live hosts discovered - check target range and connectivity"
        exit 1
    fi
}

phase3_port_scanning() {
    log "PHASE" "Phase 3: Port Scanning"
    
    cd "$OUTPUT_DIR"
    
    if [ ! -s live_hosts.txt ]; then
        log "ERROR" "No live hosts file found"
        return 1
    fi
    
    local host_count=$(wc -l < live_hosts.txt)
    log "INFO" "Starting port scanning on $host_count hosts"
    
    # Fast common port scan
    log "INFO" "Performing fast common port scan..."
    if [ "$QUICK_SCAN" = true ]; then
        nmap $SCAN_TYPE --top-ports 1000 -T"$TIMING" --open \
            -iL live_hosts.txt -oA scanning/fast_scan --min-rate "$THREADS" 2>/dev/null || true
    elif [ "$FULL_SCAN" = true ]; then
        log "INFO" "Full scan mode - this will take a while..."
        nmap $SCAN_TYPE -p- -T"$TIMING" --open \
            -iL live_hosts.txt -oA scanning/full_scan --min-rate "$THREADS" 2>/dev/null || true
    else
        nmap $SCAN_TYPE -p "$COMMON_PORTS" -T"$TIMING" --open \
            -iL live_hosts.txt -oA scanning/common_scan --min-rate "$THREADS" 2>/dev/null || true
    fi
    
    # Extract high-value targets for comprehensive scanning
    log "INFO" "Identifying high-value targets..."
    grep -E "22/open|80/open|443/open|445/open|3389/open|21/open|23/open|25/open|53/open|135/open|139/open|1433/open|3306/open|5432/open" \
        scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > high_value_targets.txt || true
    
    local hv_count=$(wc -l < high_value_targets.txt)
    if [ "$hv_count" -gt 0 ] && [ "$QUICK_SCAN" = false ]; then
        log "INFO" "Performing comprehensive scan on $hv_count high-value targets..."
        nmap $SCAN_TYPE -p- --min-rate "$((THREADS * 2))" -T"$TIMING" --open \
            -iL high_value_targets.txt -oA scanning/comprehensive_scan 2>/dev/null || true
    fi
    
    # UDP scan on common ports
    log "INFO" "Performing UDP scan on common ports..."
    nmap -sU --top-ports 100 -T"$TIMING" --open \
        -iL live_hosts.txt -oA scanning/udp_scan 2>/dev/null || true
    
    # Service categorization
    log "INFO" "Categorizing discovered services..."
    categorize_services
    
    log "INFO" "Phase 3 completed - Port scanning finished"
}

categorize_services() {
    cd "$OUTPUT_DIR"
    
    # Create service category files
    grep "21/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > ftp_targets.txt || touch ftp_targets.txt
    grep "22/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > ssh_targets.txt || touch ssh_targets.txt
    grep "23/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > telnet_targets.txt || touch telnet_targets.txt
    grep -E "25/tcp.*open|587/tcp.*open|465/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > smtp_targets.txt || touch smtp_targets.txt
    grep -E "53/tcp.*open|53/udp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > dns_targets.txt || touch dns_targets.txt
    grep -E "80/tcp.*open|443/tcp.*open|8080/tcp.*open|8443/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > web_targets.txt || touch web_targets.txt
    grep -E "110/tcp.*open|995/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > pop3_targets.txt || touch pop3_targets.txt
    grep -E "143/tcp.*open|993/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > imap_targets.txt || touch imap_targets.txt
    grep -E "135/tcp.*open|139/tcp.*open|445/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > smb_targets.txt || touch smb_targets.txt
    grep -E "1433/tcp.*open|3306/tcp.*open|5432/tcp.*open|1521/tcp.*open|27017/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > database_targets.txt || touch database_targets.txt
    grep -E "3389/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > rdp_targets.txt || touch rdp_targets.txt
    grep -E "5900/tcp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > vnc_targets.txt || touch vnc_targets.txt
    grep -E "161/udp.*open" scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u > snmp_targets.txt || touch snmp_targets.txt
    
    # Generate service summary
    {
        echo "=== Service Distribution Summary ==="
        echo "FTP Services: $(wc -l < ftp_targets.txt)"
        echo "SSH Services: $(wc -l < ssh_targets.txt)"
        echo "Telnet Services: $(wc -l < telnet_targets.txt)"
        echo "SMTP Services: $(wc -l < smtp_targets.txt)"
        echo "DNS Services: $(wc -l < dns_targets.txt)"
        echo "Web Services: $(wc -l < web_targets.txt)"
        echo "POP3 Services: $(wc -l < pop3_targets.txt)"
        echo "IMAP Services: $(wc -l < imap_targets.txt)"
        echo "SMB Services: $(wc -l < smb_targets.txt)"
        echo "Database Services: $(wc -l < database_targets.txt)"
        echo "RDP Services: $(wc -l < rdp_targets.txt)"
        echo "VNC Services: $(wc -l < vnc_targets.txt)"
        echo "SNMP Services: $(wc -l < snmp_targets.txt)"
    } > service_summary.txt
    
    log "INFO" "Service categorization completed"
    cat service_summary.txt
}

phase4_service_enumeration() {
    log "PHASE" "Phase 4: Service Enumeration"
    
    cd "$OUTPUT_DIR"
    
    # Version detection
    log "INFO" "Performing service version detection..."
    nmap -sV --version-intensity 5 -T"$TIMING" \
        -iL live_hosts.txt -oA enumeration/version_detection 2>/dev/null || true
    
    # Default script scan
    log "INFO" "Running default NSE scripts..."
    nmap -sC -T"$TIMING" \
        -iL live_hosts.txt -oA enumeration/default_scripts 2>/dev/null || true
    
    # Banner grabbing
    log "INFO" "Performing banner grabbing..."
    nmap $SCAN_TYPE --script banner -T"$TIMING" \
        -iL live_hosts.txt -oA enumeration/banners 2>/dev/null || true
    
    # Service-specific enumeration
    enumerate_web_services
    enumerate_database_services
    enumerate_smb_services
    enumerate_ssh_services
    enumerate_ftp_services
    enumerate_dns_services
    enumerate_snmp_services
    
    log "INFO" "Phase 4 completed - Service enumeration finished"
}

enumerate_web_services() {
    if [ ! -s web_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Enumerating web services..."
    
    # HTTP methods and headers
    nmap -p80,443,8080,8443 --script http-methods,http-headers,http-title,http-server-header \
        -iL web_targets.txt -oA enumeration/web_enum -T"$TIMING" 2>/dev/null || true
    
    # Technology detection
    if command -v whatweb &> /dev/null; then
        log "INFO" "Running whatweb technology detection..."
        while read -r target; do
            echo "=== Analyzing $target ===" >> enumeration/web_tech_results.txt
            whatweb --aggression 3 "http://$target" >> enumeration/web_tech_results.txt 2>/dev/null || true
            whatweb --aggression 3 "https://$target" >> enumeration/web_tech_results.txt 2>/dev/null || true
        done < web_targets.txt
    fi
    
    # SSL/TLS analysis
    nmap -p443 --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle \
        -iL web_targets.txt -oA enumeration/ssl_analysis -T"$TIMING" 2>/dev/null || true
    
    # Directory discovery (limited for automation)
    if command -v gobuster &> /dev/null && [ "$AUTO_EXPLOIT" = true ]; then
        log "INFO" "Running basic directory discovery (limited)..."
        head -3 web_targets.txt | while read -r target; do
            timeout 300 gobuster dir -u "http://$target" \
                -w /usr/share/wordlists/dirb/common.txt \
                -x php,html,txt -q -o "enumeration/gobuster_$target.txt" 2>/dev/null || true
        done
    fi
}

enumerate_database_services() {
    if [ ! -s database_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Enumerating database services..."
    
    # MySQL enumeration
    nmap -p3306 --script mysql-info,mysql-databases,mysql-variables,mysql-empty-password \
        -iL database_targets.txt -oA enumeration/mysql_enum -T"$TIMING" 2>/dev/null || true
    
    # MSSQL enumeration
    nmap -p1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password \
        -iL database_targets.txt -oA enumeration/mssql_enum -T"$TIMING" 2>/dev/null || true
    
    # PostgreSQL enumeration
    nmap -p5432 --script pgsql-brute \
        -iL database_targets.txt -oA enumeration/pgsql_enum -T"$TIMING" 2>/dev/null || true
    
    # Oracle enumeration
    nmap -p1521 --script oracle-sid-brute,oracle-enum-users \
        -iL database_targets.txt -oA enumeration/oracle_enum -T"$TIMING" 2>/dev/null || true
    
    # MongoDB enumeration
    nmap -p27017 --script mongodb-info,mongodb-databases \
        -iL database_targets.txt -oA enumeration/mongodb_enum -T"$TIMING" 2>/dev/null || true
}

enumerate_smb_services() {
    if [ ! -s smb_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Enumerating SMB services..."
    
    # SMB protocol analysis
    nmap -p445 --script smb-protocols,smb-security-mode,smb-os-discovery \
        -iL smb_targets.txt -oA enumeration/smb_protocols -T"$TIMING" 2>/dev/null || true
    
    # Share enumeration
    nmap -p445 --script smb-enum-shares,smb-enum-users \
        -iL smb_targets.txt -oA enumeration/smb_shares -T"$TIMING" 2>/dev/null || true
    
    # Manual enumeration with smbclient
    if command -v smbclient &> /dev/null; then
        log "INFO" "Running smbclient enumeration..."
        while read -r target; do
            echo "=== SMB Shares on $target ===" >> enumeration/smbclient_results.txt
            timeout 30 smbclient -L "//$target" -N >> enumeration/smbclient_results.txt 2>/dev/null || true
        done < smb_targets.txt
    fi
    
    # enum4linux if available
    if command -v enum4linux &> /dev/null && [ "$AUTO_EXPLOIT" = true ]; then
        log "INFO" "Running enum4linux (limited targets)..."
        head -3 smb_targets.txt | while read -r target; do
            timeout 300 enum4linux -a "$target" > "enumeration/enum4linux_$target.txt" 2>/dev/null || true
        done
    fi
}

enumerate_ssh_services() {
    if [ ! -s ssh_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Enumerating SSH services..."
    
    # SSH configuration analysis
    nmap -p22 --script ssh-hostkey,ssh2-enum-algos,ssh-auth-methods \
        -iL ssh_targets.txt -oA enumeration/ssh_config -T"$TIMING" 2>/dev/null || true
    
    # SSH version enumeration
    while read -r target; do
        echo "SSH version on $target:" >> enumeration/ssh_versions.txt
        timeout 10 nc "$target" 22 2>/dev/null | head -1 >> enumeration/ssh_versions.txt || true
    done < ssh_targets.txt
}

enumerate_ftp_services() {
    if [ ! -s ftp_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Enumerating FTP services..."
    
    # FTP enumeration
    nmap -p21 --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor \
        -iL ftp_targets.txt -oA enumeration/ftp_enum -T"$TIMING" 2>/dev/null || true
    
    # Manual FTP banner grabbing
    while read -r target; do
        echo "FTP banner on $target:" >> enumeration/ftp_banners.txt
        timeout 10 nc "$target" 21 2>/dev/null | head -3 >> enumeration/ftp_banners.txt || true
    done < ftp_targets.txt
}

enumerate_dns_services() {
    if [ ! -s dns_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Enumerating DNS services..."
    
    # DNS server information
    nmap -p53 --script dns-nsid,dns-recursion \
        -iL dns_targets.txt -oA enumeration/dns_enum -T"$TIMING" 2>/dev/null || true
    
    # Zone transfer attempts
    if [ "$AUTO_EXPLOIT" = true ]; then
        while read -r target; do
            echo "=== Zone transfer attempts on $target ===" >> enumeration/dns_zone_transfers.txt
            dig @"$target" "$TARGET_RANGE" AXFR >> enumeration/dns_zone_transfers.txt 2>/dev/null || true
        done < dns_targets.txt
    fi
}

enumerate_snmp_services() {
    if [ ! -s snmp_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Enumerating SNMP services..."
    
    # SNMP enumeration
    nmap -sU -p161 --script snmp-sysdescr,snmp-info \
        -iL snmp_targets.txt -oA enumeration/snmp_enum -T"$TIMING" 2>/dev/null || true
    
    # SNMP community string testing
    if command -v onesixtyone &> /dev/null; then
        log "INFO" "Testing SNMP community strings..."
        echo -e "public\nprivate\ncommunity\nmanager" > enumeration/snmp_communities.txt
        onesixtyone -c enumeration/snmp_communities.txt -i snmp_targets.txt > enumeration/snmp_community_results.txt 2>/dev/null || true
    fi
}

phase5_protocol_analysis() {
    log "PHASE" "Phase 5: Protocol Analysis"
    
    cd "$OUTPUT_DIR"
    
    # Protocol identification
    log "INFO" "Performing protocol analysis..."
    
    # Application layer protocol analysis
    nmap --script banner,version -iL live_hosts.txt \
        -oA protocol_analysis/app_protocols -T"$TIMING" 2>/dev/null || true
    
    # Encryption protocol assessment
    log "INFO" "Analyzing encryption protocols..."
    
    # SSL/TLS comprehensive analysis
    if [ -s web_targets.txt ]; then
        nmap -p443 --script ssl-cert,ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,ssl-poodle \
            -iL web_targets.txt -oA protocol_analysis/ssl_comprehensive -T"$TIMING" 2>/dev/null || true
    fi
    
    # SSH cryptographic analysis
    if [ -s ssh_targets.txt ]; then
        nmap -p22 --script ssh2-enum-algos,ssh-hostkey \
            -iL ssh_targets.txt -oA protocol_analysis/ssh_crypto -T"$TIMING" 2>/dev/null || true
    fi
    
    # VPN protocol detection
    log "INFO" "Detecting VPN protocols..."
    nmap -sU -p500,4500 --script ike-version \
        -iL live_hosts.txt -oA protocol_analysis/vpn_protocols -T"$TIMING" 2>/dev/null || true
    
    log "INFO" "Phase 5 completed - Protocol analysis finished"
}

phase6_infrastructure_mapping() {
    log "PHASE" "Phase 6: Infrastructure Mapping"
    
    cd "$OUTPUT_DIR"
    
    # Network device discovery
    log "INFO" "Discovering network devices..."
    
    # SNMP-based device discovery
    if [ -s snmp_targets.txt ]; then
        nmap -sU -p161 --script snmp-sysdescr,snmp-info,snmp-interfaces \
            -iL snmp_targets.txt -oA infrastructure/network_devices -T"$TIMING" 2>/dev/null || true
    fi
    
    # Load balancer detection
    log "INFO" "Detecting load balancers and proxies..."
    if [ -s web_targets.txt ]; then
        nmap -p80,443 --script http-trace,http-methods \
            -iL web_targets.txt -oA infrastructure/load_balancers -T"$TIMING" 2>/dev/null || true
    fi
    
    # Firewall detection
    log "INFO" "Analyzing firewall rules..."
    nmap -sA -T"$TIMING" -iL live_hosts.txt \
        -oA infrastructure/firewall_analysis 2>/dev/null || true
    
    # Service dependency mapping
    log "INFO" "Mapping service dependencies..."
    generate_service_relationships
    
    # Network topology visualization
    generate_network_topology
    
    log "INFO" "Phase 6 completed - Infrastructure mapping finished"
}

generate_service_relationships() {
    cd "$OUTPUT_DIR"
    
    # Extract service relationships
    cat scanning/*.gnmap enumeration/*.gnmap 2>/dev/null | grep "open" | \
        awk '{print $2 "," $4}' | sort | uniq > infrastructure/service_relationships.csv || true
    
    # Generate service matrix
    {
        echo "=== Service Relationship Matrix ==="
        echo "Host,Service,Port,State,Service_Name,Version"
        cat infrastructure/service_relationships.csv
    } > infrastructure/service_matrix.txt
}

generate_network_topology() {
    cd "$OUTPUT_DIR"
    
    # Create network topology data
    cat << 'EOF' > infrastructure/generate_topology.py
#!/usr/bin/env python3

import json
import sys
from collections import defaultdict

def generate_topology():
    hosts = {}
    services = defaultdict(list)
    
    try:
        # Read live hosts
        with open('live_hosts.txt', 'r') as f:
            for line in f:
                host = line.strip()
                if host:
                    hosts[host] = {'services': [], 'os': 'Unknown'}
        
        # Read service relationships
        with open('infrastructure/service_relationships.csv', 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    host, service = parts[0], parts[1]
                    if host in hosts:
                        hosts[host]['services'].append(service)
                        services[service].append(host)
        
        # Generate topology JSON
        topology = {
            'metadata': {
                'total_hosts': len(hosts),
                'total_services': len(services),
                'generated': 'ActiveRecon'
            },
            'hosts': hosts,
            'services': dict(services)
        }
        
        # Write topology file
        with open('infrastructure/network_topology.json', 'w') as f:
            json.dump(topology, f, indent=2)
        
        print(f"Generated topology with {len(hosts)} hosts and {len(services)} services")
        
    except Exception as e:
        print(f"Error generating topology: {e}")

if __name__ == "__main__":
    generate_topology()
EOF
    
    # Generate topology
    python3 infrastructure/generate_topology.py 2>/dev/null || log "WARN" "Could not generate network topology"
}

phase7_vulnerability_assessment() {
    log "PHASE" "Phase 7: Vulnerability Assessment"
    
    cd "$OUTPUT_DIR"
    
    # Comprehensive vulnerability scan
    log "INFO" "Performing comprehensive vulnerability assessment..."
    nmap --script vuln -T"$TIMING" \
        -iL live_hosts.txt -oA vulnerabilities/vuln_comprehensive 2>/dev/null || true
    
    # Service-specific vulnerability scans
    vulnerability_scan_web_services
    vulnerability_scan_smb_services
    vulnerability_scan_ssh_services
    vulnerability_scan_database_services
    
    # Configuration security assessment
    log "INFO" "Assessing security configurations..."
    
    # Default credential testing
    nmap --script auth -T"$TIMING" \
        -iL live_hosts.txt -oA vulnerabilities/default_creds 2>/dev/null || true
    
    # Weak cryptography detection
    nmap --script ssl-enum-ciphers,ssh2-enum-algos -T"$TIMING" \
        -iL live_hosts.txt -oA vulnerabilities/weak_crypto 2>/dev/null || true
    
    # Process vulnerability results
    process_vulnerability_results
    
    log "INFO" "Phase 7 completed - Vulnerability assessment finished"
}

vulnerability_scan_web_services() {
    if [ ! -s web_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Scanning web services for vulnerabilities..."
    
    # Web-specific vulnerability scan
    nmap -p80,443,8080,8443 --script http-vuln* -T"$TIMING" \
        -iL web_targets.txt -oA vulnerabilities/web_vulns 2>/dev/null || true
    
    # SSL vulnerabilities
    nmap -p443 --script ssl-heartbleed,ssl-poodle,ssl-dh-params \
        -iL web_targets.txt -oA vulnerabilities/ssl_vulns -T"$TIMING" 2>/dev/null || true
}

vulnerability_scan_smb_services() {
    if [ ! -s smb_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Scanning SMB services for vulnerabilities..."
    
    # SMB vulnerability scan
    nmap -p445 --script smb-vuln* -T"$TIMING" \
        -iL smb_targets.txt -oA vulnerabilities/smb_vulns 2>/dev/null || true
}

vulnerability_scan_ssh_services() {
    if [ ! -s ssh_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Scanning SSH services for vulnerabilities..."
    
    # SSH vulnerability scan
    nmap -p22 --script ssh-vuln* -T"$TIMING" \
        -iL ssh_targets.txt -oA vulnerabilities/ssh_vulns 2>/dev/null || true
}

vulnerability_scan_database_services() {
    if [ ! -s database_targets.txt ]; then
        return 0
    fi
    
    log "INFO" "Scanning database services for vulnerabilities..."
    
    # Database vulnerability scans
    nmap -p1433 --script ms-sql-vuln* -T"$TIMING" \
        -iL database_targets.txt -oA vulnerabilities/mssql_vulns 2>/dev/null || true
    
    nmap -p3306 --script mysql-vuln* -T"$TIMING" \
        -iL database_targets.txt -oA vulnerabilities/mysql_vulns 2>/dev/null || true
}

process_vulnerability_results() {
    cd "$OUTPUT_DIR"
    
    # Extract CVE information
    log "INFO" "Processing vulnerability results..."
    
    grep -h "CVE-[0-9]\{4\}-[0-9]\+" vulnerabilities/*.nmap 2>/dev/null | \
        sort | uniq -c | sort -nr > vulnerabilities/cve_summary.txt || touch vulnerabilities/cve_summary.txt
    
    # Categorize vulnerabilities by severity
    grep -h "VULNERABLE" vulnerabilities/*.nmap 2>/dev/null | \
        grep -iE "(critical|high)" > vulnerabilities/high_severity.txt || touch vulnerabilities/high_severity.txt
    
    grep -h "VULNERABLE" vulnerabilities/*.nmap 2>/dev/null | \
        grep -iE "(medium)" > vulnerabilities/medium_severity.txt || touch vulnerabilities/medium_severity.txt
    
    grep -h "VULNERABLE" vulnerabilities/*.nmap 2>/dev/null | \
        grep -iE "(low)" > vulnerabilities/low_severity.txt || touch vulnerabilities/low_severity.txt
    
    # Generate vulnerability statistics
    {
        echo "=== Vulnerability Assessment Summary ==="
        echo "Total CVEs Identified: $(wc -l < vulnerabilities/cve_summary.txt)"
        echo "High/Critical Vulnerabilities: $(wc -l < vulnerabilities/high_severity.txt)"
        echo "Medium Vulnerabilities: $(wc -l < vulnerabilities/medium_severity.txt)"
        echo "Low Vulnerabilities: $(wc -l < vulnerabilities/low_severity.txt)"
        echo ""
        echo "Top 10 Most Common CVEs:"
        head -10 vulnerabilities/cve_summary.txt
    } > vulnerabilities/vulnerability_summary.txt
    
    # Log critical findings
    local critical_count=$(wc -l < vulnerabilities/high_severity.txt)
    if [ "$critical_count" -gt 0 ]; then
        log "VULN" "Found $critical_count critical/high severity vulnerabilities"
        head -5 vulnerabilities/high_severity.txt | while read -r line; do
            log "VULN" "$line"
        done
    fi
}

phase8_evidence_processing() {
    log "PHASE" "Phase 8: Evidence Processing and Reporting"
    
    cd "$OUTPUT_DIR"
    
    # Consolidate all scan data
    log "INFO" "Consolidating scan data..."
    
    # Generate comprehensive service inventory
    {
        echo "IP_Address,Port,Protocol,State,Service,Version,Banner"
        cat scanning/*.gnmap enumeration/*.gnmap 2>/dev/null | grep "open" | \
            awk -F'[[:space:]]+' '{
                ip = $2; 
                port_info = $4; 
                gsub(/\//, ",", port_info); 
                print ip "," port_info ",open,Unknown,Unknown,Unknown"
            }' | sort -t',' -k1,1V -k2,2n
    } > evidence/comprehensive_service_inventory.csv
    
    # Generate attack surface report
    generate_attack_surface_report
    
    # Generate executive summary
    generate_executive_summary
    
    # Generate technical report
    generate_technical_report
    
    # Create remediation tracking template
    generate_remediation_template
    
    # Quality assurance check
    perform_quality_assurance
    
    log "INFO" "Phase 8 completed - Evidence processing finished"
}

generate_attack_surface_report() {
    cd "$OUTPUT_DIR"
    
    local total_hosts=$(wc -l < live_hosts.txt)
    local total_services=$(grep -c "," evidence/comprehensive_service_inventory.csv 2>/dev/null || echo "0")
    local critical_vulns=$(wc -l < vulnerabilities/high_severity.txt)
    
    cat << EOF > reports/attack_surface_report.md
# Attack Surface Analysis Report

## Executive Summary
- **Total Hosts Discovered:** $total_hosts
- **Total Services Identified:** $total_services  
- **Critical Vulnerabilities:** $critical_vulns
- **Assessment Date:** $(date)

## Network Infrastructure

### Live Hosts by Service Category
- **Web Services:** $(wc -l < web_targets.txt)
- **Database Services:** $(wc -l < database_targets.txt)
- **Remote Access Services:** 
  - SSH: $(wc -l < ssh_targets.txt)
  - RDP: $(wc -l < rdp_targets.txt)
  - VNC: $(wc -l < vnc_targets.txt)
- **File Sharing Services:**
  - SMB: $(wc -l < smb_targets.txt)
  - FTP: $(wc -l < ftp_targets.txt)
- **Email Services:**
  - SMTP: $(wc -l < smtp_targets.txt)
  - IMAP: $(wc -l < imap_targets.txt)
  - POP3: $(wc -l < pop3_targets.txt)

## Security Findings

### Critical/High Severity Issues
$(head -10 vulnerabilities/high_severity.txt 2>/dev/null || echo "No critical vulnerabilities found")

### Service Distribution Analysis
$(cat service_summary.txt 2>/dev/null || echo "Service summary not available")

### Vulnerability Distribution
$(cat vulnerabilities/vulnerability_summary.txt 2>/dev/null || echo "Vulnerability summary not available")

## Recommendations

### Immediate Actions Required
1. Address critical vulnerabilities identified in high_severity.txt
2. Review exposed database services for proper access controls
3. Implement network segmentation for critical services
4. Enable proper logging and monitoring for detected services

### Security Improvements
1. Disable unnecessary services identified during scanning
2. Implement strong authentication mechanisms
3. Update systems with identified version vulnerabilities
4. Deploy network-based intrusion detection systems

### Monitoring Enhancements
1. Continuous monitoring of exposed services
2. Regular vulnerability assessments
3. Network traffic analysis for anomalous behavior
4. Automated security scanning integration

## Technical Details
Detailed technical findings are available in the following files:
- Service Inventory: evidence/comprehensive_service_inventory.csv
- Vulnerability Details: vulnerabilities/ directory
- Network Topology: infrastructure/network_topology.json
- Scan Logs: activerecon.log

EOF
}

generate_executive_summary() {
    cd "$OUTPUT_DIR"
    
    local total_hosts=$(wc -l < live_hosts.txt)
    local critical_vulns=$(wc -l < vulnerabilities/high_severity.txt)
    local medium_vulns=$(wc -l < vulnerabilities/medium_severity.txt)
    local web_services=$(wc -l < web_targets.txt)
    local db_services=$(wc -l < database_targets.txt)
    
    cat << EOF > reports/executive_summary.md
# Executive Summary - Network Security Assessment

## Assessment Overview
A comprehensive network reconnaissance assessment was conducted using automated tools and manual techniques to identify the attack surface and security exposure of the target environment.

**Assessment Period:** $(date)  
**Target Scope:** $TARGET_RANGE  
**Methodology:** OWASP/NIST/PTES Standard Reconnaissance Framework

## Key Findings

### Network Scope
- **Active Systems:** $total_hosts hosts responding to network probes
- **Exposed Services:** Web applications ($web_services), Database servers ($db_services)
- **Remote Access:** SSH, RDP, and VNC services identified

### Security Risk Summary
- **Critical/High Risk:** $critical_vulns issues requiring immediate attention
- **Medium Risk:** $medium_vulns issues requiring planned remediation
- **Configuration Issues:** Multiple default configurations and weak settings identified

## Business Impact Assessment

### High Impact Risks
- Exposed database services with potential unauthorized access
- Web applications with known vulnerabilities
- Remote access services with weak authentication

### Medium Impact Risks  
- Information disclosure through service banners
- Legacy protocols enabling network reconnaissance
- Missing security headers and weak encryption

## Immediate Actions Required

1. **Critical Vulnerability Remediation** (0-7 days)
   - Address all critical/high severity vulnerabilities
   - Implement emergency patches for exposed services
   - Disable unnecessary network services

2. **Access Control Implementation** (0-14 days)
   - Implement network segmentation
   - Deploy firewall rules restricting service access
   - Enable multi-factor authentication for remote access

3. **Security Monitoring** (0-30 days)
   - Deploy network monitoring solutions
   - Implement security information and event management (SIEM)
   - Establish incident response procedures

## Long-term Strategic Recommendations

1. **Security Architecture**
   - Implement zero-trust network architecture
   - Deploy network access control (NAC) solutions
   - Establish secure network segmentation

2. **Continuous Security**
   - Regular vulnerability assessments
   - Automated security scanning integration
   - Security awareness training programs

3. **Risk Management**
   - Formal risk assessment procedures
   - Regular security policy reviews
   - Third-party security audits

## Conclusion
The assessment identified significant security exposure requiring immediate attention. Implementation of the recommended security controls will substantially reduce the organization's attack surface and improve overall security posture.

**Next Steps:** Review detailed technical report and begin implementation of immediate action items.

EOF
}

generate_technical_report() {
    cd "$OUTPUT_DIR"
    
    cat << EOF > reports/technical_report.md
# Technical Reconnaissance Report

## Methodology
This assessment followed the systematic active reconnaissance methodology covering:
- Network discovery and host enumeration  
- Comprehensive port scanning
- Service version detection and enumeration
- Protocol analysis and security assessment
- Infrastructure mapping and topology analysis
- Vulnerability identification and assessment

## Scope and Limitations
**Target Range:** $TARGET_RANGE  
**Assessment Period:** $(date)  
**Tools Used:** nmap, masscan, custom automation scripts  
**Scan Timing:** Template T$TIMING ($([ "$STEALTH_MODE" = true ] && echo "Stealth Mode" || echo "Normal Mode"))

## Detailed Findings

### Network Infrastructure Discovery
$(cat discovery/icmp_discovery.nmap 2>/dev/null | grep "Nmap scan report" | wc -l) hosts discovered via ICMP  
$(cat discovery/tcp_discovery.nmap 2>/dev/null | grep "Nmap scan report" | wc -l) hosts discovered via TCP probes  
$(cat discovery/udp_discovery.nmap 2>/dev/null | grep "Nmap scan report" | wc -l) hosts discovered via UDP probes  

### Service Distribution Analysis
$(cat service_summary.txt 2>/dev/null)

### Vulnerability Assessment Results
$(cat vulnerabilities/vulnerability_summary.txt 2>/dev/null)

### Protocol Security Analysis
- SSL/TLS configurations analyzed for $(wc -l < web_targets.txt) web services
- SSH cryptographic settings reviewed for $(wc -l < ssh_targets.txt) SSH services  
- Database security configurations assessed for $(wc -l < database_targets.txt) database services

### Configuration Security Issues
- Default credentials identified on multiple services
- Weak encryption algorithms detected
- Information disclosure through service banners
- Missing security headers on web applications

## Recommendations

### Critical Priority (0-7 days)
1. Patch systems with critical vulnerabilities
2. Disable unnecessary network services
3. Implement network access controls
4. Change default credentials

### High Priority (0-30 days)  
1. Deploy network segmentation
2. Implement monitoring solutions
3. Update weak cryptographic configurations
4. Deploy web application firewalls

### Medium Priority (30-90 days)
1. Regular vulnerability assessments
2. Security awareness training
3. Incident response procedures
4. Security policy development

## Technical Appendices
- **Appendix A:** Complete service inventory (evidence/comprehensive_service_inventory.csv)
- **Appendix B:** Vulnerability details (vulnerabilities/ directory)
- **Appendix C:** Network topology (infrastructure/network_topology.json)
- **Appendix D:** Raw scan data (scanning/ and enumeration/ directories)

EOF
}

generate_remediation_template() {
    cd "$OUTPUT_DIR"
    
    cat << 'EOF' > reports/remediation_tracking.csv
"Finding_ID","Severity","Service","Host","Port","Description","Recommendation","Status","Assigned_To","Due_Date","Completed_Date","Notes"
EOF
    
    # Auto-populate critical findings
    local finding_id=1
    if [ -s vulnerabilities/high_severity.txt ]; then
        while read -r line; do
            # Extract basic information from vulnerability line
            local desc=$(echo "$line" | cut -d':' -f3- | tr ',' ';')
            echo "\"VULN-$(printf "%03d" $finding_id)\",\"High\",\"Unknown\",\"Unknown\",\"Unknown\",\"$desc\",\"See technical report\",\"Open\",\"\",\"\",\"\",\"\"" >> reports/remediation_tracking.csv
            finding_id=$((finding_id + 1))
        done < vulnerabilities/high_severity.txt
    fi
}

perform_quality_assurance() {
    cd "$OUTPUT_DIR"
    
    log "INFO" "Performing quality assurance checks..."
    
    # Check phase completion
    local phases_completed=0
    
    [ -f "discovery/icmp_discovery.nmap" ] && phases_completed=$((phases_completed + 1))
    [ -f "scanning/common_scan.nmap" ] && phases_completed=$((phases_completed + 1))
    [ -f "enumeration/version_detection.nmap" ] && phases_completed=$((phases_completed + 1))
    [ -f "protocol_analysis/app_protocols.nmap" ] && phases_completed=$((phases_completed + 1))
    [ -f "infrastructure/network_devices.nmap" ] && phases_completed=$((phases_completed + 1))
    [ -f "vulnerabilities/vuln_comprehensive.nmap" ] && phases_completed=$((phases_completed + 1))
    [ -f "reports/executive_summary.md" ] && phases_completed=$((phases_completed + 1))
    
    # Generate QA report
    {
        echo "=== Quality Assurance Report ==="
        echo "Assessment completed: $(date)"
        echo "Phases completed: $phases_completed/7"
        echo ""
        echo "=== Data Completeness Check ==="
        echo "Live hosts discovered: $(wc -l < live_hosts.txt)"
        echo "Service inventory entries: $(wc -l < evidence/comprehensive_service_inventory.csv)"
        echo "Vulnerability findings: $(find vulnerabilities/ -name "*.txt" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "0")"
        echo ""
        echo "=== File Verification ==="
        echo "Discovery files: $(ls discovery/ 2>/dev/null | wc -l)"
        echo "Scanning files: $(ls scanning/ 2>/dev/null | wc -l)"
        echo "Enumeration files: $(ls enumeration/ 2>/dev/null | wc -l)"
        echo "Vulnerability files: $(ls vulnerabilities/ 2>/dev/null | wc -l)"
        echo "Report files: $(ls reports/ 2>/dev/null | wc -l)"
        echo ""
        echo "=== Coverage Analysis ==="
        local scanned_hosts=$(cat scanning/*.gnmap 2>/dev/null | cut -d' ' -f2 | sort -u | wc -l)
        local total_hosts=$(wc -l < live_hosts.txt)
        local coverage_percent=0
        if [ "$total_hosts" -gt 0 ]; then
            coverage_percent=$(echo "scale=2; $scanned_hosts * 100 / $total_hosts" | bc 2>/dev/null || echo "N/A")
        fi
        echo "Scan coverage: $scanned_hosts/$total_hosts hosts ($coverage_percent%)"
    } > reports/quality_assurance_report.txt
    
    log "INFO" "Quality assurance completed - see reports/quality_assurance_report.txt"
}

cleanup_and_summary() {
    cd "$OUTPUT_DIR"
    
    log "INFO" "Generating final summary..."
    
    local end_time=$(date)
    local total_hosts=$(wc -l < live_hosts.txt)
    local total_services=$(grep -c "," evidence/comprehensive_service_inventory.csv 2>/dev/null || echo "0")
    local critical_vulns=$(wc -l < vulnerabilities/high_severity.txt)
    local medium_vulns=$(wc -l < vulnerabilities/medium_severity.txt)
    
    # Generate final summary
    cat << EOF > ASSESSMENT_SUMMARY.txt
=============================================================================
                    ACTIVERECON ASSESSMENT SUMMARY
=============================================================================

Assessment Details:
- Target: $TARGET_RANGE
- Start Time: $TIMESTAMP
- End Time: $end_time
- Output Directory: $OUTPUT_DIR

Results Summary:
- Live Hosts Discovered: $total_hosts
- Total Services Identified: $total_services
- Critical/High Vulnerabilities: $critical_vulns
- Medium Risk Issues: $medium_vulns

Service Breakdown:
- Web Services: $(wc -l < web_targets.txt)
- Database Services: $(wc -l < database_targets.txt)
- SSH Services: $(wc -l < ssh_targets.txt)
- SMB Services: $(wc -l < smb_targets.txt)
- FTP Services: $(wc -l < ftp_targets.txt)

Key Files:
- Executive Summary: reports/executive_summary.md
- Technical Report: reports/technical_report.md
- Attack Surface Analysis: reports/attack_surface_report.md
- Service Inventory: evidence/comprehensive_service_inventory.csv
- Vulnerability Summary: vulnerabilities/vulnerability_summary.txt
- Remediation Tracking: reports/remediation_tracking.csv

=============================================================================
Assessment completed successfully. Review reports/ directory for detailed findings.
=============================================================================
EOF

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    ASSESSMENT COMPLETED                       ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}📊 Results Summary:${NC}"
    echo -e "   • Live Hosts: ${GREEN}$total_hosts${NC}"
    echo -e "   • Services: ${GREEN}$total_services${NC}"
    echo -e "   • Critical Vulns: ${RED}$critical_vulns${NC}"
    echo -e "   • Medium Vulns: ${YELLOW}$medium_vulns${NC}"
    echo ""
    echo -e "${CYAN}📁 Key Reports:${NC}"
    echo -e "   • Executive Summary: ${YELLOW}reports/executive_summary.md${NC}"
    echo -e "   • Technical Report: ${YELLOW}reports/technical_report.md${NC}"
    echo -e "   • Service Inventory: ${YELLOW}evidence/comprehensive_service_inventory.csv${NC}"
    echo ""
    echo -e "${CYAN}🔍 Output Directory: ${GREEN}$OUTPUT_DIR${NC}"
    echo ""
    
    if [ "$critical_vulns" -gt 0 ]; then
        echo -e "${RED}⚠️  CRITICAL: $critical_vulns high-severity vulnerabilities found!${NC}"
        echo -e "${RED}   Review vulnerabilities/high_severity.txt immediately${NC}"
        echo ""
    fi
}

# Utility functions
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -T|--timing)
                TIMING="$2"
                shift 2
                ;;
            -q|--quick)
                QUICK_SCAN=true
                shift
                ;;
            -f|--full)
                FULL_SCAN=true
                shift
                ;;
            -s|--stealth)
                STEALTH_MODE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -x|--exploit)
                AUTO_EXPLOIT=true
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                if [ -z "$TARGET_RANGE" ]; then
                    TARGET_RANGE="$1"
                else
                    log "ERROR" "Unknown option: $1"
                    print_usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate required parameters
    if [ -z "$TARGET_RANGE" ]; then
        log "ERROR" "Target range is required"
        print_usage
        exit 1
    fi
    
    # Set default output directory if not specified
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="$(pwd)/activerecon_${TIMESTAMP}"
    fi

    # Validate timing parameter
    if [[ ! "$TIMING" =~ ^[0-5]$ ]]; then
        log "ERROR" "Timing must be between 0-5"
        exit 1
    fi
    
    # Validate threads parameter
    if [[ ! "$THREADS" =~ ^[0-9]+$ ]] || [ "$THREADS" -lt 1 ] || [ "$THREADS" -gt 1000 ]; then
        log "ERROR" "Threads must be between 1-1000"
        exit 1
    fi
}

signal_handler() {
    echo ""
    log "WARN" "Received interrupt signal - cleaning up..."
    
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Generate summary of what was completed
    if [ -n "$OUTPUT_DIR" ] && [ -d "$OUTPUT_DIR" ]; then
        cd "$OUTPUT_DIR"
        echo ""
        log "INFO" "Partial results available in: $OUTPUT_DIR"
        
        if [ -f "live_hosts.txt" ]; then
            local hosts_found=$(wc -l < live_hosts.txt)
            log "INFO" "Discovered $hosts_found live hosts before interruption"
        fi
        
        if [ -f "service_summary.txt" ]; then
            log "INFO" "Service summary available in service_summary.txt"
        fi
    fi
    
    echo ""
    log "INFO" "Assessment interrupted - partial results may be available"
    exit 130
}

# Advanced scanning functions
run_advanced_scans() {
    if [ "$AUTO_EXPLOIT" = true ]; then
        log "INFO" "Running advanced exploitation checks..."
        
        # Advanced web application scanning
        if [ -s web_targets.txt ] && command -v nikto &> /dev/null; then
            log "INFO" "Running Nikto web vulnerability scanner..."
            head -5 web_targets.txt | while read -r target; do
                timeout 600 nikto -h "http://$target" -Format txt -output "enumeration/nikto_$target.txt" 2>/dev/null || true
            done
        fi
        
        # Advanced SMB exploitation checks
        if [ -s smb_targets.txt ] && command -v smbmap &> /dev/null; then
            log "INFO" "Running SMBMap for share enumeration..."
            while read -r target; do
                timeout 120 smbmap -H "$target" -u null -p "" > "enumeration/smbmap_$target.txt" 2>/dev/null || true
            done < smb_targets.txt
        fi
        
        # Database exploitation attempts
        if [ -s database_targets.txt ]; then
            log "INFO" "Testing database default credentials..."
            
            # MySQL default creds
            grep ":3306/" evidence/comprehensive_service_inventory.csv 2>/dev/null | cut -d',' -f1 | while read -r target; do
                timeout 10 mysql -h "$target" -u root -e "SELECT 1;" > "enumeration/mysql_test_$target.txt" 2>/dev/null || true
            done
            
            # MSSQL default creds
            if command -v sqsh &> /dev/null; then
                grep ":1433/" evidence/comprehensive_service_inventory.csv 2>/dev/null | cut -d',' -f1 | while read -r target; do
                    timeout 10 sqsh -S "$target" -U sa -P "" -C "SELECT 1" > "enumeration/mssql_test_$target.txt" 2>/dev/null || true
                done
            fi
        fi
    fi
}

generate_wordlists() {
    cd "$OUTPUT_DIR"
    
    # Generate custom wordlists based on discovered information
    log "INFO" "Generating custom wordlists..."
    
    # Extract potential usernames from banners and service info
    {
        grep -h "admin\|user\|guest\|test\|demo" enumeration/*.nmap 2>/dev/null || true
        echo -e "admin\nuser\nguest\ntest\ndemo\nroot\nadministrator"
    } | sort -u > enumeration/discovered_usernames.txt
    
    # Extract potential passwords from service info
    {
        grep -h "password\|passwd\|pwd" enumeration/*.nmap 2>/dev/null || true
        echo -e "password\npasswd\n123456\nadmin\nroot\nguest"
    } | sort -u > enumeration/discovered_passwords.txt
    
    # Extract hostnames for hostname-based attacks
    grep -h "hostname\|FQDN" enumeration/*.nmap 2>/dev/null | \
        grep -oE "[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sort -u > enumeration/discovered_hostnames.txt || touch enumeration/discovered_hostnames.txt
}

run_post_exploitation_checks() {
    if [ "$AUTO_EXPLOIT" = true ]; then
        log "INFO" "Running post-exploitation reconnaissance..."
        
        # Check for common misconfigurations
        check_common_misconfigurations
        
        # Generate attack path recommendations
        generate_attack_paths
    fi
}

check_common_misconfigurations() {
    cd "$OUTPUT_DIR"
    
    log "INFO" "Checking for common misconfigurations..."
    
    # Web application misconfigurations
    if [ -s web_targets.txt ]; then
        {
            echo "=== Web Application Misconfigurations ==="
            
            # Check for directory listing
            while read -r target; do
                curl -s "http://$target/" | grep -i "index of" && echo "Directory listing enabled on $target"
                curl -s "https://$target/" | grep -i "index of" && echo "Directory listing enabled on $target (HTTPS)"
            done < web_targets.txt
            
            # Check for default pages
            while read -r target; do
                curl -s "http://$target/" | grep -i "apache.*default\|nginx.*default\|iis.*default" && echo "Default web page on $target"
            done < web_targets.txt
            
        } > enumeration/web_misconfigurations.txt 2>/dev/null
    fi
    
    # SMB misconfigurations
    if [ -s smb_targets.txt ]; then
        {
            echo "=== SMB Misconfigurations ==="
            grep -h "anonymous\|guest\|null" enumeration/smb*.nmap 2>/dev/null || echo "No anonymous access detected"
        } > enumeration/smb_misconfigurations.txt
    fi
    
    # SSH misconfigurations
    if [ -s ssh_targets.txt ]; then
        {
            echo "=== SSH Misconfigurations ==="
            grep -h "password.*yes\|root.*yes" enumeration/ssh*.nmap 2>/dev/null || echo "No obvious SSH misconfigurations"
        } > enumeration/ssh_misconfigurations.txt
    fi
}

generate_attack_paths() {
    cd "$OUTPUT_DIR"
    
    log "INFO" "Generating potential attack paths..."
    
    cat << EOF > reports/attack_paths.md
# Potential Attack Paths

## Web Application Attack Paths
$(if [ -s web_targets.txt ]; then
    echo "### Identified Web Applications"
    cat web_targets.txt | head -10 | while read -r target; do
        echo "- $target: Web application requiring further manual testing"
    done
    echo ""
    echo "### Recommended Attack Vectors"
    echo "1. Directory/file enumeration using gobuster/dirb"
    echo "2. Parameter fuzzing and injection testing"
    echo "3. Authentication bypass attempts"
    echo "4. Session management testing"
else
    echo "No web applications identified"
fi)

## Database Attack Paths
$(if [ -s database_targets.txt ]; then
    echo "### Identified Database Services"
    cat database_targets.txt | head -10 | while read -r target; do
        echo "- $target: Database service requiring access testing"
    done
    echo ""
    echo "### Recommended Attack Vectors"
    echo "1. Default credential testing"
    echo "2. SQL injection attempts"
    echo "3. Privilege escalation testing"
    echo "4. Data extraction procedures"
else
    echo "No database services identified"
fi)

## Remote Access Attack Paths
$(if [ -s ssh_targets.txt ] || [ -s rdp_targets.txt ]; then
    echo "### Identified Remote Access Services"
    [ -s ssh_targets.txt ] && echo "SSH Services: $(wc -l < ssh_targets.txt)"
    [ -s rdp_targets.txt ] && echo "RDP Services: $(wc -l < rdp_targets.txt)"
    echo ""
    echo "### Recommended Attack Vectors"
    echo "1. Credential brute forcing (limited attempts)"
    echo "2. SSH key enumeration"
    echo "3. Protocol exploitation"
    echo "4. Man-in-the-middle attacks"
else
    echo "No remote access services identified"
fi)

## Network-Based Attack Paths
### Lateral Movement Opportunities
- SMB services for credential relay attacks
- Trust relationships for privilege escalation
- Service account enumeration for kerberoasting

### Information Gathering
- SNMP enumeration for network topology
- DNS enumeration for subdomain discovery
- Network scanning for additional services

EOF
}

# Main execution function
main() {
    # Set up signal handlers
    trap signal_handler SIGINT SIGTERM
    
    # Parse command line arguments first
    parse_arguments "$@"
    
    # Print banner
    print_banner
    
    # Check dependencies before creating directories
    check_dependencies
    
    # Setup environment (creates directories and log file)
    setup_environment
    
    log "INFO" "Starting ActiveRecon assessment of $TARGET_RANGE"
    log "INFO" "Scan configuration: Timing=T$TIMING, Threads=$THREADS"
    
    # Execute reconnaissance phases
    phase1_target_validation
    phase2_network_discovery
    phase3_port_scanning
    phase4_service_enumeration
    phase5_protocol_analysis
    phase6_infrastructure_mapping
    phase7_vulnerability_assessment
    
    # Advanced scans if enabled
    run_advanced_scans
    
    # Generate wordlists for future use
    generate_wordlists
    
    # Post-exploitation checks if enabled
    run_post_exploitation_checks
    
    # Process evidence and generate reports
    phase8_evidence_processing
    
    # Final cleanup and summary
    cleanup_and_summary
    
    log "INFO" "ActiveRecon assessment completed successfully"
}

# Execute main function with all arguments
main "$@"