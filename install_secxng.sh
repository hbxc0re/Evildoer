#!/usr/bin/env bash
# ==============================================================================
# Hardened SecXNG & OSINT Reconnaissance Appliance - Master Installer
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}[*] Starting SecXNG Appliance Deployment & Tool Installation...${NC}"

# 1. System Updates & Prerequisites
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y curl git ca-certificates gnupg lsb-release ufw fail2ban jq openssl golang-go python3-pip python3-dnspython python3-requests python3-setuptools libimage-exiftool-perl bsdmainutils pipx

# 2. Firewall Hardening (UFW)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.0.0/16 to any port 22 proto tcp comment 'LAN SSH'
sudo ufw allow from 192.168.0.0/16 to any port 80 proto tcp comment 'LAN HTTP'
sudo ufw allow from 192.168.0.0/16 to any port 443 proto tcp comment 'LAN HTTPS'
sudo ufw --force enable

# 3. Install Docker Engine & Compose v2
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER

# 4. Setup Project Directory at /opt/secxng
sudo mkdir -p /opt/secxng/searxng /opt/secxng/caddy_data /opt/secxng/caddy_config /opt/secxng/valkey_data
sudo chown -R $USER:$USER /opt/secxng
cd /opt/secxng

# 5. Write Configuration Files
cat << 'EOF' > docker-compose.yml
services:
  valkey:
    image: docker.io/valkey/valkey:8-alpine
    container_name: secxng-valkey
    restart: unless-stopped
    command: valkey-server --save 30 1 --loglevel warning
    volumes:
      - ./valkey_data:/data
    networks:
      secxng_net:
        ipv4_address: 172.30.0.11
    cap_drop:
      - ALL
    cap_add:
      - SETGID
      - SETUID
      - DAC_OVERRIDE

  tor-proxy:
    image: docker.io/library/alpine:latest
    container_name: secxng-tor
    restart: unless-stopped
    command: >
      sh -c "apk add --no-cache tor && echo 'SocksPort 0.0.0.0:9050' > /etc/tor/torrc && exec tor -f /etc/tor/torrc"
    networks:
      secxng_net:
        ipv4_address: 172.30.0.10

  searxng:
    image: docker.io/searxng/searxng:latest
    container_name: secxng-core
    restart: unless-stopped
    depends_on:
      - valkey
      - tor-proxy
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - ./searxng:/etc/searxng:rw
    environment:
      - SEARXNG_BASE_URL=http://localhost:8080/
      - UWSGI_WORKERS=2
      - UWSGI_THREADS=2
    networks:
      secxng_net:
        ipv4_address: 172.30.0.12
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID

  caddy:
    image: docker.io/library/caddy:2-alpine
    container_name: secxng-caddy
    restart: unless-stopped
    depends_on:
      - searxng
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy_data:/data
      - ./caddy_config:/config
    networks:
      secxng_net:
        ipv4_address: 172.30.0.13

networks:
  secxng_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
EOF

cat << 'EOF' > Caddyfile
:80 {
    reverse_proxy 172.30.0.12:8080 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
    }
}
EOF

cat << 'EOF' > searxng/settings.yml
use_default_settings: true

server:
  bind_address: "0.0.0.0"
  port: 8080
  secret_key: "REPLACE_WITH_SECRET"
  limiter: false
  image_proxy: true
  method: "POST"

search:
  safe_search: 0
  autocomplete: ""
  formats:
    - html
    - json
    - csv
    - rss

outgoing:
  request_timeout: 20.0
  max_request_timeout: 40.0
  useragent_suffix: ""
  proxies:
    all://:
      - socks5h://172.30.0.10:9050
  using_tor_proxy: true

valkey:
  url: valkey://172.30.0.11:6379/0

categories_as_tabs:
  general:
  security:
  osint:
  files:
  repos:

engines:
  - name: nvd
    engine: xpath
    shortcut: cve
    categories: [security]
    search_url: "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={query}"
    url_xpath: '//table[@data-testid="vuln-results-table"]//a[starts-with(@data-testid, "vuln-detail-link-")]/@href'
    title_xpath: '//table[@data-testid="vuln-results-table"]//a[starts-with(@data-testid, "vuln-detail-link-")]'
    content_xpath: '//table[@data-testid="vuln-results-table"]//p[starts-with(@data-testid, "vuln-summary-")]'
    disabled: false
    timeout: 15.0
    proxy: false

  - name: crtsh
    engine: json_engine
    shortcut: crt
    categories: [osint, security]
    search_url: "https://crt.sh/?q={query}&output=json"
    url_prefix: "https://crt.sh/?id="
    results_query: ""
    url_query: "id"
    title_query: "common_name"
    content_query: "name_value"
    disabled: false
    timeout: 15.0
    proxy: false

  - name: open-directories
    engine: brave
    shortcut: dir
    categories: [files, osint]
    disabled: false
    proxy: true

  - name: exploit-db-dork
    engine: brave
    shortcut: edb
    categories: [security]
    disabled: false
    proxy: true

  - name: gist-leaks
    engine: brave
    shortcut: gist
    categories: [osint, repos]
    disabled: false
    proxy: true

  - name: pastebin-dork
    engine: brave
    shortcut: paste
    categories: [osint]
    disabled: false
    proxy: true

  - name: gtfobins
    engine: duckduckgo
    shortcut: gtfo
    categories: [security, it]
    search_url: "https://html.duckduckgo.com/html/?q=site:gtfobins.github.io+{query}"
    disabled: false
    proxy: true

  - name: hacktricks
    engine: duckduckgo
    shortcut: ht
    categories: [security]
    search_url: "https://html.duckduckgo.com/html/?q=site:book.hacktricks.xyz+{query}"
    disabled: false
    proxy: true
EOF

cat << 'EOF' > dorks.txt
# Format: CATEGORY | SEARXNG_QUERY_TEMPLATE
# {{TARGET}} is automatically replaced with the domain passed via -d
# ===
# 1. Passive Recon & Asset Discovery
subdomains | !go bi site:*.{{TARGET}} -site:www.{{TARGET}} -site:mail.{{TARGET}} -site:blog.{{TARGET}}
cloud_storage | !go bi (site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com) "{{TARGET}}"
api_endpoints | !go !br site:{{TARGET}} (inurl:swagger OR inurl:api-docs OR inurl:graphql OR filetype:wsdl)

# 2. OSINT & Public Exposure Auditing
documents | !go bi site:{{TARGET}} (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx)
code_leaks | !gh "{{TARGET}}" (extension:env OR extension:yml OR extension:pem OR "DB_PASSWORD" OR "AWS_SECRET_ACCESS_KEY")
paste_dumps | !go (site:pastebin.com OR site:rentry.co) "{{TARGET}}"

# 3. Configuration & Surface Checks
open_dirs | !go bi site:{{TARGET}} intitle:"index of /" ("parent directory" OR "backup" OR ".env" OR ".git")
config_files | !go bi site:{{TARGET}} (ext:env OR ext:log OR ext:bak OR ext:sql OR ext:conf OR ext:ini)
admin_portals | !go !br site:{{TARGET}} (inurl:admin OR inurl:login OR inurl:portal OR inurl:grafana OR inurl:jenkins)
error_traces | !go site:{{TARGET}} ("SQL syntax" OR "PostgreSQL query failed" OR "ORA-01756")
EOF

cat << 'EOF' > searxng-dorker.sh
#!/usr/bin/env bash
# searxng-dorker.sh - Automated OSINT & Exposure Auditing via SearXNG JSON API
set -euo pipefail

SEARXNG_URL="${SEARXNG_URL:-http://127.0.0.1:8080}"
DORK_FILE="dorks.txt"
TARGET=""
OUTPUT_DIR="./recon_results_$(date +%Y%m%d_%H%M%S)"
MIN_DELAY=3
MAX_DELAY=8
MAX_PAGES=2
TIME_RANGE=""

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

usage() {
    echo "Usage: $(basename "$0") -d <target_domain> [OPTIONS]"
    echo "  -d <domain>    Authorized target domain (Required)"
    echo "  -f <file>      Path to query list file (Default: dorks.txt)"
    echo "  -u <url>       SearXNG base URL (Default: http://127.0.0.1:8080)"
    echo "  -o <dir>       Output directory"
    echo "  -p <pages>     Max result pages per query (Default: 2)"
    echo "  -j <min:max>   Jitter delay range in seconds (Default: 3:8)"
    exit 1
}

while getopts "d:f:u:o:p:j:t:h" opt; do
    case "$opt" in
        d) TARGET="$OPTARG";;
        f) DORK_FILE="$OPTARG";;
        u) SEARXNG_URL="${OPTARG%/}";;
        o) OUTPUT_DIR="$OPTARG";;
        p) MAX_PAGES="$OPTARG";;
        j) MIN_DELAY="${OPTARG%:*}"; MAX_DELAY="${OPTARG#*:}";;
        t) TIME_RANGE="$OPTARG";;
        h|*) usage;;
    esac
done

[[ -z "$TARGET" ]] && { echo -e "${RED}[!] Error: Target (-d) is required.${NC}"; usage; }
[[ ! -f "$DORK_FILE" ]] && { echo -e "${RED}[!] Error: File '$DORK_FILE' not found.${NC}"; exit 1; }

for cmd in curl jq awk sort; do
    command -v "$cmd" &>/dev/null || { echo -e "${RED}[!] Missing dependency: $cmd${NC}"; exit 1; }
done

mkdir -p "$OUTPUT_DIR/raw_json"

echo -e "${CYAN}[*] Verifying SearXNG JSON API at ${SEARXNG_URL}...${NC}"
HTTP_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "${SEARXNG_URL}/search?q=test&format=json" || true)
if [ "$HTTP_CHECK" -ne 200 ]; then
    echo -e "${RED}[!] API check failed (HTTP $HTTP_CHECK). Verify 'json' is enabled in settings.yml.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] SearXNG JSON API online. Auditing target: $TARGET${NC}"

sleep_jitter() {
    local sleep_time
    sleep_time=$(awk -v min="$MIN_DELAY" -v max="$MAX_DELAY" 'BEGIN{srand(); printf "%.2f", min+rand()*(max-min)}')
    echo -e "${YELLOW}[-] Jitter cooldown: sleeping ${sleep_time}s...${NC}"
    sleep "$sleep_time"
}

QUERY_COUNT=0
while IFS='|' read -r raw_cat raw_dork || [[ -n "$raw_cat" ]]; do
    category=$(echo "$raw_cat" | xargs)
    dork_template=$(echo "${raw_dork:-}" | xargs)
    [[ -z "$category" || "$category" =~ ^# ]] && continue
    [[ -z "$dork_template" ]] && continue

    safe_cat=$(echo "$category" | tr '[:upper:]' '[:lower:]' | tr '[:space:]_' '-')
    cat_url_file="${OUTPUT_DIR}/${safe_cat}_urls.txt"
    cat_meta_file="${OUTPUT_DIR}/raw_json/${safe_cat}_results.jsonl"
    query="${dork_template//\{\{TARGET\}\}/$TARGET}"
    
    ((QUERY_COUNT+=1))
    echo -e "${CYAN}[#${QUERY_COUNT}] Category:${NC} ${safe_cat} | ${CYAN}Query:${NC} ${query}"

    for ((page=1; page<=MAX_PAGES; page++)); do
        curl_args=(
            -s -G "${SEARXNG_URL}/search"
            --data-urlencode "q=${query}"
            --data-urlencode "format=json"
            --data-urlencode "pageno=${page}"
        )
        [ -n "$TIME_RANGE" ] && curl_args+=(--data-urlencode "time_range=${TIME_RANGE}")

        response=$(curl "${curl_args[@]}" -w "\n%{http_code}")
        http_code=$(tail -n1 <<< "$response")
        body=$(sed '$ d' <<< "$response")

        if [ "$http_code" -eq 429 ]; then
            echo -e "${RED}[!] HTTP 429 Rate Limit! Cooling down 30s...${NC}"
            sleep 30; continue
        elif [[ "$http_code" -ne 200 ]]; then
            echo -e "${RED}[!] HTTP ${http_code} on page ${page}. Skipping...${NC}"
            break
        fi

        hit_count=$(echo "$body" | jq '.results | length // 0' 2>/dev/null || echo 0)
        if [ "$hit_count" -eq 0 ]; then
            echo -e "    [-] Page ${page}: 0 results"
            break
        fi

        echo -e "${GREEN}    [+] Page ${page}: Extracted ${hit_count} hits${NC}"
        echo "$body" | jq -r '.results[]?.url // empty' >> "$cat_url_file"
        echo "$body" | jq -c --arg dork "$query" '.results[]? | {url: .url, title: .title, engines: .engines, dork: $dork, snippet: .content}' >> "$cat_meta_file"
        sleep_jitter
    done
done < "$DORK_FILE"

echo -e "\n${CYAN}[*] Deduplicating results by category...${NC}"
ALL_URLS_FILE="${OUTPUT_DIR}/ALL_DEDUPED_URLS.txt"
touch "$ALL_URLS_FILE"
for file in "${OUTPUT_DIR}"/*_urls.txt; do
    [[ -e "$file" ]] || continue
    total_raw=$(wc -l < "$file")
    sort -u "$file" -o "$file"
    total_unique=$(wc -l < "$file")
    cat "$file" >> "$ALL_URLS_FILE"
    base_name=$(basename "$file" _urls.txt)
    printf "  %-20s %4d unique URLs (from %d raw hits)\n" "$base_name" "$total_unique" "$total_raw"
done
sort -u "$ALL_URLS_FILE" -o "$ALL_URLS_FILE"
HOSTS_FILE="${OUTPUT_DIR}/EXTRACTED_HOSTS.txt"
awk -F/ '{print $3}' "$ALL_URLS_FILE" | sort -u > "$HOSTS_FILE"

echo -e "\n${GREEN}[+] Collection complete! Output saved to: ${OUTPUT_DIR}${NC}"
EOF

cat << 'EOF' > searxng-postproc.sh
#!/usr/bin/env bash
# searxng-postproc.sh - Sublist3r, httpx, ExifTool Metadata Audit, and Nuclei Vulnerability Scan
set -euo pipefail

RECON_DIR=""
TARGET_DOMAIN=""
THREADS=25
RATE_LIMIT=50
PROXY_URL=""
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

usage() {
    echo "Usage: $(basename "$0") -i <recon_results_dir> -d <target_domain> [OPTIONS]"
    echo "  -i <dir>       Input directory generated by searxng-dorker.sh (Required)"
    echo "  -d <domain>    Target domain for Sublist3r passive enumeration (Required)"
    echo "  -t <threads>   Concurrency threads for httpx (Default: 25)"
    echo "  -r <rate>      Rate limit (req/sec) for httpx (Default: 50)"
    echo "  -x <proxy>     Optional HTTP/SOCKS5 proxy URL (e.g., socks5://127.0.0.1:9050)"
    exit 1
}

while getopts "i:d:t:r:x:h" opt; do
    case "$opt" in
        i) RECON_DIR="${OPTARG%/}";;
        d) TARGET_DOMAIN="$OPTARG";;
        t) THREADS="$OPTARG";;
        r) RATE_LIMIT="$OPTARG";;
        x) PROXY_URL="$OPTARG";;
        h|*) usage;;
    esac
done

[[ -z "$RECON_DIR" || ! -d "$RECON_DIR" ]] && { echo -e "${RED}[!] Valid input directory (-i) required.${NC}"; usage; }
[[ -z "$TARGET_DOMAIN" ]] && { echo -e "${RED}[!] Target domain (-d) required for Sublist3r integration.${NC}"; usage; }

for cmd in curl jq exiftool httpx sublist3r nuclei; do
    command -v "$cmd" &>/dev/null || { echo -e "${RED}[!] Missing required tool: $cmd${NC}"; exit 1; }
done

POST_DIR="${RECON_DIR}/post_analysis"
DOC_DIR="${POST_DIR}/downloaded_docs"
mkdir -p "$POST_DIR" "$DOC_DIR"

# --- PHASE 0: Subdomain Enumeration via Sublist3r ---
SUBLIST3R_OUT="${POST_DIR}/sublist3r_subdomains.txt"
HOSTS_FILE="${RECON_DIR}/EXTRACTED_HOSTS.txt"

echo -e "${CYAN}[*] Phase 0: Running Sublist3r passive subdomain enumeration for ${TARGET_DOMAIN}...${NC}"
sublist3r -d "$TARGET_DOMAIN" -t 40 -o "$SUBLIST3R_OUT" 2>/dev/null || true

if [[ -s "$SUBLIST3R_OUT" ]]; then
    sub_count=$(wc -l < "$SUBLIST3R_OUT")
    echo -e "${GREEN}[+] Sublist3r discovered $sub_count subdomains. Merging into target host list...${NC}"
    cat "$SUBLIST3R_OUT" >> "$HOSTS_FILE"
    sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
fi

# --- PHASE 1: Live Host Verification with httpx ---
HTTPX_JSON="${POST_DIR}/httpx_live_hosts.jsonl"
HTTPX_TXT="${POST_DIR}/httpx_summary.txt"
LIVE_URLS_TXT="${POST_DIR}/live_urls.txt"

if [[ -s "$HOSTS_FILE" ]]; then
    host_count=$(wc -l < "$HOSTS_FILE")
    echo -e "\n${CYAN}[*] Phase 1: Probing $host_count total hostnames with httpx...${NC}"
    httpx_args=(
        -l "$HOSTS_FILE" -silent -status-code -title -tech-detect -web-server -ip
        -follow-host-redirects -threads "$THREADS" -rl "$RATE_LIMIT"
        -H "User-Agent: ${USER_AGENT}" -json -o "$HTTPX_JSON"
    )
    [ -n "$PROXY_URL" ] && httpx_args+=(-http-proxy "$PROXY_URL")
    
    httpx "${httpx_args[@]}" > /dev/null || true

    if [[ -s "$HTTPX_JSON" ]]; then
        jq -r '[.url, ("[" + (.status_code|tostring) + "]"), (.title // "No Title"), (.webserver // "Unknown"), ((.tech // []) | join(","))] | @tsv' "$HTTPX_JSON" | column -t -s $'\t' > "$HTTPX_TXT"
        jq -r '.url' "$HTTPX_JSON" > "$LIVE_URLS_TXT"
        echo -e "${GREEN}[+] Live host summary saved to: ${HTTPX_TXT}${NC}"
    fi
fi

# --- PHASE 2: Public Document Metadata Auditing with ExifTool ---
ALL_URLS="${RECON_DIR}/ALL_DEDUPED_URLS.txt"
DOC_URLS_FILE="${POST_DIR}/target_document_urls.txt"

echo -e "\n${CYAN}[*] Phase 2: Identifying public documents for metadata inspection...${NC}"
{
    [[ -f "${RECON_DIR}/documents_urls.txt" ]] && cat "${RECON_DIR}/documents_urls.txt"
    [[ -f "$ALL_URLS" ]] && grep -iE '\.(pdf|docx?|xlsx?|pptx?|odt|ods|rtf)(\?.*)?$' "$ALL_URLS" || true
} | sort -u > "$DOC_URLS_FILE"

doc_count=$(wc -l < "$DOC_URLS_FILE")
if [ "$doc_count" -gt 0 ]; then
    dl_count=0
    while IFS= read -r url || [[ -n "$url" ]]; do
        [[ -z "$url" ]] && continue
        clean_url="${url%%\?*}"
        base_name=$(basename "$clean_url")
        url_hash=$(echo -n "$url" | md5sum | cut -c1-8)
        safe_filename="${url_hash}_${base_name}"
        target_path="${DOC_DIR}/${safe_filename:0:120}"

        curl_dl_args=(-s -L -fail --max-time 20 --max-filesize 26214400 -A "$USER_AGENT" -o "$target_path")
        [ -n "$PROXY_URL" ] && curl_dl_args+=(-x "$PROXY_URL")

        if curl "${curl_dl_args[@]}" "$url" 2>/dev/null && [[ -s "$target_path" ]]; then
            ((dl_count+=1))
        else
            rm -f "$target_path"
        fi
    done < "$DOC_URLS_FILE"

    if [[ "$dl_count" -gt 0 ]]; then
        EXIF_CSV="${POST_DIR}/exif_metadata_report.csv"
        EXIF_JSON="${POST_DIR}/exif_metadata_full.json"
        exiftool -j -r "$DOC_DIR" > "$EXIF_JSON" 2>/dev/null || true
        exiftool -csv -r -FileName -FileType -Author -Creator -LastModifiedBy -CreatorTool -Software -Company -CreateDate -ModifyDate -Producer "$DOC_DIR" > "$EXIF_CSV" 2>/dev/null || true
    fi
fi

# --- PHASE 3: Vulnerability Scanning with Nuclei ---
NUCLEI_OUT="${POST_DIR}/nuclei_vulns.txt"
if [[ -s "$LIVE_URLS_TXT" ]]; then
    echo -e "\n${CYAN}[*] Phase 3: Running Nuclei vulnerability scan on live targets...${NC}"
    nuclei -list "$LIVE_URLS_TXT" -severity low,medium,high,critical -silent -o "$NUCLEI_OUT" || true
    echo -e "${GREEN}[+] Vulnerability scan results saved to: ${NUCLEI_OUT}${NC}"
fi

echo -e "\n${GREEN}[+] Full recon pipeline and post-analysis complete! Reports saved in: ${POST_DIR}${NC}"
EOF

# 6. Secure Secret Key Injection & Permissions
sed -i "s/REPLACE_WITH_SECRET/$(openssl rand -hex 32)/g" searxng/settings.yml
sudo chown -R 977:977 searxng
sudo chown -R 999:999 valkey_data 2>/dev/null || sudo chmod -R 777 valkey_data

# 7. Install Security CLI Tools (httpx, nuclei, sublist3r, penelope)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo ln -sf ~/go/bin/httpx /usr/local/bin/httpx
sudo ln -sf ~/go/bin/nuclei /usr/local/bin/nuclei

sudo git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r || true
sudo pip3 install -r /opt/Sublist3r/requirements.txt --break-system-packages || true
sudo ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
sudo ln -sf /usr/bin/python3 /usr/local/bin/python

pipx install git+https://github.com/brightio/penelope || true
sudo ln -sf ~/.local/bin/penelope /usr/local/bin/penelope 2>/dev/null || true

# 8. Make Scripts Executable & Launch Docker Stack
chmod +x searxng-dorker.sh searxng-postproc.sh
docker compose down && docker compose up -d

echo -e "${GREEN}[+] SecXNG Appliance Deployment Complete! All containers are running and tools are installed.${NC}"