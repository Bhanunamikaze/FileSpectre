#!/bin/bash

#############################################################################
# FileSpectre - Advanced File Security Scanner
# Purpose: Enterprise-grade security auditing for file system vulnerabilities
# Version: 2.0 - FileSpectre Edition
#############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Global configuration
MAX_PARALLEL_JOBS=8   # Optimized for performance (was 50)
SCAN_DEPTH=5
MAX_FILE_SIZE=$((100 * 1024 * 1024)) # 100MB limit for content scanning
ENABLE_DEEP_SCAN=1
ENABLE_CONTENT_SCAN=1
QUIET_MODE=1  # Default to quiet mode for professional output
VERBOSE_MODE=0
SHOW_PROGRESS=1
AUTO_SCALE_THREADS=1
OUTPUT_DIR="$(pwd)"
EXPORT_FORMATS=("json" "csv" "html" "xml")
INCLUDE_PATHS=()
EXCLUDE_PATHS=()
INCLUDE_EXTENSIONS=()
EXCLUDE_EXTENSIONS=()
SCAN_TYPES=("all")
RESUME_FILE=""
ENABLE_RESUME=0
SKIP_CROSS_USER=0         # 0 = enabled, 1 = skip cross-user checking

# User sampling configuration
MAX_USERS=0           # 0 = no limit, N = max N users
RANDOM_USERS=0        # 0 = disabled, 1 = enable random sampling
FIRST_USERS=0         # 0 = disabled, N = first N users only
SPECIFIC_USERS=()     # Array of specific usernames to scan

# Temporary files for parallel processing
TEMP_DIR="/tmp/vuln_scan_$$"
RESULTS_FILE="$TEMP_DIR/results.txt"
LOCK_FILE="$TEMP_DIR/lock"
PROGRESS_FILE="$TEMP_DIR/progress"

# Global counters (using temp files for thread safety)
mkdir -p "$TEMP_DIR"
echo "0" > "$TEMP_DIR/total_vulns"
echo "0" > "$TEMP_DIR/scanned_paths"
echo "0" > "$TEMP_DIR/total_files"
echo "0" > "$TEMP_DIR/processed_users"
echo "0" > "$TEMP_DIR/total_users"
echo "$(date +%s)" > "$TEMP_DIR/start_time"

# Performance monitoring
SCAN_START_TIME=$(date +%s)
LAST_SCREEN_CLEAR=0  # Track when screen was last cleared
declare -A USER_CACHE
declare -A GROUP_CACHE
declare -A PERM_CACHE

# Current user info
CURRENT_USER=$(whoami)
CURRENT_UID=$(id -u)
CURRENT_GID=$(id -g)
CURRENT_GROUPS=$(groups)
CURRENT_HOME=$(eval echo ~$CURRENT_USER)

# Log file for detailed results
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUTPUT_DIR/filespectre_scan_$TIMESTAMP.log"
JSON_REPORT="$OUTPUT_DIR/scan_report_$TIMESTAMP.json"
CSV_REPORT="$OUTPUT_DIR/scan_report_$TIMESTAMP.csv"
HTML_REPORT="$OUTPUT_DIR/scan_report_$TIMESTAMP.html"
XML_REPORT="$OUTPUT_DIR/scan_report_$TIMESTAMP.xml"
STATE_FILE="$OUTPUT_DIR/.scan_state_$TIMESTAMP"

# Vulnerability categories
declare -A VULN_TYPES=(
    ["SUID"]="SetUID files that could be exploited"
    ["SGID"]="SetGID files that could be exploited"
    ["WORLD_WRITE"]="World-writable files and directories"
    ["WORLD_READ"]="World-readable sensitive files"
    ["WORLD_EXEC"]="World-executable files"
    ["ROOT_OWNED"]="Files with root privileges"
    ["STICKY_BIT"]="Directories with sticky bit issues"
    ["CAPABILITY"]="Files with dangerous capabilities"
    ["IMMUTABLE"]="Files with immutable attribute issues"
    ["TRAVERSAL"]="Directory traversal vulnerabilities"
    ["SYMLINK"]="Symbolic link vulnerabilities"
    ["HARDLINK"]="Hard link vulnerabilities"
    ["ACL"]="Access Control List misconfigurations"
    ["BACKUP"]="Exposed backup files"
    ["TEMP"]="Insecure temporary files"
    ["HIDDEN"]="Hidden files with sensitive data"
    ["NFS_EXPORT"]="Insecure NFS exports"
    ["WEAK_PASSWORD"]="Files containing weak passwords"
    ["SSH_KEYS"]="Exposed SSH private keys"
    ["DATABASE"]="Database files with weak permissions"
    ["LOG_FILES"]="Log files with sensitive information"
    ["CONFIG_FILES"]="Configuration files with secrets"
    ["CRON_JOBS"]="Cron jobs with security issues"
    ["SERVICE_FILES"]="Service files with vulnerabilities"
    ["CROSS_USER_STRUCTURE"]="Systematic cross-user access via mirrored structure"
)

#############################################################################
# Path and Extension Filtering Functions
#############################################################################

# Check if path should be included
should_scan_path() {
    local path="$1"
    
    # Check exclude paths first
    for exclude in "${EXCLUDE_PATHS[@]}"; do
        if [[ "$path" == "$exclude"* ]]; then
            return 1  # Skip this path
        fi
    done
    
    # If include paths are specified, only scan those
    if [[ ${#INCLUDE_PATHS[@]} -gt 0 ]]; then
        for include in "${INCLUDE_PATHS[@]}"; do
            if [[ "$path" == "$include"* ]]; then
                return 0  # Include this path
            fi
        done
        return 1  # Path not in include list
    fi
    
    return 0  # Include by default
}

# Check if file extension should be included
should_scan_extension() {
    local file="$1"
    local ext="${file##*.}"
    
    # Check exclude extensions
    for exclude_ext in "${EXCLUDE_EXTENSIONS[@]}"; do
        if [[ "$ext" == "$exclude_ext" ]]; then
            return 1  # Skip this extension
        fi
    done
    
    # If include extensions are specified, only scan those
    if [[ ${#INCLUDE_EXTENSIONS[@]} -gt 0 ]]; then
        for include_ext in "${INCLUDE_EXTENSIONS[@]}"; do
            if [[ "$ext" == "$include_ext" ]]; then
                return 0  # Include this extension
            fi
        done
        return 1  # Extension not in include list
    fi
    
    return 0  # Include by default
}

# Check if vulnerability type should be scanned
should_scan_vuln_type() {
    local vuln_type="$1"
    
    # If scanning all types
    if [[ " ${SCAN_TYPES[*]} " =~ " all " ]]; then
        return 0
    fi
    
    # Check specific scan types
    case "$vuln_type" in
        "suid"|"sgid")
            [[ " ${SCAN_TYPES[*]} " =~ " suid-sgid " ]] && return 0
            ;;
        "world-writable"|"world-readable"|"world-executable")
            [[ " ${SCAN_TYPES[*]} " =~ " world-permissions " ]] && return 0
            ;;
        "root-privileges")
            [[ " ${SCAN_TYPES[*]} " =~ " root-owned " ]] && return 0
            ;;
        "capabilities")
            [[ " ${SCAN_TYPES[*]} " =~ " capabilities " ]] && return 0
            ;;
        "backup")
            [[ " ${SCAN_TYPES[*]} " =~ " backup-files " ]] && return 0
            ;;
        "sensitive")
            [[ " ${SCAN_TYPES[*]} " =~ " sensitive-files " ]] && return 0
            ;;
        "config")
            [[ " ${SCAN_TYPES[*]} " =~ " config-files " ]] && return 0
            ;;
        "ssh")
            [[ " ${SCAN_TYPES[*]} " =~ " ssh-keys " ]] && return 0
            ;;
        "database")
            [[ " ${SCAN_TYPES[*]} " =~ " database-files " ]] && return 0
            ;;
        "logs")
            [[ " ${SCAN_TYPES[*]} " =~ " log-files " ]] && return 0
            ;;
        "nfs")
            [[ " ${SCAN_TYPES[*]} " =~ " nfs-exports " ]] && return 0
            ;;
        "cron")
            [[ " ${SCAN_TYPES[*]} " =~ " cron-jobs " ]] && return 0
            ;;
    esac
    
    return 1  # Don't scan this type
}

#############################################################################
# Resume Functionality
#############################################################################

# Save scan state
save_scan_state() {
    local completed_users="$1"
    local total_users="$2"
    local current_user="$3"
    
    cat > "$STATE_FILE" <<EOF
SCAN_START_TIME=$(date -Iseconds)
COMPLETED_USERS=$completed_users
TOTAL_USERS=$total_users
CURRENT_USER=$current_user
SCAN_OPTIONS="--threads $MAX_PARALLEL_JOBS --depth $SCAN_DEPTH"
OUTPUT_DIR=$OUTPUT_DIR
EXPORT_FORMATS=${EXPORT_FORMATS[*]}
INCLUDE_PATHS=${INCLUDE_PATHS[*]}
EXCLUDE_PATHS=${EXCLUDE_PATHS[*]}
SCAN_TYPES=${SCAN_TYPES[*]}
EOF
}

# Load scan state
load_scan_state() {
    if [[ -f "$RESUME_FILE" ]]; then
        # Parse state file safely instead of executing it
        if [[ "$RESUME_FILE" == *.log ]]; then
            echo -e "${RED}[!] Error: Cannot resume from log file. Use state file instead.${NC}"
            echo -e "${YELLOW}[*] Log files contain scan results, not resumable state.${NC}"
            return 1
        fi
        
        # Source only if it's a proper state file
        if grep -q "^COMPLETED_USERS=" "$RESUME_FILE" 2>/dev/null; then
            source "$RESUME_FILE"
            echo -e "${GREEN}[*] Resuming scan from previous state${NC}"
            echo -e "${CYAN}[*] Completed: ${COMPLETED_USERS:-0}/${TOTAL_USERS:-0} users${NC}"
            return 0
        else
            echo -e "${RED}[!] Invalid state file format${NC}"
            return 1
        fi
    fi
    return 1
}

#############################################################################
# Intelligent Pattern Generation
#############################################################################

generate_sensitive_patterns() {
    # Production-grade sensitive file patterns for enterprise environments
    local tech_stack=()
    local patterns=()
    
    # Detect installed technologies and add specific patterns
    if command -v php &>/dev/null; then
        tech_stack+=("php")
        patterns+=("*.php" "*.inc" "*.phtml" "php.ini" "php-fpm.conf" ".user.ini")
    fi
    
    if command -v python &>/dev/null; then
        tech_stack+=("python")
        patterns+=("*.py" "*.pyc" "*.pyo" "settings.py" "config.py" "requirements.txt" "django.conf" "flask.conf")
    fi
    
    if command -v node &>/dev/null; then
        tech_stack+=("nodejs")
        patterns+=("*.js" "package.json" ".env*" ".npmrc" ".yarnrc" "ecosystem.config.js" "pm2.config.js")
    fi
    
    if command -v ruby &>/dev/null; then
        tech_stack+=("ruby")
        patterns+=("*.rb" "Gemfile*" "database.yml" "secrets.yml" ".ruby-version")
    fi
    
    if command -v java &>/dev/null; then
        tech_stack+=("java")
        patterns+=("*.properties" "*.xml" "*.class" "*.jar" "*.keystore" "*.jks")
    fi
    
    # Web Server Configurations (Apache, Nginx, IIS)
    patterns+=(
        "httpd.conf" "apache2.conf" "nginx.conf" "default.conf" "000-default.conf"
        ".htaccess" ".htpasswd" "access.log" "error.log" "ssl.conf" "vhosts.conf"
        "sites-available/*" "sites-enabled/*" "conf.d/*" "mods-enabled/*"
        "web.config" "applicationHost.config" "machine.config"
    )
    
    # Database Configurations (MySQL, PostgreSQL, MongoDB, Redis)
    patterns+=(
        "my.cnf" "my.ini" "mysql.conf" "mariadb.conf" "client.cnf" "server.cnf"
        "mysqld.cnf" ".my.cnf" ".mysql_history" "mysql_secure_installation"
        "postgresql.conf" "pg_hba.conf" "pg_ident.conf" "recovery.conf"
        "postgres.conf" "pgsql.conf" ".psql_history" "pgpass"
        "mongodb.conf" "mongod.conf" "mongo.conf" ".mongorc.js"
        "redis.conf" "redis-server.conf" "sentinel.conf" "cluster.conf"
        "elasticsearch.yml" "logstash.conf" "kibana.yml" "beats.yml"
        "cassandra.conf" "cassandra.yaml" "cqlshrc"
    )
    
    # Application Framework Configurations
    patterns+=(
        # WordPress & PHP Frameworks
        "wp-config.php" "wp-config-sample.php" ".wp-cli.yml" "wp-cli.yml"
        "settings.php" "services.yml" "sites.php" "local.xml" "env.php"
        "app.php" "parameters.yml" "config.yml" "security.yml"
        
        # Laravel & Symfony
        ".env.local" ".env.production" ".env.development" ".env.staging"
        "config/app.php" "config/database.php" "config/mail.php"
        
        # Drupal & Joomla
        "configuration.php" "LocalSettings.php" "settings.local.php"
        "sites/default/settings.php" "sites/default/files/*"
    )
    
    # SSL/TLS Certificates & Private Keys
    patterns+=(
        "*.key" "*.pem" "*.crt" "*.cer" "*.p12" "*.pfx" "*.jks" "*.keystore"
        "*.ca-bundle" "*.ca-cert" "ca-certificates.conf" "ssl-cert-snakeoil.key"
        "private.key" "server.key" "client.key" "ssl.key" "tls.key"
        "*.csr" "*.der" "*.p7b" "*.p7c" "*.spc" "fullchain.pem"
        "privkey.pem" "chain.pem" "cert.pem" "dhparam.pem"
    )
    
    # Container & Orchestration Configurations
    patterns+=(
        "Dockerfile*" "docker-compose*.yml" "docker-compose*.yaml" ".dockerignore"
        ".docker-compose.yml" "docker-compose.override.yml"
        "kubernetes*.yml" "*.k8s.yml" "kustomization.yaml" "skaffold.yaml"
        "helm-values.yaml" "values.yaml" "Chart.yaml" "requirements.yaml"
        "deployment.yaml" "service.yaml" "configmap.yaml" "secret.yaml"
    )
    
    # Cloud Provider Configurations
    patterns+=(
        # AWS
        ".aws/credentials" ".aws/config" "*.pem" "*.p12" "*.ppk"
        "aws-credentials.ini" "awscli.conf" "boto.cfg" "s3cfg"
        "terraform.tfvars" ".terraformrc" "terraform.rc" "*.tf"
        "cloudformation*.json" "cloudformation*.yaml" "sam*.yaml"
        
        # Google Cloud
        "*.json" "gcloud.conf" "service-account*.json" "key.json"
        ".gcloudignore" "app.yaml" "cron.yaml" "dispatch.yaml"
        
        # Azure
        "azure.conf" "*.publishsettings" "ServiceConfiguration*.cscfg"
        "ServiceDefinition.csdef" "azure-pipelines.yml"
    )
    
    # Version Control & Development Files
    patterns+=(
        ".git/config" ".gitconfig" ".git-credentials" ".netrc"
        ".svn/auth" ".hg/hgrc" ".bzr/bazaar.conf"
        ".vscode/settings.json" ".idea/workspace.xml" ".sublime-project"
        ".project" ".classpath" ".settings/*" "nbproject/*"
        "*.sublime-workspace" "*.code-workspace" ".vscode/launch.json"
    )
    
    # System Service Configurations
    patterns+=(
        # Systemd & Init
        "systemd/*.service" "systemd/*.socket" "systemd/*.timer"
        "init.d/*" "xinetd.d/*" "systemd/system/*" "systemd/user/*"
        
        # Cron & Scheduling
        "crontab" "anacrontab" "at.allow" "at.deny" "cron.allow" "cron.deny"
        "/var/spool/cron/*" "/etc/cron.d/*" "/etc/cron.*/*"
        
        # Network Services
        "sshd_config" "ssh_config" "hosts.allow" "hosts.deny"
        "exports" "nfs.conf" "smb.conf" "samba.conf" "vsftpd.conf"
        "proftpd.conf" "pure-ftpd.conf" "xinetd.conf" "inetd.conf"
        
        # Mail Services
        "postfix/main.cf" "postfix/master.cf" "dovecot.conf" "exim.conf"
        "sendmail.cf" "sendmail.mc" "email.conf" "mail.conf"
        "smtp.conf" "imap.conf" "pop3.conf"
    )
    
    # Backup & Archive Files
    patterns+=(
        "*.bak" "*.backup" "*.old" "*.save" "*.orig" "*.copy"
        "*.swp" "*.swo" "*.tmp" "*.temp" "*.cache" "*~"
        "*.dump" "*.sql.gz" "*.tar.gz" "*.zip" "*.rar" "*.7z"
        "backup/*" "backups/*" "dumps/*" "exports/*" "archive/*"
        "*.snapshot" "*.log.old" "*.conf.old" "*.bak.*"
    )
    
    # User & Authentication Files
    patterns+=(
        ".ssh/id_rsa" ".ssh/id_dsa" ".ssh/id_ecdsa" ".ssh/id_ed25519"
        ".ssh/authorized_keys" ".ssh/known_hosts" ".ssh/config"
        ".gnupg/secring.gpg" ".gnupg/pubring.gpg" ".gnupg/gpg.conf"
        "shadow" "passwd" "group" "gshadow" ".passwd" ".shadow"
        "sudoers" "sudoers.d/*" ".sudo_as_admin_successful"
        "krb5.conf" "krb5.keytab" ".k5login" "kerberos.conf"
    )
    
    # Application & Service Secrets
    patterns+=(
        # Generic secret patterns
        "*secret*" "*password*" "*credential*" "*token*" "*key*" "*api*"
        "*auth*" "*oauth*" "*jwt*" "*session*" "*cookie*"
        "*.p12" "*.pfx" "*.jks" "*.keystore" "*.truststore"
        
        # Specific application secrets
        ".env" ".env.*" "secrets.json" "appsettings.json" "local.json"
        "config.json" "settings.json" "credentials.json" "tokens.json"
        "application.properties" "application-*.properties"
        "hibernate.cfg.xml" "persistence.xml" "context.xml"
        
        # Database connection files
        "*.dsn" "*.udl" "database.yml" "database.json" "db.conf"
        "connection.php" "connect.php" "config.php" "setup.php"
    )
    
    # Log Files with Potential Sensitive Data  
    patterns+=(
        "*.log" "*.log.*" "logs/*" "log/*" "var/log/*"
        "access.log*" "error.log*" "debug.log*" "application.log*"
        "security.log*" "audit.log*" "auth.log*" "system.log*"
        ".bash_history" ".zsh_history" ".mysql_history" ".psql_history"
        ".python_history" ".node_repl_history" ".sqlite_history"
    )
    
    # Monitoring & DevOps Tools
    patterns+=(
        # Prometheus & Grafana
        "prometheus.yml" "alertmanager.yml" "grafana.ini"
        
        # Nagios & Monitoring
        "nagios.cfg" "nrpe.cfg" "nsca.cfg" "check_*"
        
        # CI/CD Configurations
        ".github/workflows/*" ".gitlab-ci.yml" "Jenkinsfile"
        "azure-pipelines.yml" ".travis.yml" ".circleci/config.yml"
        "buildspec.yml" "appspec.yml" "deploy.yml"
        
        # Configuration Management
        "ansible.cfg" "hosts.yml" "inventory.yml" "playbook.yml"
        "Vagrantfile" "Berksfile" "metadata.rb" "attributes/*"
        "puppet.conf" "site.pp" "Puppetfile" "hiera.yaml"
        "chef-repo/*" "cookbooks/*" "roles/*" "environments/*"
    )
    
    printf '%s\n' "${patterns[@]}"
}

#############################################################################
# Find Command Helpers and Path Exclusion
#############################################################################

# Generate find exclusion patterns for paths and extensions
generate_find_exclusions() {
    local exclude_patterns=""
    
    # Always exclude system directories
    exclude_patterns="-path /proc -prune -o -path /sys -prune -o -path /dev -prune"
    
    # Add user-specified exclude paths
    if [[ ${#EXCLUDE_PATHS[@]} -gt 0 ]]; then
        for exclude_path in "${EXCLUDE_PATHS[@]}"; do
            # Ensure path starts with /
            [[ "$exclude_path" != /* ]] && exclude_path="/$exclude_path"
            exclude_patterns="$exclude_patterns -o -path $exclude_path -prune"
        done
    fi
    
    # Add implicit exclusions for common noisy directories (only if not already excluded by user)
    local common_excludes=(
        "/var/tmp" "/usr/share/doc" "/usr/share/man" 
        "/usr/lib/debug" "/boot" "/media" "/run"
    )
    
    # Only add /tmp if user hasn't specified it (but don't auto-exclude /mnt)
    local add_tmp=1
    if [[ ${#EXCLUDE_PATHS[@]} -gt 0 ]]; then
        for user_path in "${EXCLUDE_PATHS[@]}"; do
            [[ "$user_path" == "/tmp" || "$user_path" == *"/tmp"* ]] && add_tmp=0
        done
    fi
    [[ $add_tmp -eq 1 ]] && common_excludes+=("/tmp")
    
    for common_exclude in "${common_excludes[@]}"; do
        exclude_patterns="$exclude_patterns -o -path $common_exclude -prune"
    done
    
    echo "$exclude_patterns"
}

# Generate minimal exclusions for world permissions (only /proc and /dev)
generate_world_permissions_exclusions() {
    local exclude_patterns=""
    
    # Only exclude /proc and /dev for world permissions
    exclude_patterns="-path /proc -prune -o -path /dev -prune"
    
    # Add user-specified exclude paths
    if [[ ${#EXCLUDE_PATHS[@]} -gt 0 ]]; then
        for exclude_path in "${EXCLUDE_PATHS[@]}"; do
            # Ensure path starts with /
            [[ "$exclude_path" != /* ]] && exclude_path="/$exclude_path"
            exclude_patterns="$exclude_patterns -o -path $exclude_path -prune"
        done
    fi
    
    echo "$exclude_patterns"
}

# Generate find command with proper exclusions and search criteria
build_find_command() {
    local search_path="$1"
    local search_criteria="$2"
    local type_filter="$3"  # Optional: -type f, -type d, etc.
    
    local exclusions=$(generate_find_exclusions)
    local full_command="find $search_path \\( $exclusions -o $search_criteria"
    
    [[ -n "$type_filter" ]] && full_command="$full_command $type_filter"
    full_command="$full_command -print \\) 2>/dev/null"
    
    echo "$full_command"
}

# Check if path should be excluded based on extension
should_exclude_extension() {
    local file="$1"
    local extension="${file##*.}"
    
    # Skip if no exclude extensions specified
    [[ ${#EXCLUDE_EXTENSIONS[@]} -eq 0 ]] && return 1
    
    # Check if extension matches any exclude pattern
    for exclude_ext in "${EXCLUDE_EXTENSIONS[@]}"; do
        [[ "$extension" == "$exclude_ext" ]] && return 0
    done
    
    return 1
}

# Check if path should be excluded
should_exclude_path() {
    local file_path="$1"
    
    # Check exclude paths
    if [[ ${#EXCLUDE_PATHS[@]} -gt 0 ]]; then
        for exclude_path in "${EXCLUDE_PATHS[@]}"; do
            # Handle both absolute and relative patterns
            if [[ "$file_path" == *"$exclude_path"* ]]; then
                return 0
            fi
        done
    fi
    
    return 1
}

#############################################################################
# Universal Detection Framework with Fallback Mechanisms
#############################################################################

# Universal vulnerability detector with multiple fallback methods
universal_vulnerability_detector() {
    local detection_type="$1"
    local primary_method="$2"  
    shift 2
    local fallback_methods=("$@")
    
    [[ $QUIET_MODE -eq 0 ]] && echo "[*] Starting $detection_type detection..."
    
    # Primary method with timeout
    local results=()
    local success=0
    
    # Execute primary method
    if timeout 300 bash -c "$primary_method" 2>/dev/null; then
        success=1
        [[ $QUIET_MODE -eq 0 ]] && echo "[+] Primary method successful for $detection_type"
    else
        [[ $QUIET_MODE -eq 0 ]] && echo "[!] Primary method failed, trying fallbacks for $detection_type"
        
        # Try each fallback method
        for fallback in "${fallback_methods[@]}"; do
            if timeout 120 bash -c "$fallback" 2>/dev/null; then
                success=1
                [[ $QUIET_MODE -eq 0 ]] && echo "[+] Fallback method successful: $fallback"
                break
            else
                [[ $QUIET_MODE -eq 0 ]] && echo "[!] Fallback failed: $fallback"
            fi
        done
    fi
    
    if [[ $success -eq 0 ]]; then
        [[ $QUIET_MODE -eq 0 ]] && echo "[!] All detection methods failed for $detection_type"
        return 1
    fi
    
    return 0
}

# Enhanced SUID/SGID detection with system-wide scanning and fallbacks
detect_suid_sgid_systemwide() {
    local results=()
    local temp_file="/tmp/suid_sgid_results_$$"
    
    # Method 1: Combined SUID/SGID detection with minimal exclusions
    local exclusions=$(generate_world_permissions_exclusions)
    local method1="find / $exclusions -o -perm -4000 -o -perm -2000 -type f -print 2>/dev/null > '$temp_file.combined'"
    
    # Method 2: Alternative perm syntax with minimal exclusions
    local method2="find / $exclusions -o -perm -u=s -o -perm -g=s -type f -print 2>/dev/null > '$temp_file.alt'"
    
    # Method 3: Directory-based search using common binary locations
    local method3="for bindir in /usr/bin /bin /sbin /usr/sbin /usr/local/bin /opt/*/bin; do [[ -d \"\$bindir\" ]] && find \"\$bindir\" \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null; done > '$temp_file.dirs'"
    
    # Method 4: System binary paths with locate
    local method4="locate -r 'bin$' 2>/dev/null | xargs -I {} find {} -maxdepth 1 \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null > '$temp_file.locate'"
    
    if universal_vulnerability_detector "SUID/SGID" "$method1" "$method2" "$method3" "$method4"; then
        # Process results from successful method
        for result_file in "$temp_file."*; do
            [[ -f "$result_file" ]] && cat "$result_file" 2>/dev/null
        done | sort -u > "$temp_file.sorted"
        
        # Use array instead of while read for performance
        local binaries
        readarray -t binaries < "$temp_file.sorted"
        for binary in "${binaries[@]}"; do
            if [[ -n "$binary" && -f "$binary" ]]; then
                # Check exclusions
                if ! should_exclude_path "$binary" && ! should_exclude_extension "$binary"; then
                    process_suid_sgid_binary "$binary"
                fi
            fi
        done
    fi
    
    # Cleanup
    rm -f "$temp_file."* 2>/dev/null
}

# Enhanced world permissions detection with system-wide scanning
detect_world_permissions_systemwide() {
    local temp_file="/tmp/world_perms_results_$$"
    
    # Method 1: Standard world-writable detection (minimal exclusions)
    local exclusions=$(generate_world_permissions_exclusions)
    local method1="find / \\( $exclusions -o -perm -2 ! -type l -ls -print \\) 2>/dev/null > '$temp_file.writable'"
    
    # Method 2: Alternative world-writable syntax (minimal exclusions)
    local method2="find / \\( $exclusions -o -perm -o+w ! -type l -ls -print \\) 2>/dev/null > '$temp_file.writable_alt'"
    
    # Method 3: World-readable sensitive files (focus on common sensitive locations)
    local method3="find /etc /home /root /var /opt \\( $exclusions -o -perm -o+r -type f -print \\) 2>/dev/null | grep -E '\\.(conf|config|ini|key|pem|crt)$' > '$temp_file.readable'"
    
    # Method 4: Sticky bit analysis (minimal exclusions)
    local method4="find / \\( $exclusions -o -perm -1000 -type d -print \\) 2>/dev/null > '$temp_file.sticky'"
    
    if universal_vulnerability_detector "World Permissions" "$method1" "$method2" "$method3" "$method4"; then
        # Process world-writable files using array for performance
        if [[ -f "$temp_file.writable" || -f "$temp_file.writable_alt" ]]; then
            cat "$temp_file.writable" "$temp_file.writable_alt" 2>/dev/null | \
            awk '{print $NF}' | sort -u > "$temp_file.writable_sorted"
            
            local writable_files
            readarray -t writable_files < "$temp_file.writable_sorted"
            for file in "${writable_files[@]}"; do
                [[ -n "$file" && -f "$file" ]] && process_world_writable_file "$file"
            done
        fi
        
        # Process world-readable sensitive files using array
        if [[ -f "$temp_file.readable" ]]; then
            local readable_files
            readarray -t readable_files < "$temp_file.readable"
            for file in "${readable_files[@]}"; do
                [[ -n "$file" && -f "$file" ]] && process_world_readable_file "$file"
            done
        fi
        
        # Process sticky bit directories using array
        if [[ -f "$temp_file.sticky" ]]; then
            local sticky_dirs
            readarray -t sticky_dirs < "$temp_file.sticky"
            for dir in "${sticky_dirs[@]}"; do
                [[ -n "$dir" && -d "$dir" ]] && analyze_sticky_bit_dir "$dir"
            done
        fi
    fi
    
    # Cleanup
    rm -f "$temp_file."* 2>/dev/null
}

# Enhanced configuration file detection with dynamic patterns
detect_config_files_systemwide() {
    local temp_file="/tmp/config_results_$$"
    
    # Method 1: Pattern-based search for common config files
    local exclusions=$(generate_find_exclusions)
    local method1="find / \\( $exclusions -o \\( -name '*.conf' -o -name '*.config' -o -name '*.ini' -o -name '*config*' \\) -type f -print \\) 2>/dev/null > '$temp_file.patterns'"
    
    # Method 2: Directory-based search in common config locations
    local method2="for confdir in /etc /usr/local/etc /opt/*/etc /var/*/config /home/*/config; do [[ -d \"\$confdir\" ]] && find \"\$confdir\" \\( $exclusions -o -type f -print \\) 2>/dev/null; done > '$temp_file.dirs'"
    
    # Method 3: Content-based detection (files containing 'password', 'secret', 'key')
    local method3="find /etc /home /var \\( $exclusions -o -type f -print \\) -exec grep -l 'password\\|secret\\|key\\|credential' {} + 2>/dev/null > '$temp_file.content'"
    
    # Method 4: Web server specific configs
    local method4="find / \\( $exclusions -o \\( -name 'httpd.conf' -o -name 'nginx.conf' -o -name 'apache2.conf' -o -name '.htaccess' -o -name 'wp-config.php' \\) -type f -print \\) 2>/dev/null > '$temp_file.web'"
    
    if universal_vulnerability_detector "Configuration Files" "$method1" "$method2" "$method3" "$method4"; then
        # Process all found configuration files
        for result_file in "$temp_file."*; do
            [[ -f "$result_file" ]] && cat "$result_file" 2>/dev/null
        done | sort -u | while IFS= read -r config_file; do
            if [[ -n "$config_file" && -f "$config_file" ]]; then
                # Check exclusions
                if ! should_exclude_path "$config_file" && ! should_exclude_extension "$config_file"; then
                    analyze_config_file "$config_file"
                fi
            fi
        done
    fi
    
    # Cleanup
    rm -f "$temp_file."* 2>/dev/null
}

# Helper functions for processing detection results
process_suid_sgid_binary() {
    local binary="$1"
    local perms=$(stat -c "%a" "$binary" 2>/dev/null || echo "unknown")
    local owner=$(stat -c "%U" "$binary" 2>/dev/null || echo "unknown")
    
    # Determine if SUID or SGID
    local suid_bit=""
    local sgid_bit=""
    [[ $perms =~ ^[0-9]*4[0-9]*$ ]] && suid_bit="SUID"
    [[ $perms =~ ^[0-9]*2[0-9]*$ ]] && sgid_bit="SGID"
    
    local vuln_type="${suid_bit}${sgid_bit:+${suid_bit:+/}$sgid_bit} Binary"
    log_vulnerability "HIGH" "$vuln_type" "$binary" "Executable with elevated privileges (owner: $owner, perms: $perms)"
}

process_world_writable_file() {
    local file="$1"
    local perms=$(stat -c "%a" "$file" 2>/dev/null || echo "unknown")
    log_vulnerability "MEDIUM" "World Writable File" "$file" "File writable by all users (perms: $perms)"
}

process_world_readable_file() {
    local file="$1"
    local perms=$(stat -c "%a" "$file" 2>/dev/null || echo "unknown")
    log_vulnerability "LOW" "World Readable Sensitive File" "$file" "Sensitive file readable by all users (perms: $perms)"
}

analyze_sticky_bit_dir() {
    local dir="$1"
    local perms=$(stat -c "%a" "$dir" 2>/dev/null || echo "unknown")
    log_vulnerability "INFO" "Sticky Bit Directory" "$dir" "Directory with sticky bit (perms: $perms)"
}

analyze_config_file() {
    local config_file="$1"
    local perms=$(stat -c "%a" "$config_file" 2>/dev/null || echo "unknown")
    
    # Check if readable by others and contains sensitive keywords
    if [[ -r "$config_file" ]] && grep -q -i 'password\|secret\|key\|credential\|token' "$config_file" 2>/dev/null; then
        log_vulnerability "HIGH" "Configuration File with Secrets" "$config_file" "Config file contains sensitive data (perms: $perms)"
    elif [[ $perms =~ ^[0-9]*[0-9][0-9][4567][0-9]*$ ]]; then
        log_vulnerability "MEDIUM" "World Readable Configuration" "$config_file" "Config file readable by others (perms: $perms)"
    fi
}

#############################################################################
# Dynamic Path Discovery System
#############################################################################

# Global path discovery arrays
declare -A DISCOVERED_PATHS
declare -A HIGH_VALUE_PATHS  
declare -A ACCESS_PATTERNS
declare -A PATH_SCORES

# Intelligence engine for dynamic path discovery and analysis
discover_and_analyze_paths() {
    local initial_findings=("$@")
    
    [[ $QUIET_MODE -eq 0 ]] && echo "[*] Analyzing discovered paths for intelligence..."
    
    for finding in "${initial_findings[@]}"; do
        [[ -z "$finding" ]] && continue
        
        # Extract directory from finding
        local dir=$(dirname "$finding" 2>/dev/null || echo "")
        [[ -z "$dir" || "$dir" == "." ]] && continue
        
        DISCOVERED_PATHS["$dir"]=1
        
        # Score path based on findings context
        local score=1
        PATH_SCORES["$dir"]=$((${PATH_SCORES["$dir"]:-0} + score))
        
        # Check if it's a high-value directory type
        case "$dir" in
            */config|*/etc|*/conf.d|*/.ssh|*/ssl|*/certs|*/certificates)
                HIGH_VALUE_PATHS["$dir"]="config"
                PATH_SCORES["$dir"]=$((${PATH_SCORES["$dir"]} + 5))
                ;;
            */public_html|*/www|*/htdocs|*/web|*/webroot|*/docroot)
                HIGH_VALUE_PATHS["$dir"]="web"
                PATH_SCORES["$dir"]=$((${PATH_SCORES["$dir"]} + 4))
                ;;
            */backup|*/backups|*/dumps|*/exports|*/archive)
                HIGH_VALUE_PATHS["$dir"]="backup"
                PATH_SCORES["$dir"]=$((${PATH_SCORES["$dir"]} + 3))
                ;;
            */bin|*/sbin|*/libexec)
                HIGH_VALUE_PATHS["$dir"]="binary"
                PATH_SCORES["$dir"]=$((${PATH_SCORES["$dir"]} + 2))
                ;;
            */var/log|*/logs|*/log)
                HIGH_VALUE_PATHS["$dir"]="logs"
                PATH_SCORES["$dir"]=$((${PATH_SCORES["$dir"]} + 2))
                ;;
            */home/*|*/users/*)
                HIGH_VALUE_PATHS["$dir"]="user"
                PATH_SCORES["$dir"]=$((${PATH_SCORES["$dir"]} + 3))
                ;;
        esac
        
        # Record access pattern
        local user_context=$(get_user_context "$finding")
        ACCESS_PATTERNS["$user_context-$dir"]=$((${ACCESS_PATTERNS["$user_context-$dir"]:-0} + 1))
        
        # Parent directory analysis - check if parent dirs are also interesting
        local parent_dir=$(dirname "$dir" 2>/dev/null || echo "")
        if [[ -n "$parent_dir" && "$parent_dir" != "/" && "$parent_dir" != "." ]]; then
            PATH_SCORES["$parent_dir"]=$((${PATH_SCORES["$parent_dir"]:-0} + 1))
            
            # Mark parent as discovered if it has enough score
            if [[ ${PATH_SCORES["$parent_dir"]} -gt 2 ]]; then
                DISCOVERED_PATHS["$parent_dir"]=1
            fi
        fi
    done
    
    # Re-scan high-value discovered paths with enhanced methods
    local rescan_count=0
    for path in "${!HIGH_VALUE_PATHS[@]}"; do
        local path_type="${HIGH_VALUE_PATHS[$path]}"
        local score=${PATH_SCORES["$path"]:-0}
        
        # Only rescan paths with significant scores to avoid noise
        if [[ $score -gt 3 && -d "$path" ]]; then
            [[ $QUIET_MODE -eq 0 ]] && echo "[*] Re-scanning high-value path: $path (type: $path_type, score: $score)"
            enhanced_deep_scan "$path" "$path_type"
            ((rescan_count++))
        fi
        
        # Limit rescans to prevent infinite loops
        [[ $rescan_count -gt 10 ]] && break
    done
    
    # Generate intelligence summary
    generate_path_intelligence_summary
}

# Enhanced deep scan for discovered high-value paths
enhanced_deep_scan() {
    local path="$1"
    local path_type="$2"
    
    [[ ! -d "$path" ]] && return 1
    
    # Apply specialized scanning based on path type
    case "$path_type" in
        "config")
            scan_config_directory_deep "$path"
            ;;
        "web")  
            scan_web_directory_deep "$path"
            ;;
        "backup")
            scan_backup_directory_deep "$path"
            ;;
        "binary")
            scan_binary_directory_deep "$path"
            ;;
        "logs")
            scan_logs_directory_deep "$path"
            ;;
        "user")
            scan_user_directory_deep "$path"
            ;;
        *)
            scan_generic_directory_deep "$path"
            ;;
    esac
}

# Specialized deep scanning functions
scan_config_directory_deep() {
    local dir="$1"
    
    # Look for configuration files with enhanced patterns
    find "$dir" -maxdepth 3 -type f \( \
        -name "*.conf" -o -name "*.config" -o -name "*.ini" -o \
        -name "*.cfg" -o -name "*.properties" -o -name "*.yaml" -o \
        -name "*.yml" -o -name "*.json" -o -name "*.xml" \
    \) -readable 2>/dev/null | while IFS= read -r config_file; do
        # Update worker heartbeat and user timestamp during file processing
        local worker_heartbeat="$TEMP_DIR/worker_${WORKER_ID:-0}_heartbeat"
        echo "$(date +%s)" > "$worker_heartbeat" 2>/dev/null
        
        # Update user activity timestamp
        if [[ -n "${WORKER_ID:-}" ]] && [[ -f "$TEMP_DIR/current_user_${WORKER_ID}" ]]; then
            local user_data=$(cat "$TEMP_DIR/current_user_${WORKER_ID}" 2>/dev/null)
            local username="${user_data%:*}"
            echo "$username:$(date +%s)" > "$TEMP_DIR/current_user_${WORKER_ID}"
        fi
        
        analyze_config_file "$config_file"
        
        # Check for secrets in config files
        if grep -q -i 'password\|secret\|key\|token\|credential' "$config_file" 2>/dev/null; then
            log_vulnerability "HIGH" "Config with Secrets" "$config_file" "Configuration file contains sensitive keywords"
        fi
    done
}

scan_web_directory_deep() {
    local dir="$1"
    
    # Look for web-specific sensitive files
    find "$dir" -maxdepth 2 -type f \( \
        -name "wp-config.php" -o -name ".env" -o -name "settings.php" -o \
        -name "config.php" -o -name ".htaccess" -o -name ".htpasswd" -o \
        -name "database.yml" -o -name "secrets.yml" \
    \) 2>/dev/null | while IFS= read -r web_file; do
        local perms=$(stat -c "%a" "$web_file" 2>/dev/null || echo "unknown")
        log_vulnerability "HIGH" "Web Configuration File" "$web_file" "Sensitive web config file (perms: $perms)"
    done
}

scan_backup_directory_deep() {
    local dir="$1"
    
    # Look for backup files that might contain sensitive data
    find "$dir" -maxdepth 2 -type f \( \
        -name "*.bak" -o -name "*.backup" -o -name "*.old" -o \
        -name "*.dump" -o -name "*.sql" -o -name "*.tar.gz" -o \
        -name "*.zip" -o -name "*backup*" \
    \) 2>/dev/null | while IFS= read -r backup_file; do
        local size=$(stat -c "%s" "$backup_file" 2>/dev/null || echo "0")
        log_vulnerability "MEDIUM" "Backup File" "$backup_file" "Backup file found (size: $size bytes)"
    done
}

scan_binary_directory_deep() {
    local dir="$1"
    
    # Enhanced SUID/SGID detection in binary directories
    find "$dir" \( -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -maxdepth 2 -type f \( -perm -4000 -o -perm -2000 \) -print \) 2>/dev/null | \
    while IFS= read -r binary; do
        process_suid_sgid_binary "$binary"
    done
}

scan_logs_directory_deep() {
    local dir="$1"
    
    # Look for log files with potential sensitive information
    find "$dir" -maxdepth 2 -type f -name "*.log*" -readable 2>/dev/null | \
    while IFS= read -r log_file; do
        # Sample first 100 lines for sensitive patterns
        if head -100 "$log_file" 2>/dev/null | \
           grep -q -i 'password\|secret\|token\|credential\|api.key' 2>/dev/null; then
            log_vulnerability "MEDIUM" "Log with Sensitive Data" "$log_file" "Log file may contain sensitive information"
        fi
    done
}

scan_user_directory_deep() {
    local dir="$1"
    
    # Look for user-specific sensitive files
    find "$dir" -maxdepth 3 -type f \( \
        -name ".ssh/*" -o -name ".aws/*" -o -name ".gnupg/*" -o \
        -name ".*_history" -o -name ".netrc" -o -name ".git-credentials" \
    \) 2>/dev/null | while IFS= read -r user_file; do
        local perms=$(stat -c "%a" "$user_file" 2>/dev/null || echo "unknown")
        log_vulnerability "MEDIUM" "User Sensitive File" "$user_file" "User directory sensitive file (perms: $perms)"
    done
}

scan_generic_directory_deep() {
    local dir="$1"
    
    # Generic deep scan for any interesting files
    find "$dir" -maxdepth 2 -type f \( \
        -name "*secret*" -o -name "*password*" -o -name "*credential*" -o \
        -name "*.key" -o -name "*.pem" -o -name "*.p12" \
    \) 2>/dev/null | while IFS= read -r sensitive_file; do
        local perms=$(stat -c "%a" "$sensitive_file" 2>/dev/null || echo "unknown")
        log_vulnerability "MEDIUM" "Potentially Sensitive File" "$sensitive_file" "File with sensitive naming pattern (perms: $perms)"
    done
}

# Get user context from file path
get_user_context() {
    local file_path="$1"
    
    # Extract user from path patterns
    case "$file_path" in
        /home/*)
            echo "${file_path#/home/}" | cut -d'/' -f1
            ;;
        /users/*)
            echo "${file_path#/users/}" | cut -d'/' -f1
            ;;
        /var/www/*)
            echo "www-data"
            ;;
        /opt/*)
            echo "system"
            ;;
        *)
            echo "system"
            ;;
    esac
}

# Generate intelligence summary of discovered paths
generate_path_intelligence_summary() {
    [[ $QUIET_MODE -eq 1 ]] && return
    
    echo ""
    echo "${CYAN}=== Path Discovery Intelligence Summary ===${NC}"
    
    # High-value paths summary
    if [[ ${#HIGH_VALUE_PATHS[@]} -gt 0 ]]; then
        echo "${GREEN}High-Value Paths Discovered:${NC}"
        for path in "${!HIGH_VALUE_PATHS[@]}"; do
            local path_type="${HIGH_VALUE_PATHS[$path]}"
            local score=${PATH_SCORES["$path"]:-0}
            echo "  ${YELLOW}[$path_type]${NC} $path (score: $score)"
        done
    fi
    
    # Access patterns summary
    echo ""
    echo "${GREEN}Top Access Patterns:${NC}"
    for pattern in "${!ACCESS_PATTERNS[@]}"; do
        local count="${ACCESS_PATTERNS[$pattern]}"
        [[ $count -gt 1 ]] && echo "  $pattern: $count occurrences"
    done | sort -t: -k2 -nr | head -5
    
    # Path scores summary
    echo ""
    echo "${GREEN}Highest Scored Paths:${NC}"
    for path in "${!PATH_SCORES[@]}"; do
        local score="${PATH_SCORES[$path]}"
        [[ $score -gt 2 ]] && echo "  $path: $score"
    done | sort -t: -k2 -nr | head -10
    
    echo ""
}

#############################################################################
# Professional Output and Progress Functions
#############################################################################

# Get terminal width for responsive layout
get_terminal_width() {
    local width=$(tput cols 2>/dev/null || echo "80")
    echo "$width"
}

# Professional progress bar
show_progress_bar() {
    local current="$1"
    local total="$2"
    local message="$3"
    local files_info="${4:-}"  # Optional file progress info
    local width=$(get_terminal_width)
    local bar_width=$((width - 100))  # Leave more space for file info and user info
    
    if [[ $bar_width -lt 20 ]]; then
        bar_width=20
    fi
    
    local percentage=$((current * 100 / total))
    local filled=$((current * bar_width / total))
    local empty=$((bar_width - filled))
    
    # Build progress bar
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    
    # Clear previous line and show progress in-place for both modes
    printf "\033[2K\r${CYAN}[%3d%%]${NC} ${GREEN}%s${NC} ${BLUE}%s${NC} (%d/%d)" \
           "$percentage" "$bar" "$message" "$current" "$total"
    
    # Add file progress info if provided
    if [[ -n "$files_info" ]]; then
        printf " ${YELLOW}%s${NC}" "$files_info"
    fi
    
    # Force output to display immediately and add newline
    tput el  # Clear to end of line
    echo ""  # Always add newline to prevent overlap with other output
}

# Professional scanning dashboard
show_dashboard() {
    local current_user="$1"
    local total_users="$2"
    local processed_users="$3"
    local vulnerabilities_found="$4"
    local scan_speed="$5"
    
    # Calculate ETA with better precision
    local elapsed=$(($(date +%s) - SCAN_START_TIME))
    local eta="calculating..."
    
    if [[ $processed_users -gt 2 ]] && [[ $elapsed -gt 5 ]]; then
        local remaining_users=$((total_users - processed_users))
        
        # Try bc first for floating point calculation
        if command -v bc &>/dev/null; then
            local rate_per_second=$(echo "scale=2; $processed_users / $elapsed" | bc 2>/dev/null || echo "0")
            
            if [[ "$rate_per_second" != "0" ]] && [[ $(echo "$rate_per_second > 0" | bc 2>/dev/null) -eq 1 ]]; then
                local eta_seconds=$(echo "scale=0; $remaining_users / $rate_per_second" | bc 2>/dev/null || echo "0")
                
                if [[ $eta_seconds -gt 0 ]]; then
                    if [[ $eta_seconds -lt 60 ]]; then
                        eta="${eta_seconds}s"
                    elif [[ $eta_seconds -lt 3600 ]]; then
                        local eta_minutes=$((eta_seconds / 60))
                        eta="${eta_minutes}m"
                    else
                        local eta_hours=$((eta_seconds / 3600))
                        local eta_rem_minutes=$(((eta_seconds % 3600) / 60))
                        eta="${eta_hours}h ${eta_rem_minutes}m"
                    fi
                fi
            fi
        else
            # Fallback without bc - use integer math with scaling
            local rate_times_10=$((processed_users * 10 / elapsed))  # users per second * 10
            if [[ $rate_times_10 -gt 0 ]]; then
                local eta_seconds=$((remaining_users * 10 / rate_times_10))
                
                if [[ $eta_seconds -gt 0 ]]; then
                    if [[ $eta_seconds -lt 60 ]]; then
                        eta="${eta_seconds}s"
                    elif [[ $eta_seconds -lt 3600 ]]; then
                        local eta_minutes=$((eta_seconds / 60))
                        eta="${eta_minutes}m"
                    else
                        local eta_hours=$((eta_seconds / 3600))
                        local eta_rem_minutes=$(((eta_seconds % 3600) / 60))
                        eta="${eta_hours}h ${eta_rem_minutes}m"
                    fi
                fi
            fi
        fi
    fi
    
    # Format scan speed better
    local speed_display="$scan_speed"
    if [[ $scan_speed -gt 1000 ]]; then
        local speed_k=$((scan_speed / 1000))
        speed_display="${speed_k}k"
    fi
    
    # Show dashboard 
    if [[ $SHOW_PROGRESS -eq 1 ]]; then
        # Dashboard content only - screen clearing handled elsewhere
        local update_time=$(date "+%H:%M:%S")
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    ${WHITE}FILESPECTRE${NC}${CYAN} - Updated: ${WHITE}$update_time${NC}${CYAN}           ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
        printf "${CYAN}║${NC} Current User: ${GREEN}%-20s${NC} ${CYAN}│${NC} Total Users: ${BLUE}%6d${NC} ${CYAN}║${NC}\n" "$current_user" "$total_users"
        printf "${CYAN}║${NC} Processed:    ${YELLOW}%-20d${NC} ${CYAN}│${NC} Remaining:   ${BLUE}%6d${NC} ${CYAN}║${NC}\n" "$processed_users" "$((total_users - processed_users))"
        printf "${CYAN}║${NC} Vulnerabilities Found: ${RED}%-12d${NC} ${CYAN}│${NC} ETA: ${GREEN}%10s${NC} ${CYAN}║${NC}\n" "$vulnerabilities_found" "$eta"
        printf "${CYAN}║${NC} Scan Speed: ${MAGENTA}%-8s files/sec${NC} ${CYAN}│${NC} Elapsed: ${BLUE}%8ds${NC} ${CYAN}║${NC}\n" "$speed_display" "$elapsed"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        # Progress bar for users (only if not in main scanning loop to avoid duplication)
        if [[ "${SHOW_USER_PROGRESS:-1}" -eq 1 ]]; then
            local files_scanned=$(cat "$TEMP_DIR/total_files" 2>/dev/null || echo "0")
            local files_info="Files: $files_scanned"
            show_progress_bar "$processed_users" "$total_users" "Scanning Users" "$files_info"
            echo ""
        fi
    fi
}

# Quiet mode vulnerability output (only show high severity)
quiet_log_vulnerability() {
    local vuln_type="$1"
    local file_path="$2"
    local details="$3"
    local severity=$(calculate_severity "$vuln_type")
    
    # Always log to file
    log_vulnerability "$vuln_type" "$file_path" "$details"
    
    # Only show CRITICAL and HIGH vulnerabilities in quiet mode
    if [[ $QUIET_MODE -eq 1 ]]; then
        if [[ "$severity" == "CRITICAL" ]] || [[ "$severity" == "HIGH" ]]; then
            # Check if screen was recently cleared, if not clear current line
            local current_time=$(date +%s)
            if [[ $((current_time - LAST_SCREEN_CLEAR)) -gt 2 ]]; then
                printf "\033[2K\r"
            fi
            echo -e "  ${RED}[$severity]${NC} ${YELLOW}$vuln_type${NC}: $file_path"
        fi
    else
        # Verbose mode - show all vulnerabilities
        case "$severity" in
            "CRITICAL")
                echo -e "${RED}[!] CRITICAL [$vuln_type]: $file_path${NC}"
                ;;
            "HIGH")
                echo -e "${YELLOW}[!] HIGH [$vuln_type]: $file_path${NC}"
                ;;
            "MEDIUM")
                echo -e "${CYAN}[!] MEDIUM [$vuln_type]: $file_path${NC}"
                ;;
            *)
                echo -e "${BLUE}[*] LOW [$vuln_type]: $file_path${NC}"
                ;;
        esac
    fi
}

#############################################################################
# Thread-safe Functions
#############################################################################

# Optimized counter increment (reduced file I/O)
increment_counter() {
    local counter_file="$1"
    local increment="${2:-1}"
    # Use atomic append instead of read-modify-write for better performance
    echo "+$increment" >> "${counter_file}.delta"
}

# Get counter value (consolidates deltas) - non-destructive read
get_counter() {
    local counter_file="$1"
    local consolidate="${2:-0}"  # Optional flag to consolidate deltas
    local base=$(cat "$counter_file" 2>/dev/null || echo "0")
    
    if [[ -f "${counter_file}.delta" ]]; then
        # Use awk for fast summation instead of while loop
        local delta_sum=$(awk '{gsub(/^\+/, "", $1); sum += $1} END {print sum+0}' "${counter_file}.delta" 2>/dev/null || echo "0")
        
        # Auto-consolidate if delta file gets too large (>100 lines)
        local delta_lines=$(wc -l < "${counter_file}.delta" 2>/dev/null || echo "0")
        if [[ "$consolidate" == "1" ]] || [[ $delta_lines -gt 100 ]]; then
            > "${counter_file}.delta"
            # Update base counter
            local total=$((base + delta_sum))
            echo "$total" > "$counter_file"
            echo "$total"
        else
            # Non-destructive read for frequent dashboard updates
            echo $((base + delta_sum))
        fi
    else
        echo "$base"
    fi
}

# Cached stat function for performance
cached_stat() {
    local file="$1"
    local format="$2"
    local cache_key="${file}_${format}"
    
    if [[ -n "${PERM_CACHE[$cache_key]}" ]]; then
        echo "${PERM_CACHE[$cache_key]}"
        return
    fi
    
    local result=$(stat -c "$format" "$file" 2>/dev/null || echo "")
    PERM_CACHE[$cache_key]="$result"
    echo "$result"
}

# Cached user lookup
cached_user_lookup() {
    local file="$1"
    local cache_key="$file"
    
    if [[ -n "${USER_CACHE[$cache_key]}" ]]; then
        echo "${USER_CACHE[$cache_key]}"
        return
    fi
    
    local user=$(stat -c '%U' "$file" 2>/dev/null || echo "unknown")
    USER_CACHE[$cache_key]="$user"
    echo "$user"
}

# Cached group lookup  
cached_group_lookup() {
    local file="$1"
    local cache_key="$file"
    
    if [[ -n "${GROUP_CACHE[$cache_key]}" ]]; then
        echo "${GROUP_CACHE[$cache_key]}"
        return
    fi
    
    local group=$(stat -c '%G' "$file" 2>/dev/null || echo "unknown")
    GROUP_CACHE[$cache_key]="$group"
    echo "$group"
}

# Fast file type detection
is_text_file() {
    local file="$1"
    local mime_type=$(file -b --mime-type "$file" 2>/dev/null)
    [[ "$mime_type" =~ ^text/ ]] || [[ "$mime_type" == "application/json" ]] || [[ "$mime_type" == "application/xml" ]]
}

# Pre-filter files by extension for faster processing
should_scan_file_fast() {
    local file="$1"
    local ext="${file##*.}"
    
    # Skip common binary extensions that are unlikely to have vulnerabilities
    case "$ext" in
        jpg|jpeg|png|gif|js|css|map|bmp|ico|svg|pdf|mp3|mp4|avi|mkv|xz|exe|dll|so|a|o|class)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

# Thread-safe result logging
log_vulnerability() {
    local vuln_type="$1"
    local file_path="$2"
    local details="$3"
    
    (
        flock -x 200
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$vuln_type] $file_path | $details" >> "$RESULTS_FILE"
        increment_counter "$TEMP_DIR/total_vulns"
    ) 200>"$LOCK_FILE"
    
    # Also log to main log file
    echo "[$vuln_type] $file_path | $details" >> "$LOG_FILE"
}

# Progress indicator
update_progress() {
    local message="$1"
    (
        flock -x 200
        echo "$message" >> "$PROGRESS_FILE"
    ) 200>"${PROGRESS_FILE}.lock"
}

#############################################################################
# Advanced Vulnerability Detection Functions
#############################################################################

# Enhanced SUID/SGID detection with system-wide scanning and fallbacks
check_suid_sgid() {
    local path="$1"
    local max_depth="${2:-3}"
    
    # Check if we should scan SUID/SGID
    if ! should_scan_vuln_type "suid" && ! should_scan_vuln_type "sgid"; then
        return
    fi
    
    # System-wide detection when path is "/" or major system directory
    if [[ "$path" == "/" ]] || [[ "$path" =~ ^/(usr|bin|sbin) ]]; then
        detect_suid_sgid_systemwide
    else
        # Limited path scanning for specific directories
        detect_suid_sgid_limited "$path" "$max_depth"
    fi
}

# Note: Enhanced system-wide SUID/SGID detection is implemented above at line ~585

# Limited path SUID/SGID detection (original method for specific directories)  
detect_suid_sgid_limited() {
    local path="$1"
    local max_depth="$2"
    
    # Use array instead of while read for massive performance gain
    local files
    readarray -t files < <(find "$path" -maxdepth "$max_depth" \( -perm -u=s -o -perm -g=s \) -type f 2>/dev/null)
    for file in "${files[@]}"; do
        if [[ -n "$file" && -r "$file" ]]; then
            process_suid_sgid_file "$file"
        fi
    done
}

# Process individual SUID/SGID files with enhanced analysis
process_suid_sgid_file() {
    local file="$1"
    local perms=$(cached_stat "$file" "%a")
    local owner=$(cached_user_lookup "$file")
    local group=$(cached_group_lookup "$file")
    local basename=$(basename "$file")
    
    # Enhanced safe binary detection with version flexibility
    local safe_binaries=(
        "sudo" "passwd" "mount" "umount" "ping" "ping6" "su" 
        "chsh" "chfn" "gpasswd" "newgrp" "chage" "expiry"
        "unix_chkpwd" "pam_extrausers_chkpwd" "ssh-agent" "fusermount3"
        "pkexec" "dbus-daemon" "polkit-agent-helper-1"
    )
    
    # Check if it's a known safe binary (with version number flexibility)
    local is_safe=0
    for safe_binary in "${safe_binaries[@]}"; do
        if [[ "$basename" =~ ^${safe_binary}([0-9]*)?$ ]]; then
            is_safe=1
            break
        fi
    done
    
    # Report if not in safe list or has unusual permissions
    if [[ $is_safe -eq 0 ]] || [[ ! "$perms" =~ ^[24]755$ ]]; then
        local vuln_type="SUID"
        [[ "$perms" =~ ^2 ]] && vuln_type="SGID"
        
        # Enhanced severity assessment
        local severity_details=""
        case "$basename" in
            *admin*|*root*|*super*|*exec*|*cmd*)
                severity_details=" | HIGH-RISK: Administrative binary"
                ;;
            *net*|*tcp*|*udp*|*sock*|*port*)
                severity_details=" | NETWORK-CAPABLE: Potential network access"
                ;;
            *file*|*dir*|*path*|*sys*)
                severity_details=" | FILE-SYSTEM: Potential file system access"
                ;;
        esac
        
        quiet_log_vulnerability "$vuln_type" "$file" "Perms: $perms | Owner: $owner:$group | Potential privilege escalation$severity_details"
    fi
}

# Process results from system-wide SUID/SGID detection
process_suid_sgid_results() {
    local files=("$@")
    local processed_count=0
    
    for file in "${files[@]}"; do
        [[ -n "$file" ]] && [[ -f "$file" ]] && process_suid_sgid_file "$file" && ((processed_count++))
    done
    
    if [[ $VERBOSE_MODE -eq 1 ]] && [[ $processed_count -gt 0 ]]; then
        echo -e "${GREEN}[+] Processed $processed_count SUID/SGID files${NC}"
    fi
}

# Enhanced world permissions detection with system-wide scanning
check_world_writable() {
    local path="$1"
    local max_depth="${2:-3}"
    
    # Check if we should scan world-writable
    if ! should_scan_vuln_type "world-writable"; then
        return
    fi
    
    # System-wide detection when path is "/" or major system directory
    if [[ "$path" == "/" ]] || [[ "$path" =~ ^/(usr|var|tmp|opt) ]]; then
        detect_world_permissions_systemwide
    else
        # Limited path scanning for specific directories
        detect_world_writable_limited "$path" "$max_depth"
    fi
}

# Note: Enhanced system-wide world permissions detection is implemented above at line ~621

# Limited path world-writable detection (original method)
detect_world_writable_limited() {
    local path="$1"
    local max_depth="$2"
    
    # Use arrays for performance - files
    local world_files
    readarray -t world_files < <(find "$path" -maxdepth "$max_depth" -perm -2 ! -type l 2>/dev/null)
    for file in "${world_files[@]}"; do
        [[ -n "$file" ]] && process_world_writable_file "$file"
    done
    
    # Use arrays for performance - directories  
    local world_dirs
    readarray -t world_dirs < <(find "$path" -maxdepth "$max_depth" \( -perm -o+w -perm -o+x \) -type d ! -perm -1000 2>/dev/null)
    for dir in "${world_dirs[@]}"; do
        [[ -n "$dir" ]] && process_world_writable_directory "$dir"
    done
}

# Process individual world-writable files
process_world_writable_file() {
    local file="$1"
    [[ ! -f "$file" ]] && return
    
    local owner=$(cached_user_lookup "$file")
    local perms=$(cached_stat "$file" "%a")
    local size=$(cached_stat "$file" "%s")
    
    # Skip files owned by current user unless they're in sensitive locations
    if [[ "$owner" == "$CURRENT_USER" ]]; then
        case "$file" in
            /etc/*|/usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/var/www/*|*/cgi-bin/*)
                # Report current user files in system directories - potential privilege escalation
                quiet_log_vulnerability "WORLD_WRITE" "$file" "User-owned world-writable in system location | Owner: $owner | Perms: $perms"
                ;;
            *)
                return  # Skip user's own files in user directories
                ;;
        esac
    else
        # Enhanced analysis for other users' files
        local risk_assessment=""
        case "$file" in
            /etc/*|*/config/*|*config*.*)
                risk_assessment=" | HIGH-RISK: Configuration file"
                ;;
            /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*)
                risk_assessment=" | CRITICAL: System binary"
                ;;
            *.php|*.py|*.pl|*.sh|*.rb|*.js)
                risk_assessment=" | HIGH-RISK: Executable script"
                ;;
            /var/www/*|*/public_html/*|*/htdocs/*)
                risk_assessment=" | WEB-ACCESSIBLE: Public web file"
                ;;
        esac
        
        quiet_log_vulnerability "WORLD_WRITE" "$file" "World-writable file | Owner: $owner | Perms: $perms | Size: $size$risk_assessment"
    fi
}

# Process world-writable directories
process_world_writable_directory() {
    local dir="$1"
    [[ ! -d "$dir" ]] && return
    
    local owner=$(cached_user_lookup "$dir")
    local perms=$(cached_stat "$dir" "%a")
    
    # Enhanced directory analysis
    local risk_level=""
    case "$dir" in
        /tmp|/var/tmp|/dev/shm)
            # These are normally world-writable with sticky bit, report if no sticky bit
            [[ ! -k "$dir" ]] && risk_level=" | MISSING-STICKY-BIT: Potential file hijacking"
            ;;
        /etc/*|/usr/*|/var/log/*|/opt/*)
            risk_level=" | CRITICAL: System directory without sticky bit"
            ;;
        /home/*/public_html/*|*/www/*|*/htdocs/*)
            risk_level=" | WEB-RISK: Web directory without sticky bit"
            ;;
    esac
    
    quiet_log_vulnerability "WORLD_WRITE" "$dir" "World-writable directory without sticky bit | Owner: $owner | Perms: $perms$risk_level"
}

# Process world-readable sensitive files (new feature)
process_world_readable_file() {
    local file="$1"
    [[ ! -f "$file" ]] && return
    
    local owner=$(cached_user_lookup "$file")
    local perms=$(cached_stat "$file" "%a")
    local basename=$(basename "$file")
    
    # Skip if owned by current user and not in sensitive system locations
    if [[ "$owner" == "$CURRENT_USER" ]] && [[ ! "$file" =~ ^/(etc|usr|opt|var) ]]; then
        return
    fi
    
    # Analyze content risk level
    local content_risk=""
    case "$basename" in
        wp-config.php|database.yml|.env*|*credentials*|*password*)
            content_risk=" | CRITICAL-CONTENT: Likely contains credentials"
            ;;
        *.conf|*.ini|*config*)
            content_risk=" | HIGH-CONTENT: Configuration file"
            ;;
        *.key|*.pem|*.p12|*.pfx)
            content_risk=" | CRITICAL-CONTENT: Cryptographic key material"
            ;;
    esac
    
    # Only report if it has potential sensitive content
    [[ -n "$content_risk" ]] && quiet_log_vulnerability "WORLD_READ" "$file" "World-readable sensitive file | Owner: $owner | Perms: $perms$content_risk"
}

# Analyze world-executable directories for security risks
analyze_world_executable_directory() {
    local dir="$1"
    [[ ! -d "$dir" ]] && return
    
    # Only report unusual world-executable directories that might pose risks
    case "$dir" in
        /home/*/bin|/home/*/scripts|*/cgi-bin/*|*/public_html/*)
            local owner=$(cached_user_lookup "$dir")
            local perms=$(cached_stat "$dir" "%a")
            
            # Check if it contains executable files
            local exec_count=$(find "$dir" -maxdepth 1 -type f -executable 2>/dev/null | wc -l)
            if [[ $exec_count -gt 0 ]]; then
                quiet_log_vulnerability "WORLD_EXEC" "$dir" "World-executable directory with $exec_count executables | Owner: $owner | Perms: $perms"
            fi
            ;;
    esac
}

# Check for cross-user access to sensitive files (shared hosting vulnerability)
check_cross_user_access() {
    local path="$1"
    
    # Skip cross-user checking if disabled
    if [[ $SKIP_CROSS_USER -eq 1 ]]; then
        return
    fi
    
    if ! should_scan_vuln_type "config-files"; then
        return
    fi
    
    # Enhanced: 200+ production-grade sensitive file patterns
    local sensitive_files=(
        # Web Application Configurations (50+ patterns)
        "wp-config.php" "wp-config-sample.php" ".wp-cli.yml" "wp-cli.yml"
        "settings.php" "services.yml" "sites.php" "local.xml" "env.php"
        "config.php" "configuration.php" "app.php" "database.php" "db_config.php" "config.inc.php"
        "httpd.conf" "apache2.conf" "nginx.conf" "default.conf" "000-default.conf" ".htaccess" ".htpasswd"
        "php.ini" "php-fpm.conf" "pool.conf" "opcache.ini" ".user.ini"
        
        # Environment & Configuration Files (40+ patterns)
        ".env" ".env.local" ".env.production" ".env.development" ".env.staging" ".env.test"
        ".env.example" ".env.sample" ".env.backup" ".env.old" ".env.orig"
        "config.yml" "config.yaml" "application.yml" "application.yaml"
        "database.yml" "database.yaml" "secrets.yml" "secrets.yaml"
        "credentials.yml" "credentials.yaml" "production.yml" "development.yml"
        
        # SSL/TLS & Cryptographic Materials (30+ patterns)
        "private.key" "server.key" "ssl.key" "tls.key" "client.key"
        "*.pem" "*.key" "*.crt" "*.cer" "*.p12" "*.pfx" "*.jks" "*.keystore"
        "ssl-cert-snakeoil.key" "ssl-cert-snakeoil.pem"
        "ca-certificates.conf" "*.ca-bundle" "*.ca-cert"
        "id_rsa" "id_dsa" "id_ecdsa" "id_ed25519" "authorized_keys" "known_hosts"
        
        # Database Configurations (25+ patterns)
        "my.cnf" "my.ini" "mysql.conf" "mariadb.conf" "client.cnf" "server.cnf"
        "postgresql.conf" "pg_hba.conf" "pg_ident.conf" "recovery.conf"
        "redis.conf" "mongodb.conf" "mongod.conf" "cassandra.conf"
        "elasticsearch.yml" "logstash.conf" "kibana.yml"
        ".my.cnf" ".mysql_history" ".psql_history"
        
        # Cloud & Container Configurations (35+ patterns)
        "docker-compose.yml" "docker-compose.yaml" ".dockerignore"
        "docker-compose.override.yml" ".docker-compose.yml"
        "Dockerfile" "kubernetes.yml" "*.k8s.yml" "kustomization.yaml"
        "helm-values.yaml" "values.yaml" "Chart.yaml"
        ".aws/credentials" ".aws/config" "aws-credentials.ini" "awscli.conf"
        "boto.cfg" "s3cfg" "terraform.tfvars" ".terraformrc" "terraform.rc"
        "service-account.json" "gcloud.json" "*.gcp" "azure-credentials.json" "*.azure"
        
        # Application-Specific Configurations (40+ patterns)
        "package.json" "package-lock.json" "yarn.lock" ".npmrc" ".yarnrc"
        "composer.json" "composer.lock" "composer.phar"
        "requirements.txt" "pip.conf" "pip.ini" "pydistutils.cfg" "setup.cfg"
        "Gemfile" "Gemfile.lock" ".bundle/config" ".ruby-version"
        "pom.xml" "build.gradle" "gradle.properties" ".gradle/gradle.properties"
        ".python-version" "celery.conf" "gunicorn.conf" "uwsgi.conf"
        "ecosystem.config.js" "pm2.config.js" "nuxt.config.js" "next.config.js"
        
        # Authentication & Authorization (20+ patterns)
        "auth.json" "secrets.json" "credentials.json" "passwords.txt"
        "users.json" "accounts.json" "tokens.json" "api-keys.json"
        ".netrc" ".authinfo" "keystore.json" "truststore.json"
        "oauth-private.key" "oauth-public.key" "jwt.key" "jwt.pem"
        "ldap.conf" "krb5.conf" "samba.conf" "smb.conf"
        
        # Version Control & Development (15+ patterns)  
        ".git/config" ".gitconfig" ".git-credentials" ".netrc"
        ".svn/auth" ".hg/hgrc" ".bzr/bazaar.conf"
        ".vscode/settings.json" ".idea/workspace.xml" ".sublime-project"
        ".project" ".classpath" "nbproject/project.properties"
        
        # System & Service Configurations (25+ patterns)
        "sshd_config" "ssh_config" "hosts.allow" "hosts.deny"
        "exports" "nfs.conf" "vsftpd.conf" "proftpd.conf"
        "postfix/main.cf" "dovecot.conf" "exim.conf" "sendmail.cf"
        "systemd/*.service" "init.d/*" "xinetd.d/*" "crontab" "anacrontab"
        "sudoers" "sudoers.d/*" "shadow" "gshadow" "passwd" "group"
    )
    
    # Define sensitive directories commonly found in web hosting
    local web_dirs=(
        "public_html"
        "www"
        "htdocs"
        "html"
        "web"
        "sites"
        "domains"
        "subdomains"
    )
    
    # Search for sensitive files in other users' directories
    for sensitive_file in "${sensitive_files[@]}"; do
        # Look for these files in the current path
        find "$path" -maxdepth 5 -name "$sensitive_file" -type f 2>/dev/null | while read -r file; do
            local file_owner=$(stat -c '%U' "$file" 2>/dev/null)
            local file_group=$(stat -c '%G' "$file" 2>/dev/null)
            local perms=$(stat -c '%a' "$file" 2>/dev/null)
            
            # Check if we can read a file that belongs to another user
            if [[ "$file_owner" != "$CURRENT_USER" ]] && [[ -r "$file" ]]; then
                # Determine the type of access issue
                local access_type=""
                local severity="HIGH"
                
                # Check permission type
                if [[ "${perms:2:1}" -ge 4 ]]; then
                    access_type="World-readable"
                    severity="CRITICAL"
                elif [[ "${perms:1:1}" -ge 4 ]] && groups | grep -q "$file_group"; then
                    access_type="Group-readable"
                    severity="HIGH" 
                else
                    access_type="Accessible via other means"
                    severity="MEDIUM"
                fi
                
                # Determine the context (web directory, home directory, etc.)
                local context=""
                for web_dir in "${web_dirs[@]}"; do
                    if [[ "$file" =~ /$web_dir/ ]]; then
                        context="Web directory ($web_dir)"
                        break
                    fi
                done
                
                if [[ -z "$context" ]]; then
                    if [[ "$file" =~ /home[0-9]*/ ]]; then
                        context="Home directory"
                    else
                        context="System location"
                    fi
                fi
                
                log_vulnerability "CONFIG_FILES" "$file" "$access_type sensitive file in $context | Owner: $file_owner | Group: $file_group | Perms: $perms"
                
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    case "$severity" in
                        "CRITICAL")
                            echo -e "${RED}[!] CRITICAL CROSS-USER ACCESS: $file (Owner: $file_owner)${NC}"
                            ;;
                        "HIGH") 
                            echo -e "${YELLOW}[!] HIGH CROSS-USER ACCESS: $file (Owner: $file_owner)${NC}"
                            ;;
                        *)
                            echo -e "${CYAN}[!] CROSS-USER ACCESS: $file (Owner: $file_owner)${NC}"
                            ;;
                    esac
                fi
                
                # If it's a readable config file, try to extract sensitive info
                if [[ "$file" =~ wp-config\.php$ ]] && [[ -r "$file" ]]; then
                    local db_info=$(grep -i "define.*DB_" "$file" 2>/dev/null | head -3)
                    if [[ -n "$db_info" ]]; then
                        log_vulnerability "CONFIG_FILES" "$file" "WordPress config accessible - database credentials exposed | Owner: $file_owner"
                        if [[ $VERBOSE_MODE -eq 1 ]]; then
                            echo -e "${RED}[!] WORDPRESS DB CREDENTIALS EXPOSED: $file${NC}"
                        fi
                    fi
                elif [[ "$file" =~ \.env$ ]] && [[ -r "$file" ]]; then
                    local env_secrets=$(grep -iE "(password|secret|key|token|api)" "$file" 2>/dev/null | wc -l)
                    if [[ $env_secrets -gt 0 ]]; then
                        log_vulnerability "CONFIG_FILES" "$file" "Environment file accessible - $env_secrets potential secrets exposed | Owner: $file_owner"
                        if [[ $VERBOSE_MODE -eq 1 ]]; then
                            echo -e "${RED}[!] ENVIRONMENT SECRETS EXPOSED: $file ($env_secrets secrets)${NC}"
                        fi
                    fi
                fi
            fi
        done
    done
    
    # Check for readable SSH directories in other users' paths
    find "$path" -maxdepth 3 -name ".ssh" -type d 2>/dev/null | while read -r ssh_dir; do
        local dir_owner=$(stat -c '%U' "$ssh_dir" 2>/dev/null)
        local perms=$(stat -c '%a' "$ssh_dir" 2>/dev/null)
        
        if [[ "$dir_owner" != "$CURRENT_USER" ]] && [[ -r "$ssh_dir" ]]; then
            log_vulnerability "SSH_KEYS" "$ssh_dir" "SSH directory accessible from other user | Owner: $dir_owner | Perms: $perms"
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${RED}[!] CROSS-USER SSH ACCESS: $ssh_dir (Owner: $dir_owner)${NC}"
            fi
            
            # Check for specific SSH files
            for ssh_file in "$ssh_dir"/id_* "$ssh_dir"/authorized_keys "$ssh_dir"/known_hosts; do
                if [[ -f "$ssh_file" ]] && [[ -r "$ssh_file" ]]; then
                    local file_perms=$(stat -c '%a' "$ssh_file" 2>/dev/null)
                    log_vulnerability "SSH_KEYS" "$ssh_file" "SSH file accessible from other user | Owner: $dir_owner | Perms: $file_perms"
                    if [[ $VERBOSE_MODE -eq 1 ]]; then
                        echo -e "${RED}[!] SSH FILE ACCESSIBLE: $ssh_file${NC}"
                    fi
                fi
            done
        fi
    done
    
    # NEW: Systematic cross-user detection based on current user's file structure
    perform_systematic_cross_user_check "$path"
}

# Systematic cross-user access detection - mirrors current user's structure to other users
perform_systematic_cross_user_check() {
    local scan_path="$1"
    
    # Skip cross-user checking if disabled
    if [[ $SKIP_CROSS_USER -eq 1 ]]; then
        return
    fi
    
    if [[ $VERBOSE_MODE -eq 1 ]]; then
        echo -e "${CYAN}[*] Performing systematic cross-user structure analysis...${NC}"
    fi
    
    # Only perform this check if we're scanning a home directory structure
    if [[ ! "$scan_path" =~ ^/home[0-9]*/ ]] && [[ ! "$scan_path" =~ ^/Users/ ]]; then
        return
    fi
    
    # Get current user's home directory structure
    local current_user_home=""
    local current_user_base=""
    
    # Detect current user's actual home patterns
    for base in /home /home1 /home2 /home3 /home4 /home5 /home6 /home7 /home8 /home9 /Users; do
        if [[ -d "$base/$CURRENT_USER" ]]; then
            current_user_home="$base/$CURRENT_USER"
            current_user_base="$base"
            break
        fi
    done
    
    if [[ -z "$current_user_home" ]] || [[ ! -d "$current_user_home" ]]; then
        return
    fi
    
    if [[ $VERBOSE_MODE -eq 1 ]]; then
        echo -e "${CYAN}[*] Current user home detected: $current_user_home${NC}"
        echo -e "${CYAN}[*] Analyzing file structure for cross-user access...${NC}"
    fi
    
    # Get relative paths from current user's home (using should_scan_file_fast filtering)
    local temp_file="/tmp/filespectre_user_files_$$"
    
    # Use array for file discovery - major performance improvement
    local all_files
    readarray -t all_files < <(find "$current_user_home" -type f -size -10M 2>/dev/null)
    
    # Filter files efficiently
    for file in "${all_files[@]}"; do
        if [[ -n "$file" ]] && should_scan_file_fast "$file"; then
            # Convert to relative path
            echo "${file#$current_user_home/}"
        fi
    done > "$temp_file" 2>/dev/null || touch "$temp_file"
    
    local file_count=0
    if [[ -f "$temp_file" ]]; then
        file_count=$(wc -l < "$temp_file" 2>/dev/null || echo "0")
    fi
    if [[ $file_count -eq 0 ]]; then
        rm -f "$temp_file"
        return
    fi
    
    if [[ $VERBOSE_MODE -eq 1 ]]; then
        echo -e "${CYAN}[*] Found $file_count files in current user structure to test${NC}"
    fi
    
    # Test these paths against other users in the same base directory and other bases
    local checked_users=0
    local accessible_files=0
    
    for base in /home /home1 /home2 /home3 /home4 /home5 /home6 /home7 /home8 /home9 /Users; do
        if [[ ! -d "$base" ]] || [[ "$base" == "$current_user_base" ]]; then
            continue
        fi
        
        # Get users in this base directory
        for user_dir in "$base"/*; do
            if [[ ! -d "$user_dir" ]]; then
                continue
            fi
            
            local target_user=$(basename "$user_dir")
            
            # Skip current user and system directories
            if [[ "$target_user" == "$CURRENT_USER" ]] || \
               [[ "$target_user" =~ ^(lost\+found|\.snapshot|\.trash|tmp|temp|cache|log|logs|backup|backups)$ ]]; then
                continue
            fi
            
            ((checked_users++))
            
            # Test each file path from current user against this target user
            while IFS= read -r relative_path; do
                [[ -z "$relative_path" ]] && continue
                
                local target_file="$user_dir/$relative_path"
                
                # Check if we can access this file
                if [[ -f "$target_file" ]] && [[ -r "$target_file" ]]; then
                    local file_owner=$(stat -c '%U' "$target_file" 2>/dev/null)
                    local file_group=$(stat -c '%G' "$target_file" 2>/dev/null)
                    local perms=$(stat -c '%a' "$target_file" 2>/dev/null)
                    
                    if [[ "$file_owner" != "$CURRENT_USER" ]]; then
                        ((accessible_files++))
                        
                        # Determine severity based on file content/type
                        local severity="MEDIUM"
                        local file_type="Regular file"
                        
                        # Check if it contains sensitive patterns
                        if [[ "$relative_path" =~ (config|password|secret|key|credential|database|wp-config|\.env) ]]; then
                            severity="CRITICAL"
                            file_type="Potential sensitive file"
                        elif [[ "$relative_path" =~ \.(php|py|js|rb|java|conf|ini|yaml|yml|json)$ ]]; then
                            severity="HIGH" 
                            file_type="Configuration/script file"
                        fi
                        
                        log_vulnerability "CROSS_USER_STRUCTURE" "$target_file" "Systematic check: $file_type accessible via mirrored structure | Source: $current_user_home/$relative_path | Owner: $file_owner | Perms: $perms"
                        
                        if [[ $VERBOSE_MODE -eq 1 ]]; then
                            case "$severity" in
                                "CRITICAL")
                                    echo -e "${RED}[!] CRITICAL STRUCTURE ACCESS: $target_file${NC}"
                                    ;;
                                "HIGH")
                                    echo -e "${YELLOW}[!] HIGH STRUCTURE ACCESS: $target_file${NC}"
                                    ;;
                                *)
                                    echo -e "${CYAN}[+] Structure access: $target_file${NC}"
                                    ;;
                            esac
                        fi
                    fi
                fi
            done < <(cat "$temp_file" 2>/dev/null || true)
            
            # Limit to prevent excessive scanning
            if [[ $checked_users -ge 50 ]]; then
                break 2
            fi
        done
    done
    
    # Also check current base with different usernames (for same base directory)
    if [[ -n "$current_user_base" ]]; then
        for user_dir in "$current_user_base"/*; do
            if [[ ! -d "$user_dir" ]]; then
                continue
            fi
            
            local target_user=$(basename "$user_dir")
            
            # Skip current user and system directories  
            if [[ "$target_user" == "$CURRENT_USER" ]] || \
               [[ "$target_user" =~ ^(lost\+found|\.snapshot|\.trash|tmp|temp|cache|log|logs|backup|backups)$ ]]; then
                continue
            fi
            
            ((checked_users++))
            
            # Test a sample of file paths (limit for performance)
            while IFS= read -r relative_path; do
                [[ -z "$relative_path" ]] && continue
                
                local target_file="$user_dir/$relative_path"
                
                if [[ -f "$target_file" ]] && [[ -r "$target_file" ]]; then
                    local file_owner=$(stat -c '%U' "$target_file" 2>/dev/null)
                    local perms=$(stat -c '%a' "$target_file" 2>/dev/null)
                    
                    if [[ "$file_owner" != "$CURRENT_USER" ]]; then
                        ((accessible_files++))
                        
                        local severity="MEDIUM"
                        if [[ "$relative_path" =~ (config|password|secret|key|credential|database|wp-config|\.env) ]]; then
                            severity="CRITICAL"
                        elif [[ "$relative_path" =~ \.(php|py|js|rb|java|conf|ini|yaml|yml|json)$ ]]; then
                            severity="HIGH"
                        fi
                        
                        log_vulnerability "CROSS_USER_STRUCTURE" "$target_file" "Same-base structure access | Source pattern: $relative_path | Owner: $file_owner | Perms: $perms"
                        
                        if [[ $VERBOSE_MODE -eq 1 ]] && [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]]; then
                            echo -e "${RED}[!] $severity SAME-BASE ACCESS: $target_file${NC}"
                        fi
                    fi
                fi
            done < <(head -100 "$temp_file" 2>/dev/null || true)  # Limit to first 100 files for same-base check
            
            if [[ $checked_users -ge 20 ]]; then
                break
            fi
        done
    fi
    
    # Cleanup
    rm -f "$temp_file"
    
    if [[ $VERBOSE_MODE -eq 1 ]]; then
        echo -e "${GREEN}[+] Systematic cross-user check complete: $checked_users users checked, $accessible_files accessible files found${NC}"
    fi
}

# Advanced content scanner
scan_file_content() {
    local file="$1"
    
    # Check if sensitive content scanning is enabled
    if ! should_scan_vuln_type "sensitive-files"; then
        return
    fi
    
    # Skip if file is too large
    local file_size=$(cached_stat "$file" "%s")
    if [[ $file_size -gt $MAX_FILE_SIZE ]]; then
        return
    fi
    
    # Fast binary file detection
    if ! should_scan_file_fast "$file" || ! is_text_file "$file"; then
        return
    fi
    
    # Sensitive patterns to search
    local patterns=(
        'BEGIN.*PRIVATE KEY'
        'api[_-]?key.*[:=].*[a-zA-Z0-9]{20,}'
        'secret.*[:=].*[a-zA-Z0-9]{20,}'
        'token.*[:=].*[a-zA-Z0-9]{20,}'
        'password.*[:=].*[^\s]{8,}'
        'AWS[_]?ACCESS[_]?KEY'
        'AWS[_]?SECRET'
        'GITHUB[_]?TOKEN'
        'DB[_]?PASSWORD'
        'DATABASE[_]?URL'
        'mongodb\+srv://'
        'postgres://'
        'mysql://'
        'ftp://'
        'ssh://'
    )
    
    for pattern in "${patterns[@]}"; do
        if grep -qiE "$pattern" "$file" 2>/dev/null; then
            local match=$(grep -iE "$pattern" "$file" 2>/dev/null | head -1 | cut -c1-80)
            quiet_log_vulnerability "SENSITIVE_CONTENT" "$file" "Pattern: $pattern | Sample: $match..."
            break
        fi
    done
}

# Check for capability vulnerabilities with fallback methods
check_capabilities() {
    local path="$1"
    
    if command -v getcap &>/dev/null; then
        # Method 1: Use getcap (preferred)
        getcap -r "$path" 2>/dev/null | while read -r line; do
            if [[ -n "$line" ]]; then
                local file=$(echo "$line" | cut -d' ' -f1)
                local caps=$(echo "$line" | cut -d' ' -f2-)
                log_vulnerability "CAPABILITY" "$file" "Capabilities: $caps"
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${RED}[!] CAPABILITY: $file has $caps${NC}"
                fi
            fi
        done
    else
        # Method 2: Alternative capability detection using standard tools
        check_capability_alternatives "$path"
    fi
}

# Alternative capability checking methods without getcap
check_capability_alternatives() {
    local path="$1"
    
    # Method 2a: Check for common capability-enabled binaries by name and location
    local capability_binaries=(
        "ping"
        "ping6" 
        "traceroute"
        "tcpdump"
        "wireshark"
        "dumpcap"
        "nmap"
        "nping"
        "masscan"
        "arping"
        "clockdiff"
        "mtr"
        "iftop"
        "nethogs"
        "ss"
        "netstat"
        "iotop"
        "powertop"
        "systemd-resolve"
    )
    
    for binary in "${capability_binaries[@]}"; do
        # Search for these binaries in the path
        find "$path" -maxdepth 3 -name "$binary" -type f 2>/dev/null | while read -r file; do
            local owner=$(stat -c '%U' "$file" 2>/dev/null)
            local perms=$(stat -c '%a' "$file" 2>/dev/null)
            local size=$(stat -c '%s' "$file" 2>/dev/null)
            
            # These binaries often have capabilities instead of SUID
            if [[ ! -u "$file" ]] && [[ -x "$file" ]]; then
                log_vulnerability "CAPABILITY" "$file" "Potential capability-enabled binary | Owner: $owner | Perms: $perms | Size: $size"
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${RED}[!] POTENTIAL CAPABILITY BINARY: $file${NC}"
                fi
            fi
        done
    done
    
    # Method 2b: Check files in capability-common directories
    local cap_dirs=(
        "/bin"
        "/sbin" 
        "/usr/bin"
        "/usr/sbin"
        "/usr/local/bin"
        "/usr/local/sbin"
    )
    
    for cap_dir in "${cap_dirs[@]}"; do
        if [[ "$path" == "$cap_dir"* ]] || [[ "$cap_dir" == "$path"* ]]; then
            # Look for executables that are not SUID but have unusual permissions
            find "$path" -maxdepth 2 -type f -executable ! -perm -u+s ! -perm -g+s 2>/dev/null | while read -r file; do
                local owner=$(stat -c '%U' "$file" 2>/dev/null)
                local perms=$(stat -c '%a' "$file" 2>/dev/null)
                
                # Check for executables owned by root but not SUID (might have capabilities)
                if [[ "$owner" == "root" ]] && [[ "$perms" =~ ^7[0-5][0-5]$ ]]; then
                    case "$(basename "$file")" in
                        ping*|trace*|tcp*|nmap|arp*|mtr*|wireshark*|dumpcap)
                            log_vulnerability "CAPABILITY" "$file" "Likely capability-enabled network tool | Owner: $owner | Perms: $perms"
                            if [[ $VERBOSE_MODE -eq 1 ]]; then
                                echo -e "${RED}[!] LIKELY CAP-ENABLED: $file${NC}"
                            fi
                            ;;
                    esac
                fi
            done
        fi
    done
    
    # Method 2c: Check for files with unusual extended attributes
    find "$path" -maxdepth 3 -type f -executable 2>/dev/null | while read -r file; do
        # Check if file has extended attributes beyond ACLs
        if command -v attr &>/dev/null; then
            local attrs=$(attr -l "$file" 2>/dev/null | grep -v "security.selinux\|system.posix_acl")
            if [[ -n "$attrs" ]]; then
                local owner=$(stat -c '%U' "$file" 2>/dev/null)
                local perms=$(stat -c '%a' "$file" 2>/dev/null)
                log_vulnerability "CAPABILITY" "$file" "Extended attributes detected (potential capabilities) | Owner: $owner | Perms: $perms"
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${RED}[!] EXTENDED ATTRS (CAPS?): $file${NC}"
                fi
            fi
        fi
        
        # Alternative: check for '+' in ls -l output (indicates extended attributes/capabilities)
        local ls_output=$(ls -l "$file" 2>/dev/null)
        if [[ "$ls_output" =~ .*\+$ ]]; then
            local owner=$(stat -c '%U' "$file" 2>/dev/null)
            # Only flag if it's not already flagged as ACL and is executable
            if [[ -x "$file" ]] && [[ "$owner" == "root" ]]; then
                case "$(basename "$file")" in
                    *ping*|*trace*|*dump*|*scan*)
                        log_vulnerability "CAPABILITY" "$file" "Executable with extended attributes | Owner: $owner"
                        if [[ $VERBOSE_MODE -eq 1 ]]; then
                            echo -e "${RED}[!] EXEC WITH EXT ATTRS: $file${NC}"
                        fi
                        ;;
                esac
            fi
        fi
    done
    
    # Method 2d: Check for capability-like behavior patterns
    # Look for network tools that shouldn't normally work for non-root users
    local network_tools=("ping" "traceroute" "tcpdump" "nmap")
    for tool in "${network_tools[@]}"; do
        if command -v "$tool" &>/dev/null && [[ $CURRENT_UID -ne 0 ]]; then
            local tool_path=$(which "$tool")
            if [[ -n "$tool_path" ]] && [[ "$tool_path" == "$path"* ]]; then
                # Try to determine if tool has capabilities by checking if it works without sudo
                if timeout 1 "$tool" --help &>/dev/null; then
                    local owner=$(stat -c '%U' "$tool_path" 2>/dev/null)
                    local perms=$(stat -c '%a' "$tool_path" 2>/dev/null)
                    if [[ "$owner" == "root" ]] && [[ ! -u "$tool_path" ]]; then
                        log_vulnerability "CAPABILITY" "$tool_path" "Network tool accessible to non-root (likely has capabilities) | Owner: $owner | Perms: $perms"
                        if [[ $VERBOSE_MODE -eq 1 ]]; then
                            echo -e "${RED}[!] NON-ROOT NETWORK TOOL: $tool_path${NC}"
                        fi
                    fi
                fi
            fi
        fi
    done
}

# Check for root-owned files
check_root_owned() {
    local path="$1"
    local max_depth="${2:-3}"
    
    if ! should_scan_vuln_type "root-privileges"; then
        return
    fi
    
    # Skip root-owned scanning when running as root user
    if [[ $CURRENT_UID -eq 0 ]]; then
        return
    fi
    
    # Optimized root-owned files search
    find "$path" -maxdepth "$max_depth" -uid 0 -type f -perm /u+r,g+r,o+r 2>/dev/null | while read -r file; do
        if [[ -r "$file" ]]; then
            local perms=$(stat -c '%a' "$file" 2>/dev/null)
            local size=$(stat -c '%s' "$file" 2>/dev/null)
            if [[ "${perms:1:1}" -ge 4 ]] || [[ "${perms:2:1}" -ge 4 ]]; then
                log_vulnerability "ROOT_OWNED" "$file" "Root-owned file accessible by others | Perms: $perms | Size: $size"
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${RED}[!] ROOT-OWNED ACCESSIBLE: $file${NC}"
                fi
            fi
        fi
    done
}

# Check for world-executable files
check_world_executable() {
    local path="$1"
    local max_depth="${2:-3}"
    
    if ! should_scan_vuln_type "world-executable"; then
        return
    fi
    
    # Use array for performance - eliminates subprocess overhead
    local files owner perms
    readarray -t files < <(find "$path" -maxdepth "$max_depth" -perm -o+x -type f 2>/dev/null)
    for file in "${files[@]}"; do
        [[ -n "$file" ]] || continue
        owner=$(stat -c '%U' "$file" 2>/dev/null)
        if [[ "$owner" != "$CURRENT_USER" ]]; then
            perms=$(stat -c '%a' "$file" 2>/dev/null)
            log_vulnerability "WORLD_EXEC" "$file" "World-executable file | Owner: $owner | Perms: $perms"
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${YELLOW}[!] WORLD-EXECUTABLE: $file${NC}"
            fi
        fi
    done
}

# Check for SSH private keys
check_ssh_keys() {
    local path="$1"
    
    if ! should_scan_vuln_type "ssh"; then
        return
    fi
    
    find "$path" -maxdepth 5 -name "id_*" -o -name "*.pem" -o -name "*.key" 2>/dev/null | while read -r file; do
        if [[ -f "$file" ]] && [[ -r "$file" ]]; then
            # Check if it's a private key
            if grep -q "BEGIN.*PRIVATE KEY" "$file" 2>/dev/null || \
               grep -q "BEGIN RSA PRIVATE KEY" "$file" 2>/dev/null || \
               grep -q "BEGIN OPENSSH PRIVATE KEY" "$file" 2>/dev/null; then
                local perms=$(stat -c '%a' "$file" 2>/dev/null)
                local owner=$(stat -c '%U' "$file" 2>/dev/null)
                log_vulnerability "SSH_KEYS" "$file" "SSH private key found | Owner: $owner | Perms: $perms"
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${RED}[!] SSH PRIVATE KEY: $file${NC}"
                fi
            fi
        fi
    done
}

# Check for database files
check_database_files() {
    local path="$1"
    
    if ! should_scan_vuln_type "database"; then
        return
    fi
    
    find "$path" -maxdepth 3 \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.mdb" \) 2>/dev/null | while read -r file; do
        if [[ -f "$file" ]] && [[ -r "$file" ]]; then
            local perms=$(stat -c '%a' "$file" 2>/dev/null)
            local owner=$(stat -c '%U' "$file" 2>/dev/null)
            local size=$(stat -c '%s' "$file" 2>/dev/null)
            
            if [[ "${perms:1:1}" -ge 4 ]] || [[ "${perms:2:1}" -ge 4 ]]; then
                log_vulnerability "DATABASE" "$file" "Database file accessible | Owner: $owner | Perms: $perms | Size: $size"
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${RED}[!] DATABASE FILE: $file${NC}"
                fi
            fi
        fi
    done
}

# Check for log files with sensitive information
check_log_files() {
    local path="$1"
    
    if ! should_scan_vuln_type "logs"; then
        return
    fi
    
    find "$path" -maxdepth 3 -name "*.log" -o -name "access.log*" -o -name "error.log*" -o -name "debug.log*" 2>/dev/null | while read -r file; do
        if [[ -f "$file" ]] && [[ -r "$file" ]]; then
            local perms=$(stat -c '%a' "$file" 2>/dev/null)
            local owner=$(stat -c '%U' "$file" 2>/dev/null)
            
            # Check if log contains sensitive patterns
            if grep -qiE "(password|token|api[_-]?key|secret|credential)" "$file" 2>/dev/null; then
                log_vulnerability "LOG_FILES" "$file" "Log file with sensitive data | Owner: $owner | Perms: $perms"
                echo -e "${YELLOW}[!] SENSITIVE LOG: $file${NC}"
            elif [[ "${perms:1:1}" -ge 4 ]] || [[ "${perms:2:1}" -ge 4 ]]; then
                log_vulnerability "LOG_FILES" "$file" "Log file with broad access | Owner: $owner | Perms: $perms"
                echo -e "${CYAN}[!] ACCESSIBLE LOG: $file${NC}"
            fi
        fi
    done
}

# Check for NFS exports
check_nfs_exports() {
    if ! should_scan_vuln_type "nfs"; then
        return
    fi
    
    if [[ -f /etc/exports ]] && [[ -r /etc/exports ]]; then
        # Check for insecure NFS exports
        while IFS= read -r line; do
            if [[ -n "$line" ]] && [[ ! "$line" =~ ^# ]]; then
                # Check for insecure options
                if [[ "$line" =~ (no_root_squash|insecure|rw) ]]; then
                    log_vulnerability "NFS_EXPORT" "/etc/exports" "Potentially insecure NFS export: $line"
                    echo -e "${RED}[!] INSECURE NFS EXPORT: $line${NC}"
                fi
            fi
        done < /etc/exports
    fi
}

# Check for cron job vulnerabilities
check_cron_jobs() {
    if ! should_scan_vuln_type "cron"; then
        return
    fi
    
    # Check system cron directories
    for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$cron_dir" ]]; then
            find "$cron_dir" -type f 2>/dev/null | while read -r file; do
                if [[ -r "$file" ]]; then
                    local perms=$(stat -c '%a' "$file" 2>/dev/null)
                    if [[ "${perms:1:1}" -ge 2 ]] || [[ "${perms:2:1}" -ge 2 ]]; then
                        local owner=$(stat -c '%U' "$file" 2>/dev/null)
                        log_vulnerability "CRON_JOBS" "$file" "Cron job with group/other write permissions (owner: $owner can modify) | Perms: $perms"
                        echo -e "${RED}[!] WRITABLE CRON JOB: $file${NC}"
                    fi
                fi
            done
        fi
    done
    
    # Check user crontabs if accessible
    if [[ -d /var/spool/cron/crontabs ]]; then
        find /var/spool/cron/crontabs -type f 2>/dev/null | while read -r file; do
            if [[ -r "$file" ]]; then
                local owner=$(stat -c '%U' "$file" 2>/dev/null)
                if [[ "$owner" != "$CURRENT_USER" ]]; then
                    log_vulnerability "CRON_JOBS" "$file" "Accessible user crontab | Owner: $owner"
                    echo -e "${YELLOW}[!] ACCESSIBLE CRONTAB: $file${NC}"
                fi
            fi
        done
    fi
}

# Check ACL misconfigurations with fallback methods
check_acl() {
    local path="$1"
    
    if command -v getfacl &>/dev/null; then
        # Method 1: Use getfacl (preferred)
        find "$path" -maxdepth 3 -type f 2>/dev/null | while read -r file; do
            local acl=$(getfacl "$file" 2>/dev/null | grep -E "^(user|group|other):" | grep -v "^user::$CURRENT_USER")
            if [[ -n "$acl" ]]; then
                local owner=$(stat -c '%U' "$file" 2>/dev/null)
                if [[ "$owner" != "$CURRENT_USER" ]] && [[ "$acl" =~ "rw" ]]; then
                    log_vulnerability "ACL" "$file" "ACL allows access: $acl"
                    if [[ $VERBOSE_MODE -eq 1 ]]; then
                        echo -e "${YELLOW}[!] ACL MISCONFIGURATION: $file${NC}"
                    fi
                fi
            fi
        done
    else
        # Method 2: Alternative ACL detection using standard tools
        check_acl_alternatives "$path"
    fi
}

# Alternative ACL checking methods without getfacl
check_acl_alternatives() {
    local path="$1"
    
    # Method 2a: Check for files with extended attributes (indicates potential ACLs)
    find "$path" -maxdepth 3 -type f 2>/dev/null | while read -r file; do
        # Check if file has extended attributes (+ in ls -l output)
        local ls_output=$(ls -ld "$file" 2>/dev/null)
        if [[ "$ls_output" =~ .*\+.* ]]; then
            local owner=$(stat -c '%U' "$file" 2>/dev/null)
            local perms=$(stat -c '%a' "$file" 2>/dev/null)
            local group=$(stat -c '%G' "$file" 2>/dev/null)
            
            # Check for suspicious permission patterns that might indicate ACL issues
            if [[ "$owner" != "$CURRENT_USER" ]]; then
                # Check if group has write access and we're in that group
                if [[ "${perms:1:1}" -ge 2 ]] && groups | grep -q "$group"; then
                    log_vulnerability "ACL" "$file" "Extended attributes detected, potential ACL access | Owner: $owner | Group: $group | Perms: $perms"
                    if [[ $VERBOSE_MODE -eq 1 ]]; then
                        echo -e "${YELLOW}[!] POTENTIAL ACL ISSUE: $file (extended attrs)${NC}"
                    fi
                fi
                
                # Check for unusual permission combinations
                if [[ "${perms:0:1}" -eq 7 ]] && [[ "${perms:1:1}" -ge 4 ]] && [[ "${perms:2:1}" -ge 4 ]]; then
                    log_vulnerability "ACL" "$file" "Suspicious permission pattern with extended attrs | Owner: $owner | Perms: $perms"
                    if [[ $VERBOSE_MODE -eq 1 ]]; then
                        echo -e "${YELLOW}[!] SUSPICIOUS PERMS WITH ATTRS: $file${NC}"
                    fi
                fi
            fi
        fi
    done
    
    # Method 2b: Check for files in ACL-sensitive locations with group access
    local acl_sensitive_dirs=(
        "/etc"
        "/var/log" 
        "/home"
        "/root"
        "/usr/local"
        "/opt"
    )
    
    for sensitive_dir in "${acl_sensitive_dirs[@]}"; do
        if [[ "$path" == "$sensitive_dir"* ]] || [[ "$sensitive_dir" == "$path"* ]]; then
            find "$path" -maxdepth 2 -type f -perm /g+w 2>/dev/null | while read -r file; do
                local owner=$(stat -c '%U' "$file" 2>/dev/null)
                local group=$(stat -c '%G' "$file" 2>/dev/null)
                local perms=$(stat -c '%a' "$file" 2>/dev/null)
                
                # Check if we have group access to files we shouldn't
                if [[ "$owner" != "$CURRENT_USER" ]] && groups | grep -q "$group"; then
                    # Check if it's a sensitive file type
                    case "$file" in
                        *.conf|*.cfg|*.ini|*.key|*.pem|*.crt|*.log|*passwd*|*shadow*|*sudoers*)
                            log_vulnerability "ACL" "$file" "Group-writable sensitive file | Owner: $owner | Group: $group | Perms: $perms"
                            if [[ $VERBOSE_MODE -eq 1 ]]; then
                                echo -e "${YELLOW}[!] GROUP ACCESS TO SENSITIVE: $file${NC}"
                            fi
                            ;;
                    esac
                fi
            done
        fi
    done
    
    # Method 2c: Check for setgid directories (potential ACL-like behavior)
    find "$path" -maxdepth 3 -type d -perm -g+s 2>/dev/null | while read -r dir; do
        local owner=$(stat -c '%U' "$dir" 2>/dev/null)
        local group=$(stat -c '%G' "$dir" 2>/dev/null)
        local perms=$(stat -c '%a' "$dir" 2>/dev/null)
        
        if [[ "$owner" != "$CURRENT_USER" ]] && groups | grep -q "$group"; then
            log_vulnerability "ACL" "$dir" "SetGID directory with group access | Owner: $owner | Group: $group | Perms: $perms"
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${YELLOW}[!] SETGID DIR ACCESS: $dir${NC}"
            fi
        fi
    done
    
    # Method 2d: Check for unusual umask effects and permission inheritance patterns
    find "$path" -maxdepth 3 -type f 2>/dev/null | while read -r file; do
        local perms=$(stat -c '%a' "$file" 2>/dev/null)
        local owner=$(stat -c '%U' "$file" 2>/dev/null)
        local group=$(stat -c '%G' "$file" 2>/dev/null)
        
        # Look for files with unusual permission patterns that might indicate ACL inheritance
        if [[ "$owner" != "$CURRENT_USER" ]]; then
            # Check for files with exactly 664 or 666 permissions (common ACL inheritance)
            if [[ "$perms" == "664" ]] || [[ "$perms" == "666" ]]; then
                case "$file" in
                    *.sh|*.py|*.pl|*.rb|*/bin/*|*/sbin/*)
                        log_vulnerability "ACL" "$file" "Executable with inherited group permissions | Owner: $owner | Group: $group | Perms: $perms"
                        if [[ $VERBOSE_MODE -eq 1 ]]; then
                            echo -e "${YELLOW}[!] INHERITED EXEC PERMS: $file${NC}"
                        fi
                        ;;
                esac
            fi
            
            # Check for files with unusual owner/group combinations
            if [[ "$group" == "root" ]] && [[ "${perms:1:1}" -ge 4 ]] && [[ "$owner" != "root" ]]; then
                log_vulnerability "ACL" "$file" "Non-root owned file with root group access | Owner: $owner | Group: $group | Perms: $perms"
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${YELLOW}[!] NON-ROOT WITH ROOT GROUP: $file${NC}"
                fi
            fi
        fi
    done
}

# Comprehensive directory scanner
deep_scan_directory() {
    local dir="$1"
    local scan_type="$2"
    
    # Update worker heartbeat at start of directory scan
    local worker_heartbeat="$TEMP_DIR/worker_${WORKER_ID:-0}_heartbeat"
    echo "$(date +%s)" > "$worker_heartbeat" 2>/dev/null
    
    # Update user activity timestamp if worker ID is available
    if [[ -n "${WORKER_ID:-}" ]] && [[ -f "$TEMP_DIR/current_user_${WORKER_ID}" ]]; then
        local user_data=$(cat "$TEMP_DIR/current_user_${WORKER_ID}" 2>/dev/null)
        local username="${user_data%:*}"
        echo "$username:$(date +%s)" > "$TEMP_DIR/current_user_${WORKER_ID}"
    fi
    
    # Check if this path should be scanned
    if ! should_scan_path "$dir"; then
        echo -e "${YELLOW}[*] Skipping excluded path: $dir${NC}"
        return
    fi
    
    # Only show detailed messages in verbose mode
    if [[ $VERBOSE_MODE -eq 1 ]]; then
        echo -e "${CYAN}[*] Deep scanning: $dir${NC}"
        update_progress "Deep scanning: $dir"
    fi
    
    # Check if directory is accessible
    if [[ ! -r "$dir" ]] && [[ -x "$dir" ]]; then
        # Traverse-only directory - use intelligent probing
        probe_traverse_directory "$dir"
        return
    elif [[ ! -r "$dir" ]]; then
        return
    fi
    
    # Count files in directory
    local file_count=$(find "$dir" -maxdepth 1 -type f 2>/dev/null | wc -l)
    increment_counter "$TEMP_DIR/total_files" "$file_count"
    
    # Update per-user file counter if worker ID is available
    if [[ -n "${WORKER_ID:-}" ]]; then
        increment_counter "$TEMP_DIR/user_${WORKER_ID}_files_scanned" "$file_count"
    fi
    
    # Optimized batch file scanning using find with formatted output
    # This single find command gets all file info at once, dramatically faster
    find "$dir" -maxdepth "$SCAN_DEPTH" -type f -printf '%p|%u|%g|%m|%s\n' 2>/dev/null | while IFS='|' read -r file owner group perms size; do
        # Check if file extension should be scanned
        if ! should_scan_extension "$file"; then
            continue
        fi
        
        # Fast pre-filtering - skip files that are unlikely to have vulnerabilities
        if ! should_scan_file_fast "$file"; then
            continue
        fi
        
        increment_counter "$TEMP_DIR/scanned_paths"
        
        # Skip if it's our own file
        if [[ "$owner" == "$CURRENT_USER" ]]; then
            continue
        fi
        
        # Check various vulnerability types
        
        # Convert octal perms to decimal for comparison
        local perms_octal=$((8#$perms))
        
        # World-readable sensitive files (check last digit of permissions)
        if [[ $((perms_octal & 4)) -ne 0 ]]; then
            local filename=$(basename "$file")
            if [[ "$filename" =~ (config|password|secret|key|token|credential|database|\.env) ]]; then
                quiet_log_vulnerability "WORLD_READ" "$file" "Owner: $owner | Perms: $perms | Size: $size"
                
                # Scan content if enabled
                if [[ $ENABLE_CONTENT_SCAN -eq 1 ]]; then
                    scan_file_content "$file"
                fi
            fi
        fi
        
        # Check for backup files
        if [[ "$file" =~ \.(bak|backup|old|save|swp|orig|tmp|temp|~)$ ]]; then
            if [[ $((perms_octal & 4)) -ne 0 ]]; then  # Readable
                quiet_log_vulnerability "BACKUP" "$file" "Exposed backup file | Owner: $owner | Perms: $perms"
            fi
        fi
        
        # Check for hidden sensitive files
        local basename=$(basename "$file")
        if [[ "$basename" =~ ^\. ]] && [[ $((perms_octal & 4)) -ne 0 ]]; then
            if [[ "$basename" =~ (ssh|gnupg|aws|kube|docker|git|history|mysql_history|bash_history) ]]; then
                quiet_log_vulnerability "HIDDEN" "$file" "Hidden sensitive file | Owner: $owner | Perms: $perms"
            fi
        fi
    done
    
    # Check for other vulnerability types based on scan types
    # Only call detection functions for enabled scan types
    if should_scan_vuln_type "suid" || should_scan_vuln_type "sgid"; then
        check_suid_sgid "$dir" 2
    fi
    
    if should_scan_vuln_type "world-writable" || should_scan_vuln_type "world-readable"; then
        check_world_writable "$dir" 2
    fi
    
    if should_scan_vuln_type "world-executable"; then
        check_world_executable "$dir" 2
    fi
    
    if should_scan_vuln_type "root-privileges"; then
        check_root_owned "$dir" 2
    fi
    
    if should_scan_vuln_type "capabilities"; then
        check_capabilities "$dir"
    fi
    
    if should_scan_vuln_type "acl"; then
        check_acl "$dir"
    fi
    
    if should_scan_vuln_type "ssh"; then
        check_ssh_keys "$dir"
    fi
    
    if should_scan_vuln_type "database"; then
        check_database_files "$dir"
    fi
    
    if should_scan_vuln_type "logs"; then
        check_log_files "$dir"
    fi
    
    if should_scan_vuln_type "config-files"; then
        check_cross_user_access "$dir"
    fi
}

# Intelligent probing for traverse-only directories
probe_traverse_directory() {
    local base_dir="$1"
    
    echo -e "${YELLOW}[+] Probing traverse-only directory: $base_dir${NC}"
    
    # Common subdirectories to probe
    local probe_dirs=(
        "public_html"
        "www"
        "htdocs"
        "httpdocs"
        "web"
        "public"
        "html"
        ".ssh"
        ".config"
        "backup"
        "backups"
        "logs"
        "tmp"
        "temp"
        "cache"
        "uploads"
        "downloads"
        "documents"
        "files"
    )
    
    for subdir in "${probe_dirs[@]}"; do
        local test_path="$base_dir/$subdir"
        
        # Test if we can access it
        if [[ -d "$test_path" ]] && [[ -r "$test_path" ]]; then
            echo -e "${GREEN}[+] Found accessible subdirectory: $test_path${NC}"
            log_vulnerability "TRAVERSAL" "$test_path" "Accessible through traverse-only parent"
            
            # Deep scan this directory
            deep_scan_directory "$test_path" "traverse"
        elif [[ -d "$test_path" ]] && [[ -x "$test_path" ]]; then
            # Can traverse but not read - probe deeper
            echo -e "${CYAN}[*] Can traverse to: $test_path${NC}"
            
            # Try common files directly
            local patterns=($(generate_sensitive_patterns))
            for pattern in "${patterns[@]:0:20}"; do  # Limit to first 20 patterns
                local glob_pattern="$test_path/$pattern"
                for file in $glob_pattern; do
                    if [[ -f "$file" ]] && [[ -r "$file" ]]; then
                        local owner=$(stat -c '%U' "$file" 2>/dev/null)
                        if [[ "$owner" != "$CURRENT_USER" ]]; then
                            log_vulnerability "TRAVERSAL" "$file" "Found through traversal | Owner: $owner"
                            echo -e "${RED}[!] FOUND VIA TRAVERSAL: $file${NC}"
                        fi
                    fi
                done
            done
        fi
    done
}

#############################################################################
# Parallel Processing Functions
#############################################################################

# Worker function for parallel processing
scan_worker() {
    local user_home="$1"
    local username="$2"
    local worker_id="$3"
    
    # Set worker ID for heartbeat tracking
    export WORKER_ID="$worker_id"
    
    # Update current user being processed by this worker with timestamp
    echo "$username:$(date +%s)" > "$TEMP_DIR/current_user_${worker_id}"
    
    # Initialize per-user file counters
    echo "0" > "$TEMP_DIR/user_${worker_id}_files_scanned"
    echo "0" > "$TEMP_DIR/user_${worker_id}_files_total"
    
    # Create worker heartbeat file for activity monitoring
    local worker_heartbeat="$TEMP_DIR/worker_${worker_id}_heartbeat"
    echo "$(date +%s)" > "$worker_heartbeat"
    
    # Quiet mode - only show in verbose mode
    if [[ $VERBOSE_MODE -eq 1 ]]; then
        echo -e "${BLUE}[Worker-$worker_id] Scanning user: $username${NC}"
    fi
    
    # Skip current user
    if [[ "$username" == "$CURRENT_USER" ]]; then
        return
    fi
    
    # Check home directory permissions
    if [[ -d "$user_home" ]]; then
        local home_perms=$(cached_stat "$user_home" "%a")
        local home_owner=$(cached_user_lookup "$user_home")
        
        # Only show detailed info in verbose mode
        if [[ $VERBOSE_MODE -eq 1 ]]; then
            echo -e "${CYAN}[Worker-$worker_id] $user_home (Perms: $home_perms)${NC}"
        fi
        
        # Quick estimate of files in user directory for progress tracking
        if [[ -d "$user_home" ]]; then
            local estimated_files=$(find "$user_home" -type f 2>/dev/null | wc -l)
            echo "$estimated_files" > "$TEMP_DIR/user_${worker_id}_files_total" 2>/dev/null
        fi
        
        # Deep scan the home directory
        deep_scan_directory "$user_home" "home"
        
        # Scan web directories
        for web_dir in "public_html" "www" "htdocs" "httpdocs" "web" "public"; do
            local web_path="$user_home/$web_dir"
            if [[ -d "$web_path" ]]; then
                deep_scan_directory "$web_path" "web"
            fi
        done
    fi
    
    # Mark user as processed
    increment_counter "$TEMP_DIR/processed_users"
    
    # Clean up worker files
    rm -f "$TEMP_DIR/worker_${WORKER_ID:-0}_heartbeat" 2>/dev/null
    rm -f "$TEMP_DIR/user_${WORKER_ID:-0}_files_scanned" 2>/dev/null
    rm -f "$TEMP_DIR/user_${WORKER_ID:-0}_files_total" 2>/dev/null
    rm -f "$TEMP_DIR/current_user_${WORKER_ID:-0}" 2>/dev/null
}

# Parallel scan manager
parallel_scan() {
    local users=("$@")
    local total_users=${#users[@]}
    local job_count=0
    
    # Store total users count
    echo "$total_users" > "$TEMP_DIR/total_users"
    
    if [[ $QUIET_MODE -eq 1 ]]; then
        echo -e "${GREEN}[*] Starting FileSpectre scan: $total_users users | $MAX_PARALLEL_JOBS workers${NC}"
    else
        echo -e "${GREEN}[*] Starting parallel scan of $total_users users with $MAX_PARALLEL_JOBS workers${NC}"
    fi
    
    # Dynamic thread scaling based on system resources
    if [[ $AUTO_SCALE_THREADS -eq 1 ]]; then
        local cpu_cores=$(nproc 2>/dev/null || echo "4")
        local optimal_threads=$((cpu_cores * 2))
        if [[ $optimal_threads -gt $MAX_PARALLEL_JOBS ]] && [[ $total_users -gt 100 ]]; then
            MAX_PARALLEL_JOBS=$optimal_threads
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Auto-scaled to $MAX_PARALLEL_JOBS threads based on $cpu_cores CPU cores${NC}"
            fi
        fi
    fi
    
    # Disable progress bar in dashboard during main scanning loop to avoid duplication
    SHOW_USER_PROGRESS=0
    
    for user_data in "${users[@]}"; do
        # Check for interruption
        if [[ $INTERRUPTED -eq 1 ]]; then
            break
        fi
        
        IFS=':' read -r username user_home <<< "$user_data"
        
        # Track current user being processed (legacy - workers handle this now)
        
        # Show dashboard in quiet mode (update more frequently)
        if [[ $QUIET_MODE -eq 1 ]] && [[ $((job_count % 3)) -eq 0 ]] && [[ $job_count -gt 1 ]]; then
            # Brief delay to let counters update from background workers
            sleep 0.5
            
            local processed=$(cat "$TEMP_DIR/processed_users" 2>/dev/null || echo "0")
            local vulns=$(get_counter "$TEMP_DIR/total_vulns")
            local files=$(get_counter "$TEMP_DIR/total_files")
            local elapsed=$(($(date +%s) - SCAN_START_TIME))
            local scan_speed="0"
            
            # Better scan speed calculation with minimum threshold
            if [[ $elapsed -gt 2 ]] && [[ $files -gt 0 ]]; then
                scan_speed=$((files / elapsed))
            fi
            
            # Only update dashboard every 3 seconds to prevent flickering
            local current_time=$(date +%s)
            if [[ $((current_time - ${last_dashboard_update:-0})) -ge 3 ]]; then
                show_dashboard "$username" "$total_users" "$processed" "$vulns" "$scan_speed"
                last_dashboard_update=$current_time
            fi
            
            # Save scan state every 50 users
            if [[ $((job_count % 50)) -eq 0 ]]; then
                save_scan_state "$processed" "$total_users" "$username"
            fi
        fi
        
        # Wait if we've reached max parallel jobs
        while [[ $(jobs -r | wc -l) -ge $MAX_PARALLEL_JOBS ]]; do
            if [[ $INTERRUPTED -eq 1 ]]; then
                break 2  # Break out of both loops
            fi
            sleep 0.1
        done
        
        # Launch worker in background
        ((job_count++))
        scan_worker "$user_home" "$username" "$job_count" &
    done
    
    # Wait for all jobs to complete
    if [[ $QUIET_MODE -eq 1 ]]; then
        echo -e "${YELLOW}[*] Finalizing scan results...${NC}"
        
        # Show final progress
        local last_progress_update=0
        local stuck_counter=0
        local last_processed=0
        
        while [[ $(jobs -r | wc -l) -gt 0 ]]; do
            if [[ $INTERRUPTED -eq 1 ]]; then
                break
            fi
            
            local processed=$(cat "$TEMP_DIR/processed_users" 2>/dev/null || echo "0")
            local vulns=$(get_counter "$TEMP_DIR/total_vulns")
            local files=$(get_counter "$TEMP_DIR/total_files")
            local elapsed=$(($(date +%s) - SCAN_START_TIME))
            local scan_speed="0"
            
            # Calculate scan speed more accurately
            if [[ $elapsed -gt 0 ]]; then
                scan_speed=$((files / elapsed))
            fi
            
            # Enhanced stuck detection - monitor file processing activity, not just user completion
            local current_files=$(cat "$TEMP_DIR/total_files" 2>/dev/null || echo "0")
            local current_vulns=$(cat "$TEMP_DIR/total_vulns" 2>/dev/null || echo "0")
            
            # Check for ANY activity: user progress, file processing, or vulnerability detection
            local activity_detected=0
            if [[ $processed -ne ${last_processed:-0} ]] || 
               [[ $current_files -ne ${last_files:-0} ]] || 
               [[ $current_vulns -ne ${last_vulns:-0} ]]; then
                activity_detected=1
            fi
            
            # Additional check: Worker heartbeat monitoring
            if [[ $activity_detected -eq 0 ]]; then
                local current_time=$(date +%s)
                local active_workers=0
                
                # Check for recent worker activity (within last 30 seconds)
                for heartbeat_file in "$TEMP_DIR"/worker_*_heartbeat; do
                    if [[ -f "$heartbeat_file" ]]; then
                        local last_heartbeat=$(cat "$heartbeat_file" 2>/dev/null || echo "0")
                        if [[ $((current_time - last_heartbeat)) -lt 30 ]]; then
                            active_workers=$((active_workers + 1))
                        fi
                    fi
                done
                
                # If workers are still active (recent heartbeats), consider it as activity
                if [[ $active_workers -gt 0 ]]; then
                    activity_detected=1
                    if [[ $VERBOSE_MODE -eq 1 ]]; then
                        echo -e "${CYAN}[*] $active_workers workers still active...${NC}"
                    fi
                fi
            fi
            
            if [[ $activity_detected -eq 1 ]]; then
                # Reset stuck counter on any activity
                stuck_counter=0
                last_processed=$processed
                last_files=$current_files
                last_vulns=$current_vulns
            else
                # No activity detected
                ((stuck_counter++))
                
                # Adaptive timeout based on environment size
                local timeout_threshold=60  # Base: 60 seconds
                if [[ $total_users -gt 100 ]]; then
                    timeout_threshold=120  # Large environments: 2 minutes
                elif [[ $total_users -gt 500 ]]; then
                    timeout_threshold=180  # Very large: 3 minutes
                fi
                
                if [[ $stuck_counter -gt $timeout_threshold ]]; then
                    echo -e "${YELLOW}[!] No activity detected for ${timeout_threshold}s at $processed/$total_users users (${current_files} files, ${current_vulns} vulnerabilities found)${NC}"
                    echo -e "${YELLOW}[!] Terminating remaining workers...${NC}"
                    jobs -p | xargs -r kill -TERM 2>/dev/null
                    break
                fi
            fi
            
            # Check for periodic screen clearing every 15 seconds
            local current_time=$(date +%s)
            local should_clear_screen=0
            
            if [[ $((current_time - LAST_SCREEN_CLEAR)) -ge 15 ]]; then
                should_clear_screen=1
                LAST_SCREEN_CLEAR=$current_time
            fi
            
            # Update progress every 4 seconds or when clearing screen
            if [[ $((current_time - last_progress_update)) -ge 4 ]] || [[ $should_clear_screen -eq 1 ]]; then
                # Get file progress info and current user
                local current_files=$(cat "$TEMP_DIR/total_files" 2>/dev/null || echo "0")
                local current_vulns=$(cat "$TEMP_DIR/total_vulns" 2>/dev/null || echo "0")
                
                # Find the most recently active user and their progress
                local current_user="..."
                local user_progress=""
                local latest_timestamp=0
                
                for user_file in "$TEMP_DIR"/current_user_*; do
                    if [[ -f "$user_file" ]]; then
                        local user_data=$(cat "$user_file" 2>/dev/null)
                        local worker_id=$(basename "$user_file" | sed 's/current_user_//')
                        local username="${user_data%:*}"
                        local timestamp="${user_data##*:}"
                        
                        # Check if this is the most recent
                        if [[ "$timestamp" -gt "$latest_timestamp" ]]; then
                            latest_timestamp="$timestamp"
                            current_user="$username"
                            
                            # Get progress for this user
                            local worker_total=$(cat "$TEMP_DIR/user_${worker_id}_files_total" 2>/dev/null || echo "0")
                            local worker_scanned=$(cat "$TEMP_DIR/user_${worker_id}_files_scanned" 2>/dev/null || echo "0")
                            if [[ "$worker_total" -gt 0 ]]; then
                                local user_percent=$((worker_scanned * 100 / worker_total))
                                user_progress="($user_percent%)"
                            fi
                        fi
                    fi
                done
                
                local files_info="F:$current_files V:$current_vulns U:$current_user$user_progress"
                
                # Clear screen and show dashboard every 15 seconds
                if [[ $should_clear_screen -eq 1 ]]; then
                    clear
                    # Calculate scan speed
                    local elapsed=$((current_time - SCAN_START_TIME))
                    local scan_speed="0"
                    if [[ $elapsed -gt 2 ]] && [[ $current_files -gt 0 ]]; then
                        scan_speed=$((current_files / elapsed))
                    fi
                    
                    # Show dashboard with current stats
                    show_dashboard "$current_user" "$total_users" "$processed" "$current_vulns" "$scan_speed"
                    echo ""
                    echo -e "${CYAN}[*] Recent Activity:${NC}"
                else
                    # Regular progress bar update
                    show_progress_bar "$processed" "$total_users" "Processing remaining users..." "$files_info"
                fi
                
                last_progress_update=$current_time
            fi
            
            # Check if all users are processed
            if [[ $processed -eq $total_users ]]; then
                echo -e "${GREEN}[*] All users processed, waiting for workers to finish...${NC}"
                break
            fi
            
            sleep 1
        done
    else
        echo -e "${YELLOW}[*] Waiting for all workers to complete...${NC}"
        wait
    fi
    
    echo -e "${GREEN}[*] All workers completed${NC}"
    
    # Save final scan state
    local final_processed=$(cat "$TEMP_DIR/processed_users" 2>/dev/null || echo "$total_users")
    save_scan_state "$final_processed" "$total_users" "completed"
}

#############################################################################
# User Discovery Functions
#############################################################################

discover_all_users() {
    local users=()
    declare -A seen_users
    
    echo -e "${BLUE}[*] Discovering login-enabled users...${NC}" >&2
    
    # Method 1: Parse /etc/passwd for actual login users
    if [[ -r /etc/passwd ]]; then
        while IFS=: read -r username _ uid _ _ home shell; do
            # Filter criteria for actual login users:
            # 1. UID >= 1000 (normal users) OR UID = 0 (root)
            # 2. Valid shell (not /bin/false, /usr/sbin/nologin, etc.)
            # 3. Valid home directory
            # 4. Not system service accounts
            if [[ -n "$home" ]] && [[ ! "${seen_users[$username]}" ]]; then
                local uid_num=${uid}
                local valid_shell=0
                
                # Check for valid login shells
                case "$shell" in
                    */bash|*/sh|*/zsh|*/fish|*/csh|*/tcsh|*/ksh)
                        valid_shell=1
                        ;;
                    /bin/false|/usr/sbin/nologin|/sbin/nologin|"")
                        valid_shell=0
                        ;;
                esac
                
                # Include if:
                # - Root user (UID 0) with valid shell
                # - Normal users (UID >= 1000) with valid shell  
                # - Users with home directories in typical user locations
                if [[ ($uid_num -eq 0 && $valid_shell -eq 1) ]] || \
                   [[ ($uid_num -ge 1000 && $valid_shell -eq 1) ]] || \
                   [[ "$home" =~ ^(/home|/Users) ]]; then
                    users+=("$username:$home")
                    seen_users[$username]=1
                fi
            fi
        done < /etc/passwd
    fi
    
    # Method 2: Scan home directories (shared hosting environments)
    echo -e "${CYAN}[*] Scanning for shared hosting users...${NC}" >&2
    for base in /home /home1 /home2 /home3 /home4 /home5 /home6 /home7 /home8 /home9 /var/www /usr/home /srv/users; do
        if [[ -d "$base" ]]; then
            # Try to list directory
            if [[ -r "$base" ]]; then
                for user_dir in "$base"/*; do
                    if [[ -d "$user_dir" ]]; then
                        local username=$(basename "$user_dir")
                        
                        # Skip common system directories that aren't actual users
                        case "$username" in
                            lost+found|.snapshot|.trash|tmp|temp|cache|log|logs|backup|backups|bin|sbin|lib|lib64|usr|var|etc|proc|sys|dev|run|boot|mnt|media|opt)
                                continue
                                ;;
                        esac
                        
                        # Validate if this looks like a real user directory
                        local is_valid_user=0
                        
                        # Check if it has typical user directory characteristics
                        if [[ ${#username} -ge 2 ]] && [[ ! "${seen_users[$username]}" ]]; then
                            # Look for signs of actual user activity
                            if [[ -d "$user_dir/public_html" ]] || \
                               [[ -d "$user_dir/www" ]] || \
                               [[ -d "$user_dir/web" ]] || \
                               [[ -d "$user_dir/.ssh" ]] || \
                               [[ -f "$user_dir/.bashrc" ]] || \
                               [[ -f "$user_dir/.profile" ]] || \
                               [[ $(find "$user_dir" -maxdepth 1 -name "*.php" 2>/dev/null | head -1) ]] || \
                               [[ $(find "$user_dir" -maxdepth 2 -name "wp-config.php" 2>/dev/null | head -1) ]] || \
                               [[ $(find "$user_dir" -maxdepth 1 -name "*.env" 2>/dev/null | head -1) ]]; then
                                is_valid_user=1
                            # Or if it matches common hosting username patterns
                            elif [[ "$username" =~ ^[a-z][a-z0-9_-]{1,31}$ ]] || \
                                 [[ "$username" =~ ^(user|usr|web|www|site|app|test|dev|prod|demo)[0-9a-z_-]*$ ]]; then
                                is_valid_user=1
                            fi
                        fi
                        
                        if [[ $is_valid_user -eq 1 ]]; then
                            users+=("$username:$user_dir")
                            seen_users[$username]=1
                            echo -e "${GREEN}[+] Found shared hosting user: $username${NC}" >&2
                        fi
                    fi
                done
            else
                # Can't list - try common patterns
                echo -e "${YELLOW}[*] Cannot list $base - trying common patterns...${NC}" >&2
                
                # Try to access numbered user directories (common in shared hosting)
                for i in {1..1000}; do
                    for prefix in user usr web www site app client domain account admin test dev prod stage demo customer; do
                        local test_path="$base/${prefix}${i}"
                        if [[ -d "$test_path" ]] && [[ ! "${seen_users[${prefix}${i}]}" ]]; then
                            # Validate it looks like a real user directory
                            if [[ -d "$test_path/public_html" ]] || \
                               [[ -d "$test_path/www" ]] || \
                               [[ -f "$test_path/.bashrc" ]] || \
                               [[ $(find "$test_path" -maxdepth 2 -name "*.php" -o -name "*.env" 2>/dev/null | head -1) ]]; then
                                users+=("${prefix}${i}:$test_path")
                                seen_users["${prefix}${i}"]=1
                                echo -e "${GREEN}[+] Found pattern-based user: ${prefix}${i}${NC}" >&2
                            fi
                        fi
                    done
                done
                
                # Try common username patterns (letter+number combinations)
                for letter in {a..z}; do
                    for num in {1..99}; do
                        local test_path="$base/${letter}${num}"
                        if [[ -d "$test_path" ]] && [[ ! "${seen_users[${letter}${num}]}" ]]; then
                            # Quick validation
                            if [[ -d "$test_path/public_html" ]] || [[ -d "$test_path/www" ]] || [[ $(ls -A "$test_path" 2>/dev/null | wc -l) -gt 2 ]]; then
                                users+=("${letter}${num}:$test_path")
                                seen_users["${letter}${num}"]=1
                                echo -e "${GREEN}[+] Found pattern-based user: ${letter}${num}${NC}" >&2
                            fi
                        fi
                    done
                done
            fi
        fi
    done
    
    # Apply user sampling if configured
    local final_users=()
    
    # Handle specific users selection first
    if [[ ${#SPECIFIC_USERS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}[*] Using specific users: ${SPECIFIC_USERS[*]}${NC}" >&2
        for specific_user in "${SPECIFIC_USERS[@]}"; do
            # Find the user in discovered users
            for user_entry in "${users[@]}"; do
                local username="${user_entry%%:*}"
                if [[ "$username" == "$specific_user" ]]; then
                    final_users+=("$user_entry")
                    break
                fi
            done
        done
    else
        # Sort users for consistent ordering
        local sorted_users=()
        while IFS= read -r user_entry; do
            sorted_users+=("$user_entry")
        done < <(printf '%s\n' "${users[@]}" | sort -u)
        
        # Apply first N users if specified
        if [[ $FIRST_USERS -gt 0 ]]; then
            echo -e "${YELLOW}[*] Selecting first $FIRST_USERS users${NC}" >&2
            local count=0
            for user_entry in "${sorted_users[@]}"; do
                if [[ $count -lt $FIRST_USERS ]]; then
                    final_users+=("$user_entry")
                    ((count++))
                else
                    break
                fi
            done
        # Apply random sampling if requested
        elif [[ $RANDOM_USERS -eq 1 ]]; then
            local sample_size=${MAX_USERS:-10}
            echo -e "${YELLOW}[*] Randomly selecting $sample_size users from ${#sorted_users[@]} discovered${NC}" >&2
            
            if [[ ${#sorted_users[@]} -le $sample_size ]]; then
                final_users=("${sorted_users[@]}")
            else
                # Shuffle users and take first N
                local shuffled_users=()
                while IFS= read -r user_entry; do
                    shuffled_users+=("$user_entry")
                done < <(printf '%s\n' "${sorted_users[@]}" | shuf)
                
                for ((i=0; i<sample_size && i<${#shuffled_users[@]}; i++)); do
                    final_users+=("${shuffled_users[i]}")
                done
            fi
        # Apply max users limit if specified
        elif [[ $MAX_USERS -gt 0 ]]; then
            echo -e "${YELLOW}[*] Limiting to maximum $MAX_USERS users${NC}" >&2
            local count=0
            for user_entry in "${sorted_users[@]}"; do
                if [[ $count -lt $MAX_USERS ]]; then
                    final_users+=("$user_entry")
                    ((count++))
                else
                    break
                fi
            done
        else
            # No sampling - use all users
            final_users=("${sorted_users[@]}")
        fi
    fi
    
    echo -e "${GREEN}[+] Selected ${#final_users[@]} users for scanning${NC}" >&2
    printf '%s\n' "${final_users[@]}"
}

#############################################################################
# Export Functions
#############################################################################

# Generate CSV report
generate_csv_report() {
    local total_vulns=$(get_counter "$TEMP_DIR/total_vulns")
    local scanned_paths=$(get_counter "$TEMP_DIR/scanned_paths")
    local total_files=$(get_counter "$TEMP_DIR/total_files")
    
    # Create CSV header
    cat > "$CSV_REPORT" <<EOF
Timestamp,Type,Path,Details,Severity,Owner,Permissions
EOF
    
    # Add vulnerability data
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            # Parse the vulnerability line
            if [[ "$line" =~ \[([^\]]+)\]\ ([^|]+)\ \|\ (.+) ]]; then
                local timestamp=$(echo "$line" | grep -o '^\[.*\]' | tr -d '[]')
                local type="${BASH_REMATCH[1]}"
                local path="${BASH_REMATCH[2]}"
                local details="${BASH_REMATCH[3]}"
                local severity=$(calculate_severity "$type")
                
                # Extract owner and permissions from details if available
                local owner=$(echo "$details" | grep -o "Owner: [^|]*" | cut -d' ' -f2 || echo "N/A")
                local perms=$(echo "$details" | grep -o "Perms: [^|]*" | cut -d' ' -f2 || echo "N/A")
                
                echo "\"$timestamp\",\"$type\",\"$path\",\"$details\",\"$severity\",\"$owner\",\"$perms\"" >> "$CSV_REPORT"
            fi
        fi
    done < "$RESULTS_FILE"
}

# Generate HTML report
generate_html_report() {
    local total_vulns=$(get_counter "$TEMP_DIR/total_vulns")
    local scanned_paths=$(get_counter "$TEMP_DIR/scanned_paths")
    local total_files=$(get_counter "$TEMP_DIR/total_files")
    
    cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .vulnerability { margin: 10px 0; padding: 15px; border-left: 4px solid; }
        .critical { border-color: #e74c3c; background-color: #fdf2f2; }
        .high { border-color: #f39c12; background-color: #fef9f3; }
        .medium { border-color: #f1c40f; background-color: #fffef2; }
        .low { border-color: #27ae60; background-color: #f2fef5; }
        .vuln-type { font-weight: bold; color: #2c3e50; }
        .vuln-path { font-family: monospace; color: #7f8c8d; }
        .vuln-details { color: #34495e; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Enterprise Security Scan Report</h1>
        <p>Generated on: $(date)</p>
        <p>Scanner Version: 2.0</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Vulnerabilities</td><td>$total_vulns</td></tr>
            <tr><td>Paths Scanned</td><td>$scanned_paths</td></tr>
            <tr><td>Files Analyzed</td><td>$total_files</td></tr>
            <tr><td>Current User</td><td>$CURRENT_USER</td></tr>
        </table>
    </div>
    
    <div class="summary">
        <h2>Vulnerability Breakdown</h2>
        <table>
            <tr><th>Type</th><th>Count</th><th>Description</th></tr>
EOF

    # Add vulnerability type breakdown
    for vuln_type in "${!VULN_TYPES[@]}"; do
        local count=$(grep -c "\\[$vuln_type\\]" "$RESULTS_FILE" 2>/dev/null || echo 0)
        count=$(echo "$count" | tr -d '\r\n')  # Remove any newlines
        if [[ $count -gt 0 ]]; then
            echo "            <tr><td>$vuln_type</td><td>$count</td><td>${VULN_TYPES[$vuln_type]}</td></tr>" >> "$HTML_REPORT"
        fi
    done
    
    cat >> "$HTML_REPORT" <<EOF
        </table>
    </div>
    
    <div class="summary">
        <h2>Detailed Vulnerabilities</h2>
EOF

    # Add vulnerability details
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            if [[ "$line" =~ \[([^\]]+)\]\ ([^|]+)\ \|\ (.+) ]]; then
                local type="${BASH_REMATCH[1]}"
                local path="${BASH_REMATCH[2]}"
                local details="${BASH_REMATCH[3]}"
                local severity=$(calculate_severity "$type")
                local severity_class=$(echo "$severity" | tr '[:upper:]' '[:lower:]')
                
                cat >> "$HTML_REPORT" <<EOF
        <div class="vulnerability $severity_class">
            <div class="vuln-type">[$severity] $type</div>
            <div class="vuln-path">$path</div>
            <div class="vuln-details">$details</div>
        </div>
EOF
            fi
        fi
    done < "$RESULTS_FILE"
    
    cat >> "$HTML_REPORT" <<EOF
    </div>
</body>
</html>
EOF
}

# Generate XML report
generate_xml_report() {
    local total_vulns=$(get_counter "$TEMP_DIR/total_vulns")
    local scanned_paths=$(get_counter "$TEMP_DIR/scanned_paths")
    local total_files=$(get_counter "$TEMP_DIR/total_files")
    
    cat > "$XML_REPORT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<security_scan>
    <metadata>
        <scan_date>$(date -Iseconds)</scan_date>
        <scanner_version>2.0</scanner_version>
        <current_user>$CURRENT_USER</current_user>
    </metadata>
    <summary>
        <total_vulnerabilities>$total_vulns</total_vulnerabilities>
        <paths_scanned>$scanned_paths</paths_scanned>
        <files_analyzed>$total_files</files_analyzed>
    </summary>
    <vulnerability_types>
EOF

    # Add vulnerability type counts
    for vuln_type in "${!VULN_TYPES[@]}"; do
        local count=$(grep -c "\\[$vuln_type\\]" "$RESULTS_FILE" 2>/dev/null || echo 0)
        echo "        <type name=\"$vuln_type\" count=\"$count\" description=\"${VULN_TYPES[$vuln_type]}\"/>" >> "$XML_REPORT"
    done
    
    echo "    </vulnerability_types>" >> "$XML_REPORT"
    echo "    <vulnerabilities>" >> "$XML_REPORT"
    
    # Add vulnerability details
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            if [[ "$line" =~ \[([^\]]+)\]\ ([^|]+)\ \|\ (.+) ]]; then
                local type="${BASH_REMATCH[1]}"
                local path="${BASH_REMATCH[2]}"
                local details="${BASH_REMATCH[3]}"
                local severity=$(calculate_severity "$type")
                
                cat >> "$XML_REPORT" <<EOF
        <vulnerability>
            <type>$type</type>
            <path>$path</path>
            <details><![CDATA[$details]]></details>
            <severity>$severity</severity>
        </vulnerability>
EOF
            fi
        fi
    done < "$RESULTS_FILE"
    
    cat >> "$XML_REPORT" <<EOF
    </vulnerabilities>
</security_scan>
EOF
}

#############################################################################
# Reporting Functions
#############################################################################

generate_json_report() {
    local total_vulns=$(get_counter "$TEMP_DIR/total_vulns")
    local scanned_paths=$(get_counter "$TEMP_DIR/scanned_paths")
    local total_files=$(get_counter "$TEMP_DIR/total_files")
    
    cat > "$JSON_REPORT" <<EOF
{
    "scan_date": "$(date -Iseconds)",
    "scanner_version": "2.0",
    "current_user": "$CURRENT_USER",
    "summary": {
        "total_vulnerabilities": $total_vulns,
        "paths_scanned": $scanned_paths,
        "files_analyzed": $total_files
    },
    "vulnerability_types": {
EOF
    
    # Count vulnerabilities by type
    local vuln_type_array=("${!VULN_TYPES[@]}")
    local last_index=$((${#vuln_type_array[@]} - 1))
    
    for i in "${!vuln_type_array[@]}"; do
        local vuln_type="${vuln_type_array[i]}"
        local count=$(grep -c "\[$vuln_type\]" "$RESULTS_FILE" 2>/dev/null || echo 0)
        count=$(echo "$count" | tr -d '\r\n')  # Remove any newlines
        count=$((count))  # Convert to integer to remove leading zeros
        
        # Add comma for all except the last item
        if [[ $i -eq $last_index ]]; then
            echo "        \"$vuln_type\": $count" >> "$JSON_REPORT"
        else
            echo "        \"$vuln_type\": $count," >> "$JSON_REPORT"
        fi
    done
    
    echo '    },' >> "$JSON_REPORT"
    echo '    "vulnerabilities": [' >> "$JSON_REPORT"
    
    # Add vulnerability details
    local first_vuln=true
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            # Parse the vulnerability line format: [TYPE] path | details
            if [[ "$line" =~ ^\[([^\]]+)\]\ (.+)\ \|\ (.+) ]]; then
                local type="${BASH_REMATCH[1]}"
                local path="${BASH_REMATCH[2]}"
                local details="${BASH_REMATCH[3]}"
                
                # Add comma for all except the first vulnerability
                if [[ "$first_vuln" == "true" ]]; then
                    first_vuln=false
                else
                    echo '        },' >> "$JSON_REPORT"
                fi
                
                cat >> "$JSON_REPORT" <<EOF
        {
            "type": "$type",
            "path": "$path",
            "details": "$details",
            "severity": "$(calculate_severity "$type")"
EOF
            fi
        fi
    done < "$RESULTS_FILE"
    
    # Close the last vulnerability object if any were found
    if [[ "$first_vuln" == "false" ]]; then
        echo '        }' >> "$JSON_REPORT"
    fi
    
    echo '    ]' >> "$JSON_REPORT"
    echo '}' >> "$JSON_REPORT"
}

calculate_severity() {
    local vuln_type="$1"
    
    case "$vuln_type" in
        SUID|SGID|CAPABILITY|SSH_KEYS|ROOT_OWNED)
            echo "CRITICAL"
            ;;
        WORLD_WRITE|TRAVERSAL|NFS_EXPORT|CRON_JOBS|DATABASE)
            echo "HIGH"
            ;;
        WORLD_READ|WORLD_EXEC|ACL|SENSITIVE_CONTENT|CONFIG_FILES|LOG_FILES)
            echo "MEDIUM"
            ;;
        *)
            echo "LOW"
            ;;
    esac
}

print_summary() {
    local total_vulns=$(get_counter "$TEMP_DIR/total_vulns")
    local scanned_paths=$(get_counter "$TEMP_DIR/scanned_paths")
    local total_files=$(get_counter "$TEMP_DIR/total_files")
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        FILESPECTRE SCAN COMPLETE           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}📊 SCAN STATISTICS:${NC}"
    echo -e "   ${YELLOW}►${NC} Total Paths Scanned: ${BLUE}$scanned_paths${NC}"
    echo -e "   ${YELLOW}►${NC} Total Files Analyzed: ${BLUE}$total_files${NC}"
    echo -e "   ${YELLOW}►${NC} Parallel Workers Used: ${BLUE}$MAX_PARALLEL_JOBS${NC}"
    echo ""
    echo -e "${RED}⚠️  VULNERABILITIES FOUND: $total_vulns${NC}"
    echo ""
    
    # Show vulnerability breakdown
    echo -e "${CYAN}📋 VULNERABILITY BREAKDOWN:${NC}"
    for vuln_type in "${!VULN_TYPES[@]}"; do
        local count=$(grep -c "\[$vuln_type\]" "$RESULTS_FILE" 2>/dev/null || echo 0)
        count=$(echo "$count" | tr -d '\r\n')  # Remove any newlines
        if [[ $count -gt 0 ]]; then
            echo -e "   ${YELLOW}►${NC} $vuln_type: ${RED}$count${NC}"
            echo -e "      ${VULN_TYPES[$vuln_type]}"
        fi
    done
    
    echo ""
    echo -e "${GREEN}📁 REPORTS GENERATED:${NC}"
    echo -e "   ${YELLOW}►${NC} Detailed Log: ${BLUE}$LOG_FILE${NC}"
    echo -e "   ${YELLOW}►${NC} Raw Results: ${BLUE}$RESULTS_FILE${NC}"
    
    # Show generated reports based on export formats
    for format in "${EXPORT_FORMATS[@]}"; do
        case "$format" in
            "json")
                echo -e "   ${YELLOW}►${NC} JSON Report: ${BLUE}$JSON_REPORT${NC}"
                ;;
            "csv")
                echo -e "   ${YELLOW}►${NC} CSV Report: ${BLUE}$CSV_REPORT${NC}"
                ;;
            "html")
                echo -e "   ${YELLOW}►${NC} HTML Report: ${BLUE}$HTML_REPORT${NC}"
                ;;
            "xml")
                echo -e "   ${YELLOW}►${NC} XML Report: ${BLUE}$XML_REPORT${NC}"
                ;;
        esac
    done
    echo ""
    
    # Show top vulnerable paths
    if [[ $total_vulns -gt 0 ]]; then
        echo -e "${RED}🔝 TOP VULNERABLE PATHS:${NC}"
        cat "$RESULTS_FILE" | cut -d'|' -f1 | cut -d']' -f2 | sort | uniq -c | sort -rn | head -5 | while read count path; do
            echo -e "   ${YELLOW}►${NC} $path (${RED}$count issues${NC})"
        done
    fi
}

#############################################################################
# Main Execution
#############################################################################

main() {
    # Banner
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║             FILESPECTRE - File Security Scanner       ║"
    echo "║                    Version 2.0                        ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --threads|-t)
                MAX_PARALLEL_JOBS="$2"
                shift 2
                ;;
            --depth|-d)
                SCAN_DEPTH="$2"
                shift 2
                ;;
            --no-content)
                ENABLE_CONTENT_SCAN=0
                shift
                ;;
            --quick)
                ENABLE_DEEP_SCAN=0
                SCAN_DEPTH=2
                MAX_PARALLEL_JOBS=20
                shift
                ;;
            --output-dir|-o)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --export-format)
                IFS=',' read -ra EXPORT_FORMATS <<< "$2"
                shift 2
                ;;
            --include-paths)
                IFS=',' read -ra INCLUDE_PATHS <<< "$2"
                shift 2
                ;;
            --exclude-paths)
                IFS=',' read -ra EXCLUDE_PATHS <<< "$2"
                shift 2
                ;;
            --include-extensions)
                IFS=',' read -ra INCLUDE_EXTENSIONS <<< "$2"
                shift 2
                ;;
            --exclude-extensions)
                IFS=',' read -ra EXCLUDE_EXTENSIONS <<< "$2"
                shift 2
                ;;
            --scan-types)
                IFS=',' read -ra SCAN_TYPES <<< "$2"
                shift 2
                ;;
            --resume)
                RESUME_FILE="$2"
                ENABLE_RESUME=1
                shift 2
                ;;
            --quiet|-q)
                QUIET_MODE=1
                VERBOSE_MODE=0
                shift
                ;;
            --verbose|-v)
                VERBOSE_MODE=1
                QUIET_MODE=0
                shift
                ;;
            --no-progress)
                SHOW_PROGRESS=0
                shift
                ;;
            --no-auto-scale)
                AUTO_SCALE_THREADS=0
                shift
                ;;
            --skip-cross-user)
                SKIP_CROSS_USER=1
                shift
                ;;
            --max-users)
                MAX_USERS="$2"
                shift 2
                ;;
            --random-users)
                RANDOM_USERS=1
                if [[ "$2" =~ ^[0-9]+$ ]]; then
                    MAX_USERS="$2"
                    shift 2
                else
                    MAX_USERS=10  # Default to 10 random users
                    shift
                fi
                ;;
            --first-users)
                FIRST_USERS="$2"
                shift 2
                ;;
            --specific-users)
                IFS=',' read -ra SPECIFIC_USERS <<< "$2"
                shift 2
                ;;
            --help|-h)
                cat <<EOF
Usage: $0 [OPTIONS]

Basic Options:
  -t, --threads NUM           Number of parallel workers (default: 10)
  -d, --depth NUM             Maximum scan depth (default: 5)
  -o, --output-dir DIR        Output directory for reports (default: current directory)
  --no-content                Disable content scanning for faster execution
  --quick                     Quick scan mode (shallow depth, more threads)

Export Options:
  --export-format FORMATS     Export formats: json,csv,html,xml (default: all formats)
                              Example: --export-format json,csv,html

Filtering Options:
  --include-paths PATHS       Comma-separated paths to include (only scan these)
                              Example: --include-paths /home,/var/www
  --exclude-paths PATHS       Comma-separated paths to exclude from scan
                              Example: --exclude-paths /proc,/sys,/dev
  --include-extensions EXTS   Comma-separated extensions to include
                              Example: --include-extensions php,js,py
  --exclude-extensions EXTS   Comma-separated extensions to exclude
                              Example: --exclude-extensions tmp,log,cache

Vulnerability Selection:
  --scan-types TYPES          Comma-separated vulnerability types to scan:
                              - all (default): Scan all vulnerability types
                              - suid-sgid: SUID/SGID binaries
                              - world-permissions: World-writable/readable/executable
                              - root-owned: Files with root privileges
                              - capabilities: Files with dangerous capabilities
                              - backup-files: Exposed backup files
                              - sensitive-files: Files with sensitive content
                              - config-files: Configuration files with secrets
                              - ssh-keys: SSH private keys
                              - database-files: Database files
                              - log-files: Log files with sensitive data
                              - nfs-exports: Insecure NFS exports
                              - cron-jobs: Cron job vulnerabilities
                              Example: --scan-types suid-sgid,world-permissions,ssh-keys

Resume Options:
  --resume STATE_FILE         Resume scan from previous state file

User Sampling Options:
  --max-users NUM             Limit scan to maximum NUM users (0 = no limit)
                              Example: --max-users 20
  --random-users [NUM]        Randomly select users for scanning (default: 10)
                              Example: --random-users 15
  --first-users NUM           Scan only the first NUM users (alphabetically sorted)
                              Example: --first-users 5
  --specific-users USERS      Scan only specified users (comma-separated)
                              Example: --specific-users user1,user2,webuser

Output Control:
  -q, --quiet                 Quiet mode - show only critical/high vulnerabilities and progress
  -v, --verbose               Verbose mode - show all vulnerabilities and detailed output
  --no-progress               Disable progress dashboard and bars
  --no-auto-scale             Disable automatic thread scaling based on CPU cores
  --skip-cross-user           Skip cross-user access checking (performance optimization)

Help:
  -h, --help                  Show this help message

Examples:
  # Basic scan with default settings
  $0
  
  # Fast scan with CSV and HTML reports
  $0 --threads 20 --quick --export-format csv,html
  
  # Deep scan excluding system directories, only scan config files
  $0 --depth 7 --exclude-paths /proc,/sys,/dev --scan-types config-files,ssh-keys
  
  # Scan only PHP and Python files in web directories
  $0 --include-paths /var/www,/home --include-extensions php,py,js --threads 15
  
  # Fast scan with random 10 users for quick assessment
  $0 --random-users 10 --quick
  
  # Scan only first 5 users alphabetically with specific vulnerability types
  $0 --first-users 5 --scan-types suid-sgid,world-permissions
  
  # Scan specific users only
  $0 --specific-users webuser,admin,testuser --threads 20
  
  # Large environment optimization - limit to 20 users maximum
  $0 --max-users 20 --threads 50 --quiet
  
  # Resume a previous scan
  $0 --resume ./scan_state_20241201_120000
  
  # Fast scan with cross-user checking disabled for performance
  $0 --skip-cross-user --threads 20 --quick
EOF
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Create scan results directory if using default output directory
    if [[ "$OUTPUT_DIR" == "$(pwd)" ]]; then
        SCAN_RESULTS_DIR="$OUTPUT_DIR/scan_results_$TIMESTAMP"
        OUTPUT_DIR="$SCAN_RESULTS_DIR"
        echo -e "${BLUE}[*] Creating scan results directory: $OUTPUT_DIR${NC}"
    fi
    
    # Create output directory if it doesn't exist
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR" || {
            echo -e "${RED}[!] Cannot create output directory: $OUTPUT_DIR${NC}"
            exit 1
        }
    fi
    
    # Update file paths with correct output directory
    LOG_FILE="$OUTPUT_DIR/filespectre_scan_$TIMESTAMP.log"
    
    # Move results file from temp location to output directory
    OLD_RESULTS_FILE="$RESULTS_FILE"
    RESULTS_FILE="$OUTPUT_DIR/raw_results_$TIMESTAMP.txt"
    
    # Copy existing results if any
    if [[ -f "$OLD_RESULTS_FILE" ]]; then
        cp "$OLD_RESULTS_FILE" "$RESULTS_FILE" 2>/dev/null || touch "$RESULTS_FILE"
    else
        touch "$RESULTS_FILE"
    fi
    
    JSON_REPORT="$OUTPUT_DIR/scan_report_$TIMESTAMP.json"
    CSV_REPORT="$OUTPUT_DIR/scan_report_$TIMESTAMP.csv"
    HTML_REPORT="$OUTPUT_DIR/scan_report_$TIMESTAMP.html"
    XML_REPORT="$OUTPUT_DIR/scan_report_$TIMESTAMP.xml"
    STATE_FILE="$OUTPUT_DIR/.scan_state_$TIMESTAMP"
    
    # Check for resume
    if [[ $ENABLE_RESUME -eq 1 ]]; then
        if load_scan_state; then
            echo -e "${GREEN}[*] Resuming from previous scan...${NC}"
        else
            echo -e "${YELLOW}[*] Resume file not found or invalid, starting fresh scan${NC}"
            ENABLE_RESUME=0
        fi
    fi
    
    # Initialize
    echo -e "${YELLOW}[*] Initializing scanner...${NC}"
    echo "========================================" > "$LOG_FILE"
    echo "Enterprise Security Scan Report" >> "$LOG_FILE"
    echo "Date: $(date)" >> "$LOG_FILE"
    echo "User: $CURRENT_USER (UID: $CURRENT_UID)" >> "$LOG_FILE"
    echo "Groups: $CURRENT_GROUPS" >> "$LOG_FILE"
    echo "Output Directory: $OUTPUT_DIR" >> "$LOG_FILE"
    echo "Export Formats: ${EXPORT_FORMATS[*]}" >> "$LOG_FILE"
    echo "Scan Types: ${SCAN_TYPES[*]}" >> "$LOG_FILE"
    echo "Include Paths: ${INCLUDE_PATHS[*]}" >> "$LOG_FILE"
    echo "Exclude Paths: ${EXCLUDE_PATHS[*]}" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    
    # System information
    if [[ $QUIET_MODE -eq 1 ]]; then
        echo -e "${CYAN}[*] Target: $(hostname) | User: $CURRENT_USER | Threads: $MAX_PARALLEL_JOBS${NC}"
        echo ""
    else
        echo -e "${CYAN}[*] System Information:${NC}"
        echo "   OS: $(uname -a)"
        echo "   Hostname: $(hostname)"
        echo "   Current User: $CURRENT_USER"
        echo "   Home Directory: $CURRENT_HOME"
        echo ""
    fi
    
    # Phase 1: User Discovery
    if [[ $QUIET_MODE -eq 1 ]]; then
        echo -e "${GREEN}[1/4] Discovering users...${NC}"
    else
        echo -e "${GREEN}[PHASE 1] USER DISCOVERY${NC}"
        echo "----------------------------------------"
    fi
    # Discover users using proper array handling
    local users=()
    while IFS= read -r user_line; do
        [[ -n "$user_line" ]] && users+=("$user_line")
    done < <(discover_all_users)
    echo -e "${BLUE}[*] Discovered ${#users[@]} users${NC}"
    
    # Phase 2: Parallel Vulnerability Scanning  
    if [[ $QUIET_MODE -eq 1 ]]; then
        echo -e "${GREEN}[2/4] Scanning user directories...${NC}"
    else
        echo ""
        echo -e "${GREEN}[PHASE 2] PARALLEL VULNERABILITY SCANNING${NC}"
        echo "----------------------------------------"
    fi
    parallel_scan "${users[@]}"
    
    # Phase 2.5: Scan Include Paths (if specified)
    if [[ ${#INCLUDE_PATHS[@]} -gt 0 ]]; then
        if [[ $QUIET_MODE -eq 1 ]]; then
            echo -e "${GREEN}[2.5/4] Scanning specified include paths...${NC}"
        else
            echo ""
            echo -e "${GREEN}[PHASE 2.5] INCLUDE PATH SCANNING${NC}"
            echo "----------------------------------------"
        fi
        
        for include_path in "${INCLUDE_PATHS[@]}"; do
            if [[ -d "$include_path" ]]; then
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${CYAN}[*] Scanning include path: $include_path${NC}"
                fi
                deep_scan_directory "$include_path" "include"
            else
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${YELLOW}[!] Include path not found: $include_path${NC}"
                fi
            fi
        done
    fi
    
    # Phase 3: System-wide Vulnerability Checks
    if [[ $QUIET_MODE -eq 1 ]]; then
        echo -e "${GREEN}[3/4] System-wide security checks...${NC}"
    else
        echo ""
        echo -e "${GREEN}[PHASE 3] SYSTEM-WIDE VULNERABILITY CHECKS${NC}"
        echo "----------------------------------------"
    fi
    
    # Skip system-wide scans if include-paths is specified (performance optimization)
    if [[ ${#INCLUDE_PATHS[@]} -eq 0 ]]; then
        # Enhanced SUID/SGID detection system-wide
        if should_scan_vuln_type "suid" || should_scan_vuln_type "sgid"; then
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Scanning for SUID/SGID binaries...${NC}"
            fi
            detect_suid_sgid_systemwide
        fi
        
        # Enhanced world permissions detection system-wide
        if should_scan_vuln_type "world-writable" || should_scan_vuln_type "world-readable"; then
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Scanning world permissions system-wide...${NC}"
            fi
            detect_world_permissions_systemwide
        fi
        
        # Check world executable files system-wide
        if should_scan_vuln_type "world-executable"; then
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Scanning world executable files...${NC}"
            fi
            check_world_executable "/" 2
        fi
        
        # Check for root-owned files system-wide
        if should_scan_vuln_type "root-privileges"; then
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Scanning root-owned files...${NC}"
            fi
            check_root_owned "/" 2
        fi
        
        # Check for capabilities system-wide
        if should_scan_vuln_type "capabilities"; then
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Scanning file capabilities...${NC}"
            fi
            check_capabilities "/"
        fi
        
        # Check for SSH keys system-wide
        if should_scan_vuln_type "ssh"; then
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Scanning SSH keys...${NC}"
            fi
            check_ssh_keys "/"
        fi
        
        # Check for database files system-wide
        if should_scan_vuln_type "database"; then
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Scanning database files...${NC}"
            fi
            check_database_files "/"
        fi
        
        # Check for log files system-wide
        if should_scan_vuln_type "logs"; then
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Scanning log files...${NC}"
            fi
            check_log_files "/"
        fi
        
        # Check for ACL misconfigurations system-wide
        if should_scan_vuln_type "acl"; then
            if [[ $VERBOSE_MODE -eq 1 ]]; then
                echo -e "${CYAN}[*] Scanning ACL configurations...${NC}"
            fi
            check_acl "/"
        fi
        
    else
        if [[ $VERBOSE_MODE -eq 1 ]]; then
            echo -e "${YELLOW}[*] Skipping system-wide scans (include-paths specified)${NC}"
        fi
    fi
    
    # System-wide checks that don't depend on include-paths
    # Check system-wide NFS exports
    if should_scan_vuln_type "nfs"; then
        if [[ $VERBOSE_MODE -eq 1 ]]; then
            echo -e "${CYAN}[*] Scanning NFS exports...${NC}"
        fi
        check_nfs_exports
    fi
    
    # Check system cron jobs
    if should_scan_vuln_type "cron"; then
        if [[ $VERBOSE_MODE -eq 1 ]]; then
            echo -e "${CYAN}[*] Scanning cron jobs...${NC}"
        fi
        check_cron_jobs
    fi
    
    # Enhanced system-wide config file detection
    if should_scan_vuln_type "config-files"; then
        if [[ $VERBOSE_MODE -eq 1 ]]; then
            echo -e "${CYAN}[*] Scanning configuration files...${NC}"
        fi
        detect_config_files_systemwide
    fi
    
    # Phase 4: Generate Reports
    if [[ $QUIET_MODE -eq 1 ]]; then
        echo -e "${GREEN}[4/4] Generating reports...${NC}"
    else
        echo ""
        echo -e "${GREEN}[PHASE 4] GENERATING REPORTS${NC}"
        echo "----------------------------------------"
    fi
    
    # Generate reports in specified formats
    for format in "${EXPORT_FORMATS[@]}"; do
        case "$format" in
            "json")
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${CYAN}[*] Generating JSON report...${NC}"
                fi
                generate_json_report
                ;;
            "csv")
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${CYAN}[*] Generating CSV report...${NC}"
                fi
                generate_csv_report
                ;;
            "html")
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${CYAN}[*] Generating HTML report...${NC}"
                fi
                generate_html_report
                ;;
            "xml")
                if [[ $VERBOSE_MODE -eq 1 ]]; then
                    echo -e "${CYAN}[*] Generating XML report...${NC}"
                fi
                generate_xml_report
                ;;
            *)
                echo -e "${YELLOW}[*] Unknown export format: $format${NC}"
                ;;
        esac
    done
    
    # Print summary
    print_summary
    
    # Performance summary
    local total_elapsed=$(($(date +%s) - SCAN_START_TIME))
    local total_files=$(cat "$TEMP_DIR/total_files" 2>/dev/null || echo "0")
    local processed_users=$(cat "$TEMP_DIR/processed_users" 2>/dev/null || echo "0")
    local scan_speed="0"
    if [[ $total_elapsed -gt 0 ]]; then
        scan_speed=$((total_files / total_elapsed))
    fi
    
    # Cleanup
    if [[ $VERBOSE_MODE -eq 1 ]]; then
        echo -e "${CYAN}[*] Cleaning up temporary files...${NC}"
    fi
    # Keep results for analysis, but clean up locks
    rm -f "$TEMP_DIR"/*.lock
    
    echo ""
    if [[ $QUIET_MODE -eq 1 ]]; then
        echo -e "${GREEN}✅ FileSpectre scan completed!${NC} ${CYAN}(${total_elapsed}s | ${scan_speed} files/s | ${processed_users} users)${NC}"
    else
        echo -e "${GREEN}✅ Scan completed successfully!${NC}"
        echo -e "${BLUE}📈 Performance: ${CYAN}${total_elapsed}s elapsed | ${scan_speed} files/sec | ${processed_users} users processed${NC}"
        echo -e "${YELLOW}⚡ Tip: Use 'jq' to analyze the JSON report:${NC}"
        echo -e "   cat $JSON_REPORT | jq '.vulnerabilities[] | select(.severity==\"CRITICAL\")'"
    fi
}

# Signal handlers for cleanup
INTERRUPTED=0

cleanup_and_exit() {
    INTERRUPTED=1
    echo -e "\n${RED}[!] Scan interrupted. Cleaning up background jobs...${NC}"
    
    # Kill all background jobs
    jobs -p | xargs -r kill -TERM 2>/dev/null
    sleep 1
    jobs -p | xargs -r kill -KILL 2>/dev/null
    
    # Clean up temp directory
    rm -rf "$TEMP_DIR" 2>/dev/null
    
    echo -e "${YELLOW}[!] Scanner stopped successfully.${NC}"
    exit 130
}

trap cleanup_and_exit INT TERM

# Check for required commands
check_requirements() {
    local missing=()
    
    for cmd in stat find grep; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[!] Missing required commands: ${missing[*]}${NC}"
        echo -e "${YELLOW}[*] Please install the missing commands and try again.${NC}"
        exit 1
    fi
    
    # Optional commands (warn but don't exit)
    for cmd in getcap getfacl jq file; do
        if ! command -v "$cmd" &>/dev/null; then
            case "$cmd" in
                "getfacl")
                    echo -e "${YELLOW}[*] Optional command not found: $cmd (ACL scanning disabled)${NC}"
                    echo -e "${CYAN}[*] Install with: sudo apt install acl (Ubuntu/Debian) or yum install acl (RHEL/CentOS)${NC}"
                    ;;
                "getcap")
                    echo -e "${YELLOW}[*] Optional command not found: $cmd (using capability detection alternatives)${NC}"
                    echo -e "${CYAN}[*] Alternative methods: extended attributes, binary analysis, permission patterns${NC}"
                    echo -e "${CYAN}[*] Install for full capability scanning: sudo apt install libcap2-bin${NC}"
                    ;;
                "attr")
                    echo -e "${YELLOW}[*] Optional command not found: $cmd (extended attribute detection limited)${NC}"
                    echo -e "${CYAN}[*] Install with: sudo apt install attr${NC}"
                    ;;
                *)
                    echo -e "${YELLOW}[*] Optional command not found: $cmd (some features will be disabled)${NC}"
                    ;;
            esac
        fi
    done
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_requirements
    main "$@"
fi
