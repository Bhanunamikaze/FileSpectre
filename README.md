# FileSpectre - Advanced File Security Scanner

> **Enterprise-grade file security scanner designed for shared hosting environments, multi-user systems, and security audits. Detects 26+ vulnerability types with revolutionary systematic structure detection for 300+ users and millions of files.**

## Key Features

### Production-Ready Enhancements
- **Universal Detection Framework** - Multi-fallback detection system with 4+ methods per vulnerability type
- **System-Wide Scanning** - Enhanced SUID/SGID and world permissions detection across entire filesystem
- **Advanced Exclusions** - Directory pruning (--exclude-paths) with automatic /proc, /sys, /dev exclusion
- **Robust Signal Handling** - Proper Ctrl+C support without screen flooding
- **Root User Optimization** - Smart detection adjustments when running as root
- **Professional Output** - Clean dashboard with progress bars and status indicators
- **Auto-Directory Creation** - Creates `scan_results_TIMESTAMP` directories by default
- **Enterprise Compatibility** - Works without additional package dependencies
- **Cross-User Detection** - Identifies lateral access in shared hosting environments

### Performance & Scalability
- **50+ Parallel Workers** - Auto-scaling based on CPU cores for optimal performance
- **Smart Caching** - User/group/permission lookups cached for 5x speed improvement
- **Optimized Find Commands** - Uses fastest Unix permission detection methods
- **File Pre-filtering** - Skips binary files and irrelevant extensions automatically
- **Memory Efficient** - Handles millions of files with minimal resource usage
- **Resume Capability** - Continue interrupted scans from saved state

### Comprehensive Vulnerability Detection

| Category | Vulnerability Types | Description |
|----------|-------------------|-------------|
| **Permissions** | SUID, SGID, World-Write, World-Read, World-Exec | Standard Unix permission vulnerabilities |
| **Privilege Escalation** | Root-Owned Files, Capabilities, Cron Jobs | Files that could lead to privilege escalation |
| **Access Control** | ACL Misconfigurations, Group Access Issues | Advanced permission systems |
| **Web Security** | Config Files, Cross-User Access, Backup Files | Web application specific vulnerabilities |
| **Systematic Detection** | Cross-User Structure Mirroring | Revolutionary file structure analysis |
| **Credentials** | SSH Keys, Database Files, Sensitive Content | Exposed authentication and secrets |
| **System** | Symlinks, Hard Links, NFS Exports, Service Files | System-level security issues |

### ** Shared Hosting Specialist**
- **Multi-Home Detection** - Scans `/home`, `/home1`, `/home2`, `/home3`, `/home4`, etc.
- **Web Directory Awareness** - Detects `public_html`, `www`, `htdocs`, `html`, `web`
- **Cross-User Analysis** - Identifies when your user can access other users' files
- **Systematic Structure Detection** - Mirrors your file structure to find vulnerabilities in other users
- **WordPress Security** - Specialized detection for `wp-config.php` and WordPress vulnerabilities
- **Environment File Scanning** - Detects exposed `.env` files with credentials

### ** Professional Reporting**
- **Multiple Formats** - JSON, CSV, HTML, XML exports
- **Interactive HTML Reports** - Styled reports with vulnerability breakdown
- **Real-time Dashboard** - Progress tracking with ETA and performance metrics
- **Severity Classification** - CRITICAL, HIGH, MEDIUM, LOW with color coding
- **Integration Ready** - Compatible with `jq`, security tools, and spreadsheets

## 🛠️ **Installation**

```bash
# Clone the repository
git clone https://github.com/bhanunamikaze/FileSpectre.git
cd FileSpectre

# Make executable
chmod +x scanner.sh

# Run basic scan
./scanner.sh
```

### **Dependencies**
- **Required**: `bash`, `find`, `stat`, `grep`, `date` (standard Unix tools)
- **Optional**: `getfacl` (ACL scanning), `getcap` (capabilities), `jq` (JSON analysis)
- **Fallback Methods**: Full functionality available without optional dependencies

##  **Usage**

### **Basic Usage**
```bash
# Quick scan with professional output (default)
./scanner.sh

# Verbose mode with detailed output
./scanner.sh --verbose

# Maximum performance scan
./scanner.sh --threads auto --quick

# Specific vulnerability types with exclusions
./scanner.sh --scan-types suid-sgid,config-files,ssh-keys --exclude-paths "/mnt,/media"

# System-wide security audit
./scanner.sh --scan-types suid-sgid,world-permissions --threads 100 --exclude-paths "/mnt"
```

### **Shared Hosting Security Audit**
```bash
# Comprehensive shared hosting scan
./scanner.sh \
  --scan-types config-files,ssh-keys,world-permissions,cross-user \
  --include-paths /home,/home1,/home2,/home3 \
  --export-format html,json \
  --verbose

# WordPress security audit
./scanner.sh \
  --scan-types config-files,backup-files,sensitive-files \
  --include-extensions php,env,conf,ini \
  --include-paths /var/www,/home \
  --export-format html
```

### **Enterprise Environment**
```bash
# Large environment scan (300+ users)
./scanner.sh \
  --threads 100 \
  --quiet \
  --export-format json,csv \
  --output-dir /var/security/reports

# Resume interrupted scan
./scanner.sh --resume ./scan_state_20241201_120000
```

##  **Command Line Options**

### **Core Options**
| Option | Description | Default |
|--------|-------------|---------|
| `-t, --threads NUM` | Parallel workers | 50 (auto-scaled) |
| `-d, --depth NUM` | Scan depth | 5 |
| `-o, --output-dir DIR` | Report directory | `./scan_results_TIMESTAMP` |
| `-q, --quiet` | Professional mode | Enabled |
| `-v, --verbose` | Detailed output | Disabled |

### **Scanning Control**
| Option | Description | Example |
|--------|-------------|---------|
| `--scan-types TYPES` | Vulnerability types | `suid-sgid,config-files` |
| `--include-paths PATHS` | Scan specific paths | `/home,/var/www` |
| `--exclude-paths PATHS` | Skip paths (auto-excludes /proc,/sys,/dev) | `/mnt,/media,/tmp` |
| `--exclude-extensions EXTS` | Skip file extensions | `log,tmp,cache,jpg,mp4` |
| `--include-extensions EXTS` | File types | `php,py,js,env` |

### **Performance Options**
| Option | Description | Use Case |
|--------|-------------|----------|
| `--quick` | Fast scan mode | Quick audits |
| `--no-content` | Skip content analysis | Performance |
| `--no-auto-scale` | Fixed thread count | Controlled resources |
| `--no-progress` | Minimal output | Automation |

### **Export Options**
| Option | Description | Formats |
|--------|-------------|---------|
| `--export-format FORMATS` | Report formats | `json,csv,html,xml` |
| `--resume STATE_FILE` | Continue scan | Previous state file |

##  **Vulnerability Types**

### **Available Scan Types**
```bash
# Permission-based vulnerabilities
--scan-types suid-sgid              # SUID/SGID binaries
--scan-types world-permissions      # World-writable/readable/executable
--scan-types root-owned             # Root-owned accessible files

# Security-specific  
--scan-types ssh-keys               # SSH private keys
--scan-types config-files           # Configuration files with secrets (includes systematic detection)
--scan-types sensitive-files        # Files with sensitive content
--scan-types backup-files           # Exposed backup files
--scan-types database-files         # Database files

# System vulnerabilities
--scan-types capabilities           # File capabilities
--scan-types acl                    # ACL misconfigurations
--scan-types cron-jobs              # Cron job vulnerabilities
--scan-types nfs-exports            # NFS export issues

# Combined scans
--scan-types all                    # All vulnerability types (default)
```

**NEW: Systematic Structure Detection** (included in `config-files` scan type)
- Automatically mirrors your file structure to test cross-user access
- Finds vulnerabilities with ANY file naming convention
- No additional parameters needed - works automatically during `config-files` scan

##  **Sample Output**

### **Professional Dashboard (Default)**
```
╔══════════════════════════════════════════════════════════════╗
║                    FILESPECTRE                            ║
╠══════════════════════════════════════════════════════════════╣
║ Current User: webuser01           │ Total Users:     156 ║
║ Processed:    89                  │ Remaining:        67 ║
║ Vulnerabilities Found: 23         │ ETA:       2m 15s ║
║ Scan Speed: 1247 files/sec        │ Elapsed:       45s ║
╚══════════════════════════════════════════════════════════════╝

[ 57%] █████████████████░░░░░░░░░░░░░░ Processing remaining users... (89/156)
```

### **Vulnerability Detection**
```bash
# System-wide SUID/SGID detection
[+] Fallback method successful: locate -r 'bin$' method
[HIGH] SUID Binary: /usr/bin/sudo
[HIGH] SUID Binary: /usr/bin/passwd
[HIGH] SGID Binary: /usr/bin/chage

# World permissions detection  
[HIGH] WORLD_WRITE: init
[INFO] WORLD_READ: 127 world-readable sensitive files found

# Cross-user access detection
[!] CRITICAL CROSS-USER ACCESS: /home1/user123/public_html/wp-config.php (Owner: user123)
[!] WORDPRESS DB CREDENTIALS EXPOSED: /home1/user123/public_html/wp-config.php

# Systematic structure detection
[!] CRITICAL STRUCTURE ACCESS: /home2/user456/app/database.conf
[!] HIGH STRUCTURE ACCESS: /home3/user789/api/config.py
[+] Structure access: /home4/user999/public_html/index.php

# Cron job vulnerabilities
[!] WRITABLE CRON JOB: /etc/cron.daily/logrotate
[!] WRITABLE CRON JOB: /etc/cron.d/sysstat
```

### **Report Generation**
```
 REPORTS GENERATED:
   ► Detailed Log: ./scan_results_20241201_143022/filespectre_scan_20241201_143022.log
   ► Raw Results: ./scan_results_20241201_143022/raw_results_20241201_143022.txt
   ► JSON Report: ./scan_results_20241201_143022/scan_report_20241201_143022.json  
   ► CSV Report: ./scan_results_20241201_143022/scan_report_20241201_143022.csv
   ► HTML Report: ./scan_results_20241201_143022/scan_report_20241201_143022.html
   ► XML Report: ./scan_results_20241201_143022/scan_report_20241201_143022.xml
```

## 🔧 **Advanced Features**

### **Cross-User Detection**
Specifically designed for shared hosting environments:
```bash
# Your user: user1 in /home1/user1/wordpress/wp-config.php
# Scanner finds: /home2/user2/wordpress/wp-config.php (accessible to you!)

./scanner.sh --scan-types config-files --include-paths /home,/home1,/home2,/home3
```

### ** Systematic Structure Detection**
**Revolutionary feature that mirrors your entire file structure to detect cross-user access:**

```bash
# How it works:
# 1. Scans YOUR file structure: /home/you/app/config.php, /home/you/blog/wp-config.php
# 2. Tests SAME paths on other users: /home1/user1/app/config.php, /home2/user2/blog/wp-config.php
# 3. Finds accessible files with ANY naming convention (not just predefined patterns)

# Performance optimized:
# - Tests up to 1000 files from your structure
# - Checks against 50+ users across different home bases
# - Excludes media files automatically (jpg, mp4, etc.)
# - Smart severity assessment (CRITICAL for configs, HIGH for scripts)
```

**Example Discovery:**
```bash
[*] Current user home detected: /home/myuser
[*] Found 247 files in current user structure to test
[!] CRITICAL STRUCTURE ACCESS: /home1/user123/wordpress/wp-config.php
[!] HIGH STRUCTURE ACCESS: /home2/user456/api/database.py
[+] Structure access: /home3/user789/public_html/contact.php
[+] Systematic cross-user check complete: 15 users checked, 23 accessible files found
```

### **Universal Detection Framework**
Advanced multi-fallback system for robust vulnerability detection:
- **SUID/SGID Detection**: 4 fallback methods (combined find, alternative syntax, directory-based, locate)
- **World Permissions**: Multiple detection methods with automatic directory pruning
- **ACL Detection**: Extended attributes, permission patterns, location analysis
- **Capability Detection**: Binary analysis, behavioral testing, extended attributes  
- **System-Wide Exclusions**: Automatic pruning of /proc, /sys, /dev with user-specified exclusions
- **Timeout Protection**: 300s primary method, 120s fallback method timeouts

### **Resume Functionality**
```bash
# Automatic state saving
./scanner.sh --threads 50 --depth 6  # Creates state file automatically

# Resume interrupted scan
./scanner.sh --resume ./scan_state_20241201_120000
```

### **Result Analysis**
```bash
# Find critical vulnerabilities
jq '.vulnerabilities[] | select(.severity=="CRITICAL")' scan_report.json

# WordPress-specific issues  
jq '.vulnerabilities[] | select(.path | contains("wp-config"))' scan_report.json

# Cross-user access issues
jq '.vulnerabilities[] | select(.details | contains("cross-user"))' scan_report.json

# Systematic structure detection results
jq '.vulnerabilities[] | select(.type=="CROSS_USER_STRUCTURE")' scan_report.json

# Group by severity
jq 'group_by(.severity) | .[] | {severity: .[0].severity, count: length}' scan_report.json
```

##  **Use Cases**

### **Security Auditing**
- **Shared Hosting Providers** - Multi-tenant security validation
- **Enterprise Environments** - Large-scale permission audits  
- **Compliance Checking** - GDPR, SOX, HIPAA file security requirements
- **Penetration Testing** - Privilege escalation path discovery

### **DevOps & System Administration**
- **Server Hardening** - Pre-production security validation
- **Configuration Management** - Detect configuration drift
- **Incident Response** - Post-breach security assessment
- **Continuous Security** - Automated security scanning in CI/CD

### **Web Application Security**
- **WordPress Security** - wp-config.php and plugin vulnerabilities
- **PHP Application Audits** - Configuration and credential exposure
- **Multi-site Environments** - Cross-tenant access validation
- **Backup Security** - Exposed backup file detection

##  **Performance Benchmarks**

| Environment | Users | Files | Scan Time | Throughput |
|-------------|-------|-------|-----------|------------|
| Small Shared Host | 50 | 50K | 30s | 1,667 files/sec |
| Medium Enterprise | 300 | 500K | 4m 15s | 1,961 files/sec |
| Large Hosting | 1000+ | 2M+ | 12m 30s | 2,667 files/sec |

*Benchmarks on 8-core server with SSD storage*


### **Multi-Fallback Reliability**
- **Primary Detection Methods**: Fast system-wide find commands
- **Fallback Method 1**: Alternative permission syntax (`-u=s`, `-g=s`)  
- **Fallback Method 2**: Directory-based search in common binary locations
- **Fallback Method 3**: Locate-based binary discovery (proven successful)
- **Timeout Protection**: 300s primary, 120s fallback method limits

##  **Security Considerations**

### **Safe Operation**
- ✅ **Read-only scanning** - Never modifies files or permissions
- ✅ **Signal handling** - Clean interruption with Ctrl+C
- ✅ **Resource limits** - Respects file size and memory limits
- ✅ **Error handling** - Graceful handling of permission denied errors
- ✅ **Thread safety** - Atomic operations prevent race conditions

### **Privacy & Compliance**
- ✅ **No data exfiltration** - All analysis performed locally
- ✅ **Configurable logging** - Control what information is logged
- ✅ **Secure cleanup** - Temporary files cleaned automatically
- ✅ **Audit trail** - Complete scanning activity logs


##  **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
