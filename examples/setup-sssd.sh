#!/bin/bash

# LDAP Authentication Setup Script for Ubuntu Servers
# This script automates the installation and configuration of SSSD for LDAP authentication

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
    
    # Check if user has sudo privileges
    if ! sudo -n true 2>/dev/null; then
        error "This script requires sudo privileges. Please run with a user that has sudo access."
        exit 1
    fi
}

# Default configuration (can be overridden by command line arguments)
LDAP_URI="ldap://localhost:3893"

LDAP_BASE_DN="dc=glauth,dc=com"

LDAP_BIND_DN="cn=service,dc=glauth,dc=com"
LDAP_BIND_PASSWORD="testing"

LDAP_USER_SEARCH_BASE="ou=users,dc=glauth,dc=com"
LDAP_GROUP_SEARCH_BASE="ou=groups,dc=glauth,dc=com"

DOMAIN_NAME="glauth"

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ldap-uri)
                LDAP_URI="$2"
                shift 2
                ;;
            --base-dn)
                LDAP_BASE_DN="$2"
                shift 2
                ;;
            --bind-dn)
                LDAP_BIND_DN="$2"
                shift 2
                ;;
            --bind-password)
                LDAP_BIND_PASSWORD="$2"
                shift 2
                ;;
            --user-search-base)
                LDAP_USER_SEARCH_BASE="$2"
                shift 2
                ;;
            --group-search-base)
                LDAP_GROUP_SEARCH_BASE="$2"
                shift 2
                ;;
            --domain)
                DOMAIN_NAME="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
LDAP Authentication Setup Script for Ubuntu

Usage: $0 [OPTIONS]

OPTIONS:
    --ldap-uri URI              LDAP server URI (default: ldap://localhost:3893)
    --base-dn DN               LDAP base DN (default: dc=glauth,dc=com)
    --bind-dn DN               LDAP bind DN (default: cn=service,dc=glauth,dc=com)
    --bind-password PASSWORD    LDAP bind password (default: testing)
    --user-search-base DN       User search base (default: ou=users,dc=glauth,dc=com)
    --group-search-base DN      Group search base (default: ou=groups,dc=glauth,dc=com)
    --domain NAME              SSSD domain name (default: glauth)
    --help, -h                 Show this help message

Examples:
    $0
    $0 --ldap-uri ldap://ldap.example.com:389 --base-dn dc=example,dc=com
    $0 --bind-dn cn=admin,dc=example,dc=com --bind-password mypassword

EOF
}

# Check Ubuntu version compatibility
check_ubuntu_version() {
    log "Checking Ubuntu version compatibility..."
    
    if ! command -v lsb_release &> /dev/null; then
        error "lsb_release command not found. Cannot determine Ubuntu version."
        exit 1
    fi
    
    UBUNTU_VERSION=$(lsb_release -rs)
    UBUNTU_MAJOR=$(echo $UBUNTU_VERSION | cut -d. -f1)
    
    if [[ $UBUNTU_MAJOR -lt 18 ]]; then
        error "This script requires Ubuntu 18.04 or newer. Current version: $UBUNTU_VERSION"
        exit 1
    fi
    
    success "Ubuntu version $UBUNTU_VERSION is supported"
}

# Update package lists
update_packages() {
    log "Updating package lists..."
    sudo apt update
    success "Package lists updated"
}

# Install required packages
install_packages() {
    log "Installing required packages..."
    
    local packages=(
        "sssd"
        "sssd-tools"
        "libnss-sss"
        "libpam-sss"
        "ldap-utils"
        "libpam-modules"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log "Installing $package..."
            sudo apt install -y "$package"
        else
            log "$package is already installed"
        fi
    done
    
    success "All required packages installed"
}

# Backup existing configuration
backup_configs() {
    log "Backing up existing configurations..."
    
    local backup_dir="/etc/sssd/backup-$(date +%Y%m%d-%H%M%S)"
    sudo mkdir -p "$backup_dir"
    
    # Backup SSSD config if it exists
    if [[ -f /etc/sssd/sssd.conf ]]; then
        sudo cp /etc/sssd/sssd.conf "$backup_dir/"
        log "Backed up existing SSSD configuration"
    fi
    
    # Backup PAM configs
    sudo cp /etc/pam.d/common-auth "$backup_dir/"
    sudo cp /etc/pam.d/common-session "$backup_dir/"
    sudo cp /etc/pam.d/common-account "$backup_dir/"
    sudo cp /etc/pam.d/common-password "$backup_dir/"
    
    success "Configuration files backed up to $backup_dir"
}

# Test LDAP connectivity
test_ldap_connection() {
    log "Testing LDAP connectivity..."
    
    if ! command -v ldapsearch &> /dev/null; then
        error "ldapsearch command not available"
        return 1
    fi
    
    if ldapsearch -x -H "$LDAP_URI" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASSWORD" -b "$LDAP_BASE_DN" -s base &>/dev/null; then
        success "LDAP connection test successful"
        return 0
    else
        warning "LDAP connection test failed. Continuing with configuration..."
        return 1
    fi
}

# Create SSSD configuration
create_sssd_config() {
    log "Creating SSSD configuration..."
    
    sudo tee /etc/sssd/sssd.conf > /dev/null << EOF
[sssd]
config_file_version = 2
services = nss, pam
domains = $DOMAIN_NAME
debug_level = 3

[domain/$DOMAIN_NAME]
# Provider settings
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap

# LDAP connection settings
ldap_uri = $LDAP_URI
ldap_search_base = $LDAP_BASE_DN
ldap_default_bind_dn = $LDAP_BIND_DN
ldap_default_authtok = $LDAP_BIND_PASSWORD

# Schema settings for GLAuth (RFC2307)
ldap_schema = rfc2307
ldap_user_object_class = posixAccount
ldap_user_name = uid
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
ldap_user_home_directory = homeDirectory
ldap_user_shell = loginShell
ldap_user_gecos = cn

ldap_group_object_class = posixGroup
ldap_group_name = cn
ldap_group_gid_number = gidNumber
ldap_group_member = memberUid

# Authentication settings
ldap_auth_disable_tls_never_use_in_production = true
ldap_tls_reqcert = never
ldap_id_use_start_tls = false

# Search bases
ldap_user_search_base = $LDAP_USER_SEARCH_BASE
ldap_group_search_base = $LDAP_GROUP_SEARCH_BASE

# Cache settings
cache_credentials = true
krb5_store_password_if_offline = true
entry_cache_timeout = 600
account_cache_expiration = 7
offline_credentials_expiration = 2

# Home directory settings
override_homedir = /home/%u
fallback_homedir = /home/%u
default_shell = /bin/bash

# Enumeration settings - disable for better performance
enumerate = false

# Access control - allow all authenticated users
access_provider = permit
auto_private_groups = true
autocreate_homedir = true

[nss]
filter_groups = root
filter_users = root
reconnection_retries = 3
enum_cache_timeout = 120

[pam]
reconnection_retries = 3
offline_credentials_expiration = 2
offline_failed_login_attempts = 3
offline_failed_login_delay = 5
pam_verbosity = 1
EOF

    # Set proper permissions
    sudo chmod 600 /etc/sssd/sssd.conf
    sudo chown root:root /etc/sssd/sssd.conf
    
    success "SSSD configuration created"
}

# Configure PAM for SSSD
configure_pam() {
    log "Configuring PAM for SSSD..."
    
    # Enable SSSD in PAM configuration
    sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --enable sss --force
    
    # Add mkhomedir module for automatic home directory creation
    if ! grep -q "pam_mkhomedir.so" /etc/pam.d/common-session; then
        sudo sed -i '/session.*pam_sss.so/a session optional pam_mkhomedir.so skel=/etc/skel umask=077' /etc/pam.d/common-session
        log "Added pam_mkhomedir.so for automatic home directory creation"
    fi
    
    success "PAM configuration completed"
}

# Start and enable SSSD service
configure_sssd_service() {
    log "Configuring SSSD service..."
    
    # Stop SSSD if running
    sudo systemctl stop sssd 2>/dev/null || true
    
    # Clear SSSD cache
    sudo rm -rf /var/lib/sss/db/* 2>/dev/null || true
    
    # Enable and start SSSD
    sudo systemctl enable sssd
    sudo systemctl start sssd
    
    # Wait for service to start
    sleep 3
    
    if sudo systemctl is-active --quiet sssd; then
        success "SSSD service started successfully"
    else
        error "SSSD service failed to start"
        sudo systemctl status sssd
        exit 1
    fi
}

# Test LDAP authentication
test_authentication() {
    log "Testing LDAP authentication..."
    
    # Wait for SSSD to initialize
    sleep 5
    
    local test_passed=false
    
    # Test if we can resolve users from LDAP
    log "Testing user resolution..."
    if getent passwd | grep -q ":.*:.*:.*:/home/"; then
        local ldap_users=$(getent passwd | grep ":.*:.*:.*:/home/" | head -3)
        if [[ -n "$ldap_users" ]]; then
            success "LDAP users found:"
            echo "$ldap_users" | while read line; do
                echo "  - $(echo $line | cut -d: -f1)"
            done
            test_passed=true
        fi
    fi
    
    if $test_passed; then
        success "LDAP authentication setup appears to be working"
        echo
        echo "To test user login, try:"
        echo "  su - <username>"
        echo "Or for SSH access, ensure 'PasswordAuthentication yes' in /etc/ssh/sshd_config"
    else
        warning "No LDAP users found. Please verify:"
        echo "  1. LDAP server is accessible"
        echo "  2. Bind credentials are correct"
        echo "  3. User search base contains users"
        echo "  4. Check SSSD logs: sudo journalctl -u sssd -f"
    fi
}

# Configure NSS
configure_nss() {
    log "Configuring NSS..."
    
    # Update /etc/nsswitch.conf to use SSSD
    sudo sed -i 's/^passwd:.*/passwd:         files systemd sss/' /etc/nsswitch.conf
    sudo sed -i 's/^group:.*/group:          files systemd sss/' /etc/nsswitch.conf
    sudo sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf
    
    success "NSS configuration updated"
}

# Main execution function
main() {
    echo "============================================"
    echo "  LDAP Authentication Setup for Ubuntu"
    echo "============================================"
    echo
    
    parse_args "$@"
    
    log "Starting LDAP authentication setup with configuration:"
    echo "  LDAP URI: $LDAP_URI"
    echo "  Base DN: $LDAP_BASE_DN"
    echo "  Bind DN: $LDAP_BIND_DN"
    echo "  Domain: $DOMAIN_NAME"
    echo
    
    check_root
    check_ubuntu_version
    update_packages
    install_packages
    backup_configs
    test_ldap_connection
    create_sssd_config
    configure_nss
    configure_pam
    configure_sssd_service
    test_authentication
    
    echo
    echo "============================================"
    success "LDAP authentication setup completed!"
    echo "============================================"
    echo
    echo "Next steps:"
    echo "1. Test user login: su - <ldap_username>"
    echo "2. Check SSSD status: sudo systemctl status sssd"
    echo "3. View SSSD logs: sudo journalctl -u sssd -f"
    echo "4. Clear SSSD cache if needed: sudo sss_cache -E"
    echo
    echo "For troubleshooting, check:"
    echo "- SSSD logs: /var/log/sssd/"
    echo "- Configuration: /etc/sssd/sssd.conf"
    echo "- Service status: sudo systemctl status sssd"
}

# Run main function with all arguments
main "$@" 