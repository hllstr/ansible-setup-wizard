#!/bin/bash

# Script to generate a complete Ansible project structure for automating
# the installation of basic services on Linux and Windows hosts.

# --- Configuration ---
PROJECT_NAME="ansible-project"
JINJA2_TEMPLATES_SRC_DIR="jinja2-templates" # External source directory for Jinja2 templates

# --- Global Variables ---
USE_SECURE_PROTOCOLS="yes"
INSECURE_WARNING_MESSAGE_GENERAL="⚠️ WARNING: Using unencrypted connections is not recommended for production environments. This should only be used in lab/testing environments to simplify the setup."
INSECURE_WARNING_MESSAGE_WINRM_SPECIFIC="For insecure WinRM, you must enable AllowUnencrypted and Basic Authentication on the target Windows Server to allow Ansible to communicate.\nExample PowerShell commands on Windows Server:\n  winrm quickconfig -q\n  winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'\n  winrm set winrm/config/service/auth '@{Basic=\"true\"}'"

WINRM_GLOBAL_CFG_SETTINGS_INSECURE=""
WINRM_HOST_VARS_INSECURE="ansible_connection=winrm ansible_winrm_transport=basic ansible_winrm_server_cert_validation=ignore ansible_port=5985"
WINRM_HOST_VARS_SECURE="ansible_connection=winrm ansible_winrm_transport=negotiate ansible_port=5986 ansible_winrm_scheme=https ansible_winrm_server_cert_validation=ignore" # 'ignore' for lab/self-signed certs

# --- Helper Functions ---

# Function to create a directory if it doesn't exist
create_dir() {
    if [ ! -d "$1" ]; then
        mkdir -p "$1"
        echo "Created directory: $1"
    fi
}

# Function to create a file with content
create_file() {
    echo -e "$2" > "$1"
    echo "Created file: $1"
}

# Function to append content to a file
append_to_file() {
    echo -e "$2" >> "$1"
    # No echo here to avoid cluttering output for warnings
}

# Function to prompt user with Y/n choice
prompt_yes_no() {
    local prompt_message=$1
    local default_value=${2:-"y"} 
    local choice

    while true; do
        read -r -p "$prompt_message [Y/n]: " choice
        choice=${choice:-$default_value} 
        case "$choice" in
            [Yy]* ) return 0;; # Yes
            [Nn]* ) return 1;; # No
            * ) echo "Please answer yes (y) or no (n).";;
        esac
    done
}

# --- Main Script ---

echo "Ansible Project Setup Script"
echo "----------------------------"

# --- 1. Secure Protocol Option Prompt ---
if prompt_yes_no "Do you want to use secure connections (SSH for Linux, WinRM over HTTPS for Windows)? (Recommended)"; then
    USE_SECURE_PROTOCOLS="yes"
    echo "Using secure protocols."
else
    USE_SECURE_PROTOCOLS="no"
    echo ""
    echo -e "$INSECURE_WARNING_MESSAGE_GENERAL"
    echo -e "$INSECURE_WARNING_MESSAGE_WINRM_SPECIFIC"
    echo ""

    WINRM_GLOBAL_CFG_SETTINGS_INSECURE=$(cat <<-END
# Settings for insecure WinRM (HTTP). Per-host variables in inventory are more specific.
ansible_winrm_transport = basic
ansible_winrm_server_cert_validation = ignore
END
)
fi

# --- 2. Project Structure Creation ---
echo ""
echo "Creating project structure in ./${PROJECT_NAME}/"
create_dir "${PROJECT_NAME}"
create_dir "${PROJECT_NAME}/inventory"
create_dir "${PROJECT_NAME}/group_vars"
create_dir "${PROJECT_NAME}/host_vars"
create_dir "${PROJECT_NAME}/roles"
create_dir "${PROJECT_NAME}/playbooks"
create_dir "${PROJECT_NAME}/templates" # Central location for copied Jinja2 templates

# --- 3. Ansible Configuration File (ansible.cfg) ---
ANSIBLE_CFG_CONTENT=$(cat <<-END
[defaults]
inventory = ./inventory/hosts.ini
roles_path = ./roles
# Disable host key checking for lab/testing environments. For production, set to True.
host_key_checking = False
# Default remote user - uncomment and set if common across hosts
# remote_user = your_ssh_user

# Default privilege escalation for Linux hosts
[privilege_escalation]
become = True
become_method = sudo
become_user = root
# become_ask_pass = True # Uncomment if you want to be prompted for sudo password

[winrm]
# WinRM settings can be defined here or, more specifically, in inventory.
# The following are applied if USE_SECURE_PROTOCOLS was 'no' during script generation.
END
)

if [ "$USE_SECURE_PROTOCOLS" = "no" ]; then
    ANSIBLE_CFG_CONTENT+="\n${WINRM_GLOBAL_CFG_SETTINGS_INSECURE}\n"
else
    ANSIBLE_CFG_CONTENT+="\n# For secure WinRM (HTTPS), ensure target Windows hosts have an SSL certificate for the WinRM listener.\n"
    ANSIBLE_CFG_CONTENT+="ansible_winrm_transport = negotiate # or 'kerberos' or 'ssl' depending on auth\n"
    ANSIBLE_CFG_CONTENT+="ansible_winrm_server_cert_validation = ignore # For self-signed certs; use 'validate' for CA-signed in prod\n"
fi

create_file "${PROJECT_NAME}/ansible.cfg" "${ANSIBLE_CFG_CONTENT}"

# --- 4. Dynamic Inventory & Host Setup ---
echo ""
echo "Host Setup:"
echo "Enter a comma or space-separated list of hostnames (e.g., LIN1,LIN2,WIN1):"
read -r HOST_LIST_INPUT
IFS=', ' read -r -a HOSTS <<< "$HOST_LIST_INPUT"

declare -A HOST_OS                 # HOST_OS[hostname]="os_type"
declare -A HOST_SERVICES           # HOST_SERVICES[hostname]="service1,service2"
ALL_LINUX_SERVICES=("apache2" "bind9" "haproxy")
ALL_WINDOWS_SERVICES=("dns" "webserver") # 'webserver' for IIS
ALL_ROLES_TO_CREATE=()             # To keep track of unique roles needed
ALL_TEMPLATES_TO_COPY=()           # To keep track of unique templates needed

for HOST in "${HOSTS[@]}"; do
    # Sanitize host name to be used as array key
    CLEAN_HOST=$(echo "$HOST" | sed 's/[^a-zA-Z0-9_-]//g')
    if [ -z "$CLEAN_HOST" ]; then
        echo "Skipping invalid or empty hostname from input: '$HOST'"
        continue
    fi
    
    echo ""
    echo "Configuring host: ${HOST}"

    OS_TYPE=""
    while [[ -z "$OS_TYPE" ]]; do
        DEFAULT_OS=""
        if [[ "$HOST" == *"LIN"* || "$HOST" == *"lin"* || "$HOST" == *"Lnx"* ]]; then
            DEFAULT_OS="linux"
        elif [[ "$HOST" == *"WIN"* || "$HOST" == *"win"* || "$HOST" == *"Win"* ]]; then
            DEFAULT_OS="windows"
        fi

        read -r -p "Enter OS type for ${HOST} (linux/windows) [default: ${DEFAULT_OS:-linux}]: " INPUT_OS_TYPE
        INPUT_OS_TYPE=${INPUT_OS_TYPE:-${DEFAULT_OS:-linux}}
        INPUT_OS_TYPE=$(echo "$INPUT_OS_TYPE" | tr '[:upper:]' '[:lower:]')

        if [[ "$INPUT_OS_TYPE" == "linux" || "$INPUT_OS_TYPE" == "windows" ]]; then
            OS_TYPE="$INPUT_OS_TYPE"
            HOST_OS["$CLEAN_HOST"]="$OS_TYPE"
        else
            echo "Invalid OS type. Please enter 'linux' or 'windows'."
        fi
    done

    SELECTED_SERVICES_FOR_HOST=()
    if [ "$OS_TYPE" == "linux" ]; then
        echo "Available Linux services for ${HOST}: ${ALL_LINUX_SERVICES[*]}"
        read -r -p "Enter services (comma-separated, e.g., apache2,bind9), or leave empty: " INPUT_SERVICES
        IFS=',' read -r -a RAW_SERVICES <<< "$INPUT_SERVICES"
        for SERVICE in "${RAW_SERVICES[@]}"; do
            TRIMMED_SERVICE=$(echo "$SERVICE" | xargs) 
            if [[ -n "$TRIMMED_SERVICE" && " ${ALL_LINUX_SERVICES[*]} " =~ " ${TRIMMED_SERVICE} " ]]; then
                SELECTED_SERVICES_FOR_HOST+=("$TRIMMED_SERVICE")
                ALL_ROLES_TO_CREATE+=("linux_${TRIMMED_SERVICE}")
                ALL_TEMPLATES_TO_COPY+=("${TRIMMED_SERVICE}.j2")
            elif [ -n "$TRIMMED_SERVICE" ]; then
                echo "Warning: Service '${TRIMMED_SERVICE}' is not a known Linux service for ${HOST}. Skipping."
            fi
        done
    elif [ "$OS_TYPE" == "windows" ]; then
        echo "Available Windows services for ${HOST}: ${ALL_WINDOWS_SERVICES[*]}"
        read -r -p "Enter services (comma-separated, e.g., dns,webserver), or leave empty: " INPUT_SERVICES
        IFS=',' read -r -a RAW_SERVICES <<< "$INPUT_SERVICES"
        for SERVICE in "${RAW_SERVICES[@]}"; do
            TRIMMED_SERVICE=$(echo "$SERVICE" | xargs) 
            if [[ -n "$TRIMMED_SERVICE" && " ${ALL_WINDOWS_SERVICES[*]} " =~ " ${TRIMMED_SERVICE} " ]]; then
                SELECTED_SERVICES_FOR_HOST+=("$TRIMMED_SERVICE")
                ALL_ROLES_TO_CREATE+=("windows_${TRIMMED_SERVICE}")
                TEMPLATE_NAME=""
                if [ "$TRIMMED_SERVICE" == "webserver" ]; then TEMPLATE_NAME="iis.j2"; fi
                if [ "$TRIMMED_SERVICE" == "dns" ]; then TEMPLATE_NAME="dns_win.j2"; fi
                if [ -n "$TEMPLATE_NAME" ]; then ALL_TEMPLATES_TO_COPY+=("$TEMPLATE_NAME"); fi
            elif [ -n "$TRIMMED_SERVICE" ]; then
                echo "Warning: Service '${TRIMMED_SERVICE}' is not a known Windows service for ${HOST}. Skipping."
            fi
        done
    fi
    HOST_SERVICES["$CLEAN_HOST"]=$(IFS=,; echo "${SELECTED_SERVICES_FOR_HOST[*]}")
done

UNIQUE_ROLES=($(echo "${ALL_ROLES_TO_CREATE[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
UNIQUE_TEMPLATES=($(echo "${ALL_TEMPLATES_TO_COPY[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

# --- 5. Inventory File (inventory/hosts.ini) ---
INVENTORY_CONTENT="; Ansible inventory file\n\n"
LINUX_HOSTS_GROUP_CONTENT=""
WINDOWS_HOSTS_GROUP_CONTENT=""
HAS_LINUX_HOSTS=false
HAS_WINDOWS_HOSTS=false

for HOST_KEY in "${!HOST_OS[@]}"; do # HOST_KEY is the sanitized name
    ORIGINAL_HOST_NAME="" # Find original name if needed, or assume HOST_KEY is fine for inventory
                        # For simplicity, we'll use HOST_KEY, assuming user entered valid hostnames
                        # or IPs that don't need complex original mapping here.
                        # If hostnames were complex, we'd need to store original names alongside sanitized keys.
                        # For now, assume HOST_KEY is the intended inventory name.
    INVENTORY_HOST_NAME="${HOST_KEY}" # This relies on HOST_KEY being the desired inventory entry.
                                      # The script should prompt for FQDNs or IPs.
                                      # For this example, we use the name as entered.

    OS=${HOST_OS["$HOST_KEY"]}
    if [ "$OS" == "linux" ]; then
        LINUX_HOSTS_GROUP_CONTENT+="${INVENTORY_HOST_NAME}\n"
        HAS_LINUX_HOSTS=true
    elif [ "$OS" == "windows" ]; then
        WINDOWS_HOST_LINE="${INVENTORY_HOST_NAME}"
        if [ "$USE_SECURE_PROTOCOLS" = "no" ]; then
            WINDOWS_HOST_LINE+=" ${WINRM_HOST_VARS_INSECURE}"
        else
            WINDOWS_HOST_LINE+=" ${WINRM_HOST_VARS_SECURE}"
        fi
        WINDOWS_HOSTS_GROUP_CONTENT+="${WINDOWS_HOST_LINE}\n"
        HAS_WINDOWS_HOSTS=true
    fi
done

if $HAS_LINUX_HOSTS; then
    INVENTORY_CONTENT+="[linux_hosts]\n${LINUX_HOSTS_GROUP_CONTENT}\n"
fi
if $HAS_WINDOWS_HOSTS; then
    INVENTORY_CONTENT+="[windows_hosts]\n${WINDOWS_HOSTS_GROUP_CONTENT}\n"
fi

INVENTORY_CONTENT+="\n[all:vars]\n"
INVENTORY_CONTENT+="; Common variables for all hosts can be defined here\n"
INVENTORY_CONTENT+="; example_variable: some_value\n"
INVENTORY_CONTENT+="\n; To define OS-specific variables, create group_vars/linux_hosts.yml or group_vars/windows_hosts.yml\n"
INVENTORY_CONTENT+="; To define host-specific variables, create host_vars/YOUR_HOSTNAME.yml\n"

create_file "${PROJECT_NAME}/inventory/hosts.ini" "${INVENTORY_CONTENT}"

# --- 6. Role Scaffolding & Jinja2 Template Import ---
echo ""
echo "Creating Roles and Importing Templates..."

if [ ${#UNIQUE_TEMPLATES[@]} -gt 0 ]; then
    echo "Copying selected Jinja2 templates from '${JINJA2_TEMPLATES_SRC_DIR}/' to '${PROJECT_NAME}/templates/'..."
    if [ ! -d "${JINJA2_TEMPLATES_SRC_DIR}" ]; then
        echo "WARNING: Source Jinja2 template directory '${JINJA2_TEMPLATES_SRC_DIR}' not found."
        echo "Please create it and populate it with .j2 files (e.g., apache2.j2, iis.j2)."
    else
        for TEMPLATE_FILE in "${UNIQUE_TEMPLATES[@]}"; do
            if [ -f "${JINJA2_TEMPLATES_SRC_DIR}/${TEMPLATE_FILE}" ]; then
                cp "${JINJA2_TEMPLATES_SRC_DIR}/${TEMPLATE_FILE}" "${PROJECT_NAME}/templates/"
                echo "Copied ${TEMPLATE_FILE} to ${PROJECT_NAME}/templates/"
            else
                echo "WARNING: Template file '${TEMPLATE_FILE}' not found in '${JINJA2_TEMPLATES_SRC_DIR}/'. Skipping."
            fi
        done
    fi
fi


for ROLE_FULL_NAME in "${UNIQUE_ROLES[@]}"; do
    ROLE_DIR="${PROJECT_NAME}/roles/${ROLE_FULL_NAME}"
    create_dir "${ROLE_DIR}"
    create_dir "${ROLE_DIR}/tasks"
    create_dir "${ROLE_DIR}/handlers"
    create_dir "${ROLE_DIR}/templates" 
    create_dir "${ROLE_DIR}/vars"
    create_dir "${ROLE_DIR}/defaults"
    create_dir "${ROLE_DIR}/meta"

    TASK_CONTENT="# tasks file for ${ROLE_FULL_NAME}\n# TODO: Implement the tasks to install and configure the service.\n\n"
    ROLE_OS=$(echo "$ROLE_FULL_NAME" | cut -d'_' -f1)
    ROLE_SERVICE=$(echo "$ROLE_FULL_NAME" | cut -d'_' -f2-)
    TEMPLATE_TASK_COMMENT="# To use a template from the project's 'templates/' directory (e.g., ${ROLE_SERVICE}.j2):\n# Make sure it was copied from '${JINJA2_TEMPLATES_SRC_DIR}/${ROLE_SERVICE}.j2' to '${PROJECT_NAME}/templates/${ROLE_SERVICE}.j2'"
    HANDLER_CONTENT="# handlers file for ${ROLE_FULL_NAME}\n# TODO: Define handlers for services (e.g., restart service).\n"

    if [ "$ROLE_OS" == "linux" ]; then
        TASK_CONTENT+="# Ensure your tasks are idempotent (can be run multiple times without adverse effects).\n"
        TASK_CONTENT+="# Use 'become: yes' for tasks requiring root privileges.\n\n"
        case "$ROLE_SERVICE" in
            "apache2")
                TASK_CONTENT+="- name: Ensure Apache2 package is present (example for Debian/Ubuntu)\n  ansible.builtin.apt:\n    name: apache2\n    state: present\n    update_cache: yes\n  become: yes\n  notify: restart apache2\n\n- name: Ensure Apache2 service is started and enabled\n  ansible.builtin.service:\n    name: apache2\n    state: started\n    enabled: yes\n  become: yes\n\n"
                TASK_CONTENT+="${TEMPLATE_TASK_COMMENT}\n# - name: Deploy Apache2 configuration (example)\n#   ansible.builtin.template:\n#     src: ../../templates/apache2.j2\n#     dest: /etc/apache2/sites-available/000-default.conf # TODO: Adjust path\n#   become: yes\n#   notify: restart apache2\n"
                HANDLER_CONTENT+="- name: restart apache2\n  ansible.builtin.service:\n    name: apache2\n    state: restarted\n  become: yes\n"
                ;;
            "bind9")
                TASK_CONTENT+="- name: Ensure BIND9 package is present (example for Debian/Ubuntu: bind9, RHEL/CentOS: bind)\n  ansible.builtin.package: # Generic module, use apt/yum/dnf for specifics\n    name: bind9 # TODO: Adjust package name per distribution\n    state: present\n  become: yes\n  notify: restart bind9\n\n- name: Ensure BIND9 service is started and enabled (service name varies, e.g., named or bind9)\n  ansible.builtin.service:\n    name: named # TODO: Adjust service name (e.g., bind9 on Debian/Ubuntu)\n    state: started\n    enabled: yes\n  become: yes\n\n"
                TASK_CONTENT+="${TEMPLATE_TASK_COMMENT}\n# - name: Deploy BIND9 configuration (example)\n#   ansible.builtin.template:\n#     src: ../../templates/bind9.j2\n#     dest: /etc/bind/named.conf.options # TODO: Adjust path\n#   become: yes\n#   notify: restart bind9\n"
                HANDLER_CONTENT+="- name: restart bind9\n  ansible.builtin.service:\n    name: named # TODO: Adjust service name\n    state: restarted\n  become: yes\n"
                ;;
            "haproxy")
                TASK_CONTENT+="- name: Ensure HAProxy package is present\n  ansible.builtin.package:\n    name: haproxy\n    state: present\n  become: yes\n  notify: restart haproxy\n\n- name: Ensure HAProxy service is started and enabled\n  ansible.builtin.service:\n    name: haproxy\n    state: started\n    enabled: yes\n  become: yes\n\n"
                TASK_CONTENT+="${TEMPLATE_TASK_COMMENT}\n# - name: Deploy HAProxy configuration (example)\n#   ansible.builtin.template:\n#     src: ../../templates/haproxy.j2\n#     dest: /etc/haproxy/haproxy.cfg # TODO: Adjust path\n#   become: yes\n#   notify: restart haproxy\n"
                HANDLER_CONTENT+="- name: restart haproxy\n  ansible.builtin.service:\n    name: haproxy\n    state: restarted\n  become: yes\n"
                ;;
        esac
    elif [ "$ROLE_OS" == "windows" ]; then
        TASK_CONTENT+="# Ensure your tasks are idempotent.\n# Most Windows tasks do not require 'become'. Privileges are usually tied to the WinRM user.\n\n"
        case "$ROLE_SERVICE" in
            "dns")
                TASK_CONTENT+="- name: Ensure DNS Server Windows feature is installed\n  ansible.windows.win_feature:\n    name: DNS\n    state: present\n  register: dns_install_result\n\n- name: Reboot if DNS installation requires it (optional)\n  ansible.windows.win_reboot:\n  when: dns_install_result.reboot_required\n\n"
                TASK_CONTENT+="${TEMPLATE_TASK_COMMENT}\n# - name: Configure DNS zone using a PowerShell script (template example)\n#   ansible.windows.win_template:\n#     src: ../../templates/dns_win.j2 # This template should produce a .ps1 script\n#     dest: C:\\Temp\\configure_dns_zone.ps1\n# - name: Execute DNS configuration script\n#   ansible.windows.win_powershell:\n#     path: C:\\Temp\\configure_dns_zone.ps1\n#     removes_scripts_after_running: true\n" # Note: win_powershell 'script' parameter is deprecated, use 'path'
                HANDLER_CONTENT+="# - name: clear dns cache # Example, actual handler may vary\n#   ansible.windows.win_shell: Clear-DnsServerCache -Force\n"
                ;;
            "webserver") # IIS
                TASK_CONTENT+="- name: Ensure IIS Web-Server feature is installed\n  ansible.windows.win_feature:\n    name: Web-Server\n    state: present\n    include_management_tools: yes\n    # include_all_subfeatures: yes # Optional\n  notify: restart iis\n\n- name: Ensure IIS service (W3SVC) is started and set to auto\n  ansible.windows.win_service:\n    name: W3SVC\n    start_mode: auto\n    state: started\n\n"
                TASK_CONTENT+="${TEMPLATE_TASK_COMMENT}\n# - name: Deploy default web page (example)\n#   ansible.windows.win_template:\n#     src: ../../templates/iis.j2 # Example: an index.html or web.config\n#     dest: C:\\inetpub\\wwwroot\\index.html # TODO: Adjust path\n"
                HANDLER_CONTENT+="- name: restart iis\n  ansible.windows.win_service:\n    name: W3SVC\n    state: restarted\n"
                ;;
        esac
    fi
    TASK_CONTENT+="\n# TODO: Add more tasks for detailed configuration, firewall rules, etc.\n"
    TASK_CONTENT+="# Refer to Ansible module documentation: https://docs.ansible.com/ansible/latest/collections/index.html\n"
    create_file "${ROLE_DIR}/tasks/main.yml" "${TASK_CONTENT}"
    create_file "${ROLE_DIR}/handlers/main.yml" "${HANDLER_CONTENT}"

    VARS_CONTENT="# vars file for ${ROLE_FULL_NAME}\n# Variables defined here have high precedence.\n# Example:\n# my_critical_setting: 'important_value'\n"
    create_file "${ROLE_DIR}/vars/main.yml" "${VARS_CONTENT}"

    DEFAULTS_CONTENT="# defaults file for ${ROLE_FULL_NAME}\n# Define default variables for this role. These are easily overridden.\n# Example:\n# ${ROLE_SERVICE}_port: 80\n"
    create_file "${ROLE_DIR}/defaults/main.yml" "${DEFAULTS_CONTENT}"

    META_CONTENT="galaxy_info:\n  author: Your Name Here\n  description: Manages the ${ROLE_SERVICE} service on ${ROLE_OS} hosts.\n  company: Your Company Here\n  license: MIT # Or your preferred license\n  min_ansible_version: '2.10' # Or your preferred minimum version\n\n  platforms:"
    if [ "$ROLE_OS" == "linux" ]; then
        META_CONTENT+="\n  - name: EL\n    versions:\n      - '7'\n      - '8'\n      - '9'\n  - name: Debian\n    versions:\n      - buster\n      - bullseye\n  - name: Ubuntu\n    versions:\n      - focal\n      - jammy"
    elif [ "$ROLE_OS" == "windows" ]; then
        META_CONTENT+="\n  - name: Windows\n    versions:\n      - '2012R2'\n      - '2016'\n      - '2019'\n      - '2022'"
    fi
    META_CONTENT+="\n\ndependencies: []\n  # List role dependencies here, for example:\n  # - { role: common, some_parameter: value }\n"
    create_file "${ROLE_DIR}/meta/main.yml" "${META_CONTENT}"

    echo "Created role structure for ${ROLE_FULL_NAME}"
done


# --- 7. Playbook Generation (playbooks/main.yml) ---
PLAYBOOK_CONTENT="---\n# Main playbook to orchestrate configuration of services on hosts.\n\n"
declare -A linux_roles_for_playbook
declare -A windows_roles_for_playbook

# Populate roles for each OS group based on actual host assignments
for HOST_KEY in "${!HOST_OS[@]}"; do
    OS=${HOST_OS["$HOST_KEY"]}
    SERVICES_ON_HOST=${HOST_SERVICES["$HOST_KEY"]}
    IFS=',' read -r -a SERVICE_ARRAY <<< "$SERVICES_ON_HOST"
    for SERVICE_NAME in "${SERVICE_ARRAY[@]}"; do
        if [ -n "$SERVICE_NAME" ]; then # Ensure service name is not empty
            if [ "$OS" == "linux" ]; then
                linux_roles_for_playbook["linux_${SERVICE_NAME}"]=1
            elif [ "$OS" == "windows" ]; then
                windows_roles_for_playbook["windows_${SERVICE_NAME}"]=1
            fi
        fi
    done
done

if $HAS_LINUX_HOSTS; then
    PLAYBOOK_CONTENT+="- name: Configure Linux Hosts\n"
    PLAYBOOK_CONTENT+="  hosts: linux_hosts\n"
    PLAYBOOK_CONTENT+="  # become: yes # Default 'become' is set in ansible.cfg [privilege_escalation]\n"
    PLAYBOOK_CONTENT+="  gather_facts: yes\n"
    PLAYBOOK_CONTENT+="  # pre_tasks:\n  #   - name: Update apt cache on Debian/Ubuntu before roles\n  #     ansible.builtin.apt:\n  #       update_cache: yes\n  #       cache_valid_time: 3600 # Update if cache is older than 1 hour\n  #     become: yes\n  #     when: ansible_os_family == \"Debian\"\n\n"
    PLAYBOOK_CONTENT+="  roles:\n"
    for role_name in "${!linux_roles_for_playbook[@]}"; do
        PLAYBOOK_CONTENT+="    - ${role_name}\n"
    done
    PLAYBOOK_CONTENT+="\n  # tasks:\n  #   - name: Final Linux configuration checks\n  #     ansible.builtin.debug:\n  #       msg: \"Linux host {{ inventory_hostname }} configuration complete.\"\n\n"
fi

if $HAS_WINDOWS_HOSTS; then
    PLAYBOOK_CONTENT+="- name: Configure Windows Hosts\n"
    PLAYBOOK_CONTENT+="  hosts: windows_hosts\n"
    PLAYBOOK_CONTENT+="  gather_facts: yes\n"
    PLAYBOOK_CONTENT+="  roles:\n"
    for role_name in "${!windows_roles_for_playbook[@]}"; do
        PLAYBOOK_CONTENT+="    - ${role_name}\n"
    done
    PLAYBOOK_CONTENT+="\n  # tasks:\n  #   - name: Final Windows configuration checks\n  #     ansible.builtin.debug:\n  #       msg: \"Windows host {{ inventory_hostname }} configuration complete.\"\n\n"
fi

PLAYBOOK_CONTENT+="# You can add more plays targeting specific hosts or groups.\n"
PLAYBOOK_CONTENT+="# Use 'group_vars/' and 'host_vars/' directories to manage variables effectively.\n"
PLAYBOOK_CONTENT+="# Example: create 'group_vars/all.yml' for variables common to all hosts."

create_file "${PROJECT_NAME}/playbooks/main.yml" "${PLAYBOOK_CONTENT}"

# --- 8. README.md Generation ---
README_CONTENT="# Ansible Project: ${PROJECT_NAME}\n\n"
README_CONTENT+="This Ansible project was automatically generated to help you set up and manage basic services on your Linux and Windows hosts.\n\n"
README_CONTENT+="## Project Structure Overview\n\n\`\`\`\n${PROJECT_NAME}/\n"
README_CONTENT+="├── ansible.cfg             # Main Ansible configuration for the project\n"
README_CONTENT+="├── inventory/                # Host inventory definitions\n"
README_CONTENT+="│   └── hosts.ini           # Default inventory file with host groups\n"
README_CONTENT+="├── group_vars/             # Directory for group-specific variables (e.g., group_vars/linux_hosts.yml)\n"
README_CONTENT+="├── host_vars/              # Directory for host-specific variables (e.g., host_vars/server1.yml)\n"
README_CONTENT+="├── playbooks/\n"
README_CONTENT+="│   └── main.yml            # Main playbook to run against your infrastructure\n"
README_CONTENT+="├── roles/                    # Contains all the roles for service management\n"
for ROLE_FULL_NAME in "${UNIQUE_ROLES[@]}"; do
    README_CONTENT+="│   └── ${ROLE_FULL_NAME}/      # Role for ${ROLE_FULL_NAME#*_} on ${ROLE_FULL_NAME%%_*}\n"
    README_CONTENT+="│       ├── tasks/main.yml    # Main tasks for the role\n"
    README_CONTENT+="│       ├── handlers/main.yml # Handlers triggered by tasks\n"
    README_CONTENT+="│       ├── templates/        # Role-specific Jinja2 templates (can also use project templates/)\n"
    README_CONTENT+="│       ├── vars/main.yml     # Variables specific to this role (high precedence)\n"
    README_CONTENT+="│       ├── defaults/main.yml # Default variables for the role (lowest precedence)\n"
    README_CONTENT+="│       └── meta/main.yml     # Role metadata (dependencies, platform support)\n"
done
if [ ${#UNIQUE_ROLES[@]} -eq 0 ]; then
    README_CONTENT+="│   └── (No roles generated based on input)\n"
fi
README_CONTENT+="├── templates/                # Project-level Jinja2 templates (copied from source: ${JINJA2_TEMPLATES_SRC_DIR}/)\n"
if [ ${#UNIQUE_TEMPLATES[@]} -gt 0 ]; then
    for TEMPLATE_FILE in "${UNIQUE_TEMPLATES[@]}"; do
        README_CONTENT+="│   └── ${TEMPLATE_FILE}\n"
    done
else
    README_CONTENT+="│   └── (No templates copied based on service selection)\n"
fi
README_CONTENT+="└── README.md               # This documentation file\n\`\`\`\n\n"

README_CONTENT+="## Getting Started\n\n"
README_CONTENT+="1.  **Navigate to the Project Directory:**\n    \`cd ${PROJECT_NAME}\`\n\n"
README_CONTENT+="2.  **Review and Customize:**\n"
README_CONTENT+="    * **Inventory (`inventory/hosts.ini`):**\n        * Verify hostnames. Replace with FQDNs or IP addresses if necessary.\n        * Adjust connection variables per host if defaults are not suitable (e.g., `ansible_user`, `ansible_ssh_private_key_file`).\n"
README_CONTENT+="    * **Variables:**\n        * Use `group_vars/` and `host_vars/` for environment-specific settings. For example, create `group_vars/all.yml` for global variables, or `group_vars/linux_hosts.yml` for variables applicable only to Linux hosts.\n        * Role defaults are in `roles/ROLENAME/defaults/main.yml` (easily overridden).\n        * Role variables are in `roles/ROLENAME/vars/main.yml` (higher precedence).\n"
README_CONTENT+="    * **Roles (`roles/`):**\n        * The core logic for managing each service is within its role, primarily in `tasks/main.yml`.\n        * Flesh out the tasks. The generated files contain TODOs and examples.\n        * Ensure templates (if used) in the `templates/` directory (or role-specific `roles/ROLENAME/templates/`) are correct and referenced appropriately in tasks (e.g., `src: ../../templates/your_template.j2` when a role task references a project-level template).\n"
README_CONTENT+="    * **Playbook (`playbooks/main.yml`):**\n        * This playbook orchestrates the roles. Modify it to change which roles run or to add specific tasks outside of roles.\n\n"

README_CONTENT+="3.  **(Windows Hosts Only) Configure WinRM:**\n"
README_CONTENT+="    Ansible communicates with Windows hosts using Windows Remote Management (WinRM). Ensure it's enabled and configured on your Windows targets.\n"
if [ "$USE_SECURE_PROTOCOLS" = "no" ]; then
    README_CONTENT+="    * **You selected INSECURE (HTTP) WinRM for this project.**\n"
    README_CONTENT+="        On each target Windows host, run these PowerShell commands as Administrator:\n"
    README_CONTENT+="        \`\`\`powershell\n        # Basic WinRM setup (enables HTTP listener by default)\n        winrm quickconfig -q\n\n        # Allow unencrypted traffic (required for HTTP)\n        winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'\n\n        # Enable Basic authentication (if you plan to use username/password with HTTP)\n        winrm set winrm/config/service/auth '@{Basic=\"true\"}'\n\n        # Ensure Firewall allows WinRM HTTP port (default 5985)\n        # Example: New-NetFirewallRule -Name 'Ansible WinRM HTTP In' -DisplayName 'Ansible WinRM HTTP In' -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5985 -Profile Any -Action Allow\n        \`\`\`\n"
else
    README_CONTENT+="    * **You selected SECURE (HTTPS) WinRM for this project.**\n"
    README_CONTENT+="        This is the recommended approach for production.\n"
    README_CONTENT+="        On each target Windows host:\n"
    README_CONTENT+="        1.  Ensure WinRM is enabled: `Enable-PSRemoting -Force`\n"
    README_CONTENT+="        2.  A valid SSL certificate must be installed on the host and configured for the WinRM HTTPS listener (port 5986).\n            * For lab/test environments, a self-signed certificate can be used. The generated Ansible inventory for Windows hosts includes `ansible_winrm_server_cert_validation=ignore` to allow this.\n            * For production, use a certificate issued by a trusted Certificate Authority (CA) and set `ansible_winrm_server_cert_validation=validate`.\n"
    README_CONTENT+="        3.  Consult the Ansible documentation for detailed instructions on configuring WinRM for HTTPS: [Ansible Windows Setup](https://docs.ansible.com/ansible/latest/user_guide/windows_setup.html)\n"
fi
README_CONTENT+="    * Test WinRM connection from your Ansible control node: `ansible windows_hosts -i inventory/hosts.ini -m win_ping`\n\n"

README_CONTENT+="4.  **Run the Playbook:**\n"
README_CONTENT+="    From the `${PROJECT_NAME}` directory:\n"
README_CONTENT+="    \`\`\`bash\n"
README_CONTENT+="    # Run the main playbook against all hosts in the inventory\n"
README_CONTENT+="    ansible-playbook playbooks/main.yml\n\n"
README_CONTENT+="    # Run against a specific group or host\n"
README_CONTENT+="    # ansible-playbook playbooks/main.yml --limit linux_hosts\n"
README_CONTENT+="    # ansible-playbook playbooks/main.yml --limit YOUR_HOSTNAME\n\n"
README_CONTENT+="    # For more detailed output (debugging)\n"
README_CONTENT+="    # ansible-playbook playbooks/main.yml -vvv\n"
README_CONTENT+="    \`\`\`\n\n"

if [ "$USE_SECURE_PROTOCOLS" = "no" ]; then
    README_CONTENT+="## ⚠️ Security Warning: Insecure Connection Setup\n\n"
    README_CONTENT+="${INSECURE_WARNING_MESSAGE_GENERAL}\n\n"
    README_CONTENT+="* **For Windows Hosts:** You chose to configure WinRM over HTTP (port 5985) with basic authentication and certificate validation ignored. This transmits credentials and data in plain text.\n"
    README_CONTENT+="* **For Linux Hosts:** While SSH itself is encrypted, `host_key_checking = False` is set in `ansible.cfg`. This bypasses verification of the remote host's SSH key, making you vulnerable to man-in-the-middle attacks. For production, set this to `True` and manage known_hosts.\n\n"
    README_CONTENT+="**Always prioritize secure connection methods (SSH with key validation, WinRM over HTTPS) for production systems.**\n\n"
fi

README_CONTENT+="## Further Customization\n\n"
README_CONTENT+="* **Adding New Hosts:** Edit `inventory/hosts.ini` and assign them to existing or new groups.\n"
README_CONTENT+="* **Adding New Services/Roles:**\n    1.  Create a new role directory structure under `roles/` (e.g., `roles/linux_newservice/`).\n    2.  Develop tasks, handlers, variables, and templates for the new role.\n    3.  Update `playbooks/main.yml` to apply the new role to the appropriate host groups.\n"
README_CONTENT+="* **Ansible Vault:** For managing sensitive data like passwords or API keys, use [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html).\n\n"
README_CONTENT+="Happy Automating!\n"

create_file "${PROJECT_NAME}/README.md" "${README_CONTENT}"

# --- Final Output ---
echo ""
echo "--------------------------------------------------"
echo "✅ Ansible project '${PROJECT_NAME}' generated successfully!"
echo "--------------------------------------------------"
echo ""
echo "Next Steps:"
echo "1.  `cd ${PROJECT_NAME}`"
echo "2.  **Review and Customize:**"
echo "    * `inventory/hosts.ini` (verify hostnames/IPs, connection details)"
echo "    * `roles/*/tasks/main.yml` (implement the actual service automation logic)"
echo "    * `templates/` (if using templates, ensure they are correct and customize them)"
echo "    * `group_vars/` and `host_vars/` for variables."
echo "    * `playbooks/main.yml` (review role application)"
echo "3.  **Prepare Target Hosts:**"
echo "    * For Windows: Configure WinRM as per instructions in `README.md`."
echo "    * For Linux: Ensure SSH access is available (key-based auth recommended)."
echo "4.  **(If you skipped this earlier)** Populate the external \`${JINJA2_TEMPLATES_SRC_DIR}/\` directory with your actual Jinja2 templates and either:"
echo "    a) Manually copy needed templates into \`${PROJECT_NAME}/templates/\` and update role tasks."
echo "    b) Or, re-run this script (after removing the current \`${PROJECT_NAME}\` directory) to automatically copy them."
echo "5.  **Run your playbook:** \`ansible-playbook playbooks/main.yml\`"
echo ""
if [ "$USE_SECURE_PROTOCOLS" = "no" ]; then
    echo "🔴 REMEMBER: You opted for an INSECURE setup. This is for LAB/TESTING ONLY."
    echo "   Review the security warnings in the generated README.md."
fi
echo "--------------------------------------------------"

exit 0