#!/bin/bash

# Function to print messages in bold
print_bold() {
    echo -e "\033[1m$1\033[0m"
}

# Function to check if the script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "\033[0;31mThis script must be run as root. Use sudo.\033[0m"
        exit 1
    fi
}

# Check if the script is run as root
check_root

display_banner() {
clear
echo -e "\033[1;34m============================================================================================================="
echo -e "           			\033[1;32mOS HARDENING SCRIPT\033[1;34m"
echo -e "============================================================================================================="
echo "

   ▄███████▄    ▄████████  ▄██████▄      ███        ▄████████  ▄████████     ███      ▄██████▄     ▄████████ 
  ███    ███   ███    ███ ███    ███ ▀█████████▄   ███    ███ ███    ███ ▀█████████▄ ███    ███   ███    ███ 
  ███    ███   ███    ███ ███    ███    ▀███▀▀██   ███    █▀  ███    █▀     ▀███▀▀██ ███    ███   ███    ███ 
  ███    ███  ▄███▄▄▄▄██▀ ███    ███     ███   ▀  ▄███▄▄▄     ███            ███   ▀ ███    ███  ▄███▄▄▄▄██▀ 
▀█████████▀  ▀▀███▀▀▀▀▀   ███    ███     ███     ▀▀███▀▀▀     ███            ███     ███    ███ ▀▀███▀▀▀▀▀   
  ███        ▀███████████ ███    ███     ███       ███    █▄  ███    █▄      ███     ███    ███ ▀███████████ 
  ███          ███    ███ ███    ███     ███       ███    ███ ███    ███     ███     ███    ███   ███    ███ 
 ▄████▀        ███    ███  ▀██████▀     ▄████▀     ██████████ ████████▀     ▄████▀    ▀██████▀    ███    ███ 
               ███    ███                                                                         ███    ███ 

 "
}

# Function to add a delay
add_delay() {
    sleep 2.5
}

# Display banner
display_banner
echo
echo
# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Dynamic Information
SCRIPT_NAME=$(basename "$0")
VERSION="1.0"
CURRENT_DATE=$(date "+%Y-%m-%d %H:%M:%S")
USER=$(whoami)

# Print the banner
echo -e "${RED}#####################################################################################################${NC}"
echo -e "${RED}#                                           																#${NC}"
echo -e "${RED}#  				${GREEN}Script Name:${NC} ${GREEN}$SCRIPT_NAME${NC}                   				#${RED}"
echo -e "${RED}#  				${GREEN}Version:${NC} ${GREEN}$VERSION${NC}                              		#${RED}"
echo -e "${RED}#  				${GREEN}Date:${NC} ${GREEN}$CURRENT_DATE${NC}                       		 			#${RED}"
echo -e "${RED}#  				${GREEN}User:${NC} ${GREEN}$USER${NC}                          	 	#${RED}"
echo -e "${RED}#                                           													   		 #${NC}"
echo -e "${RED}####################################################################################################${NC}"
echo
print_bold "Starting Security Hardening Script"
echo
echo

# Function to check and run commands
run_command() {
    local command="$1"
    echo -e "\nRunning: $command"
    eval "$command"
    if [ $? -ne 0 ]; then
        echo -e "\033[0;31mError occurred while executing: $command\033[0m"
        echo -e "Skipping this step and continuing..."
        return 1
    fi
    return 0
}

# Function to prompt for user input
prompt_input() {
    local prompt="$1"
    local var_name="$2"
    read -p "$prompt: " input
    eval "$var_name=\"$input\""
}

# Function to prompt for user choice
prompt_choice() {
    local prompt="$1"
    local option1="$2"
    local option2="$3"
    local choice

    echo -e "\n$prompt"
    echo "1) $option1"
    echo "2) $option2"
    read -p "Select an option (1 or 2): " choice

    case $choice in
        1)
            echo "You selected: $option1"
            return 1
            ;;
        2)
            echo "You selected: $option2"
            return 2
            ;;
        *)
            echo "Invalid option. Exiting."
            exit 1
            ;;
    esac
}

# Function to prompt for confirmation
prompt_confirm() {
    local prompt="$1"
    local default="$2"
    local choice

    echo -e "\n$prompt [${default:0:1}/n]"
    read -p "Confirm (y/n): " choice

    if [ -z "$choice" ]; then
        choice=$default
    fi

    if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
        return 0
    else
        return 1
    fi
}

# Spoof MAC Address
print_bold "Configuring MAC Address Spoofing..."
add_delay
echo "Please manually set the MAC address in Network Manager as described."
echo "Open Network Manager."
echo "1. Edit your Wifi/Wired Connection."
echo "2. Click on the Identity Tab and enter the MAC Address you want in the Cloned Address box."
echo "3. Click on Apply."
add_delay
echo
# Prompt for Avahi action
prompt_choice "What action would you like to take for Avahi?" "Disable Avahi" "Remove Avahi"
avahi_choice=$?

if [ $avahi_choice -eq 1 ]; then
    # Disable Avahi
    print_bold "Disabling Avahi..."
    add_delay
    run_command "sudo systemctl disable avahi-daemon"
elif [ $avahi_choice -eq 2 ]; then
    # Remove Avahi
    print_bold "Removing Avahi..."
    add_delay
    run_command "sudo apt purge avahi-daemon"
fi
echo
# Prompt for CUPS action
prompt_choice "What action would you like to take for CUPS?" "Disable CUPS" "Remove CUPS"
cups_choice=$?

if [ $cups_choice -eq 1 ]; then
    # Disable CUPS
    print_bold "Disabling CUPS..."
    add_delay
    run_command "sudo systemctl disable cups-browsed || sudo systemctl stop cups-browsed"
elif [ $cups_choice -eq 2 ]; then
    # Remove CUPS
    print_bold "Removing CUPS..."
    add_delay
    run_command "sudo apt autoremove cups-daemon"
fi
echo

# Function to check if a command exists, and install if not
check_and_install_ufw() {
    if ! command -v ufw &> /dev/null; then
        echo "UFW not found. Installing..."
        sudo apt-get update && sudo apt-get install ufw
        if [ $? -ne 0 ]; then
            echo -e "\033[0;31mFailed to install UFW. Exiting.\033[0m"
            exit 1
        fi
    fi
}

# Check and install UFW if necessary
check_and_install_ufw

# Configure UFW
print_bold "Configuring UFW Firewall..."
add_delay

# Enable UFW
run_command "sudo ufw enable" || { echo "Failed to enable UFW. Skipping UFW configuration."; exit 1; }

# Prompt user for ports
prompt_input "Enter the UDP ports to allow for outgoing traffic (comma-separated, e.g., 5025,5005)" UDP_OUT_PORTS
prompt_input "Enter the UDP ports to allow for incoming traffic (comma-separated, e.g., 5015,5005)" UDP_IN_PORTS
prompt_input "Enter the TCP ports to allow for outgoing traffic (comma-separated, e.g., 6050,7050)" TCP_OUT_PORTS
prompt_input "Enter the TCP ports to allow for incoming traffic (comma-separated, e.g., 7050,6050)" TCP_IN_PORTS
prompt_input "Enter the port to allow for MySQL (e.g., 3306)" MYSQL_PORT

# Set default rules
run_command "sudo ufw default deny incoming"
run_command "sudo ufw default deny outgoing"

# Allow HTTP and HTTPS
run_command "sudo ufw allow out http comment 'allow HTTP'"
run_command "sudo ufw allow out https comment 'allow HTTPS'"

# Allow user-defined UDP outgoing ports
IFS=',' read -r -a udp_out_ports <<< "$UDP_OUT_PORTS"
for port in "${udp_out_ports[@]}"; do
    run_command "sudo ufw allow out proto udp port $port"
done

# Allow user-defined UDP incoming ports
IFS=',' read -r -a udp_in_ports <<< "$UDP_IN_PORTS"
for port in "${udp_in_ports[@]}"; do
    run_command "sudo ufw allow in proto udp port $port"
done

# Allow user-defined TCP outgoing ports
IFS=',' read -r -a tcp_out_ports <<< "$TCP_OUT_PORTS"
for port in "${tcp_out_ports[@]}"; do
    run_command "sudo ufw allow out proto tcp port $port"
done

# Allow user-defined TCP incoming ports
IFS=',' read -r -a tcp_in_ports <<< "$TCP_IN_PORTS"
for port in "${tcp_in_ports[@]}"; do
    run_command "sudo ufw allow in proto tcp port $port"
done

# Allow MySQL port
run_command "sudo ufw allow in proto tcp port $MYSQL_PORT comment 'MySQL service'"

# Allow DNS
run_command "sudo ufw allow out 53/tcp"
run_command "sudo ufw allow out 53/udp"

add_delay

# Default outgoing rules
print_bold "Configuring default outgoing rules..."
add_delay
run_command "sudo ufw default deny outgoing"

# Show UFW status
run_command "sudo ufw status numbered"

# Defend Against Physical Attacks
print_bold "Defending Against Physical Attacks..."
echo "Ensure Secure Boot is enabled and set Supervisor password in BIOS."
echo "Follow the instructions: if you need to set that"
echo "1. Restart your computer."
echo "2. Enter the BIOS setup by pressing the designated key (e.g., F2, Del, Esc) during startup."
echo "3. Navigate to the 'Security' tab or similar section."
echo "4. Select 'Supervisor Password' or 'Administrator Password'."
echo "5. Enter a strong password and confirm it."
echo "6. Save changes and exit the BIOS setup."
echo "7. Verify by rebooting and re-entering BIOS setup."
add_delay

echo
# Install and Configure USBGuard
prompt_confirm "Do you want to install and configure USBGuard?" "y"
if [ $? -eq 0 ]; then
add_delay
run_command "sudo apt install usbguard usbutils udisks2"
run_command "sudo systemctl enable usbguard.service --now"
run_command "sudo systemctl start usbguard.service"
run_command "sudo usbguard generate-policy -X -t reject >/etc/usbguard/rules.conf"
echo
add_delay
echo "This whitelists currently connected devices"
echo "List devices with 'lsusb' and allow specific devices using 'sudo usbguard allow-device {device_ID}'."
add_delay

# Install and Configure AIDE
#prompt_confirm "Install and Configure AIDE?" "y"
#if [ $? -eq 0 ]; then
#    print_bold "Installing and Configuring AIDE..."
#    add_delay
#    run_command "sudo apt install aide"
#    run_command "sudo aideinit"
#    run_command "cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
#    run_command "update-aide.conf"
#    run_command "cp /var/lib/aide/aide.conf.autogenerated /etc/aide/aide.conf"
#    run_command "aide -c /etc/aide/aide.conf --check"
#fi

# Data at Rest Encryption in MySQL
#prompt_confirm "Configure MySQL Data Encryption?" "y"
#if [ $? -eq 0 ]; then
#    print_bold "Configuring MySQL Data Encryption..."
#    echo "Ensure mysql-server is installed and configured."
#    echo "Add the following to /etc/mysql/mysql.conf.d/mysqld.conf:"
#    echo "early-plugin-load = keyring_file.so"
#    echo "keyring_file_data = /var/lib/mysql-keyring/keyring"
#    echo "Restart MySQL service after making changes."

#    echo "Access MySQL and run:"
#    echo "INSTALL PLUGIN keyring-file SONAME 'keyring_file.so';"
#    echo "SET GLOBAL keyring_file_data = '/var/lib/mysql-keyring/';"
#    echo "SET GLOBAL default_table_encryption = ON;"
#    echo "ALTER TABLE t1 ENCRYPTION = 'Y';"
#    echo "ALTER INSTANCE ROTATE INNODB MASTER KEY;"
#fi
echo
echo

# Kernel Hardening
print_bold "Configuring Kernel Hardening..."
add_delay
echo "Add the following to /etc/sysctl.conf or /etc/sysctl.d/*.conf:"
cat <<EOL >> /etc/sysctl.conf
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.printk=3 3 3 3
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
dev.tty.ldisc_autoload=0
vm.unprivileged_userfaultfd=0
kernel.kexec_load_disabled=1
kernel.sysrq=4
kernel.unprivileged_userns_clone=0
kernel.perf_event_paranoid=3
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0
kernel.yama.ptrace_scope=2
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
fs.protected_symlinks=1
fs.protected_hardlinks=1
fs.protected_fifos=2
fs.protected_regular=2
net.ipv4.tcp_timestamps=0
EOL
run_command "sudo sysctl -p"
echo
echo
print_bold "Updating GRUB with Boot Parameters..."
echo
add_delay
run_command "sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=\"[^\"]*\"/GRUB_CMDLINE_LINUX_DEFAULT=\"slab_nomerge page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0 spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force ipv6.disable=1 apparmor=1 security=apparmor random.trust_cpu=off intel_iommu=on amd_iommu=on efi=disable_early_pci_dma\"/g' /etc/default/grub"
run_command "sudo update-grub"
echo
echo

# Blacklist Kernel Modules
print_bold "Blacklisting Kernel Modules..."
add_delay
cat <<EOL | sudo tee -a /etc/modprobe.d/blacklist.conf
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install ksmbd /bin/true
install gfs2 /bin/true
install vivid /bin/false
install bluetooth /bin/false
install btusb /bin/false
install uvcvideo /bin/false
install firewire-core /bin/false
install thunderbolt /bin/false
EOL
echo
echo

# Rfkill
print_bold "Configuring rfkill..."
echo "Not Configured in the present situation."
add_delay
#run_command "rfkill block all"
#run_command "rfkill unblock wifi"

# Kernel Pointer Leaks
print_bold "Configuring Kernel Pointer Leaks..."
add_delay
echo "If to implement restriction 'chmod 700 /home/$user' can be utilized, but difficult to access everything if run"
#run_command "chmod 700 /home/$user"
add_delay
run_command "chmod 700 /boot /usr/src /lib/modules /usr/lib/modules"

# File Permissions
print_bold "Allotting File Permissions..."
add_delay
run_command "dpkg-statoverride --add root root 700 /usr/src"
run_command "dpkg-statoverride --add root root 700 /lib/modules"
run_command "dpkg-statoverride --add root root 700 /usr/lib/modules"
run_command "dpkg-statoverride --add root root 700 /boot"
echo "To List the current rules type in the command : dpkg-stateoverride --list"

# Deny root login via SSH
echo
echo
print_bold "Denying root login via SSH..."
add_delay
run_command "sudo sed -i '/^PermitRootLogin/s/.*/PermitRootLogin no/' /etc/ssh/ssh_config"
run_command "sudo systemctl restart ssh.service"

# Remove user from adm group
print_bold "Removing user from 'adm' group to restrict access to kernel logs..."
read -p "Enter username to remove from 'adm' group: " user
add_delay
run_command "sudo gpasswd -d $user adm"
echo
echo
add_delay

#GRUB 2 Password Protection
echo "Steps to Set Up GRUB 2 Password Protection (without password hashing):"
echo ""
echo "1. Open the GRUB Configuration File"
echo "   Run the following command in your terminal:"
echo "   sudo nano /etc/grub.d/40_custom"
echo ""
echo "2. Add Superuser and Password Entries"
echo "   At the top of the 40_custom file, add the following lines:"
echo "   set superusers=\"yourusername\""
echo "   password yourusername yourpassword"
echo "   (Replace 'yourusername' and 'yourpassword' with your desired values.)"
echo ""
echo "3. Protect the GRUB Menu"
echo "   To require a password for editing GRUB menu entries, add the following line:"
echo "   set superusers=\"yourusername\""
echo ""
echo "4. Update GRUB Configuration"
echo "   After making the changes, run the following command:"
echo "   sudo update-grub"
echo ""
echo "5. Reboot and Test"
echo "   Reboot your system using:"
echo "   sudo reboot"
echo ""
echo "   When the GRUB menu appears, try to edit an entry. You should be prompted for the username and password you set."
echo ""
echo "Important Notes:"
echo " - Storing plaintext passwords in configuration files is insecure. Use hashed passwords for better security."
echo " - Always back up your configuration files before making changes."
echo " - If you forget your password, you may need to boot from a live environment to access and edit GRUB configuration files."
echo
echo
add_delay

# Set umask
print_bold "Setting umask to restrict file permissions..."
add_delay
echo "umask 0077" | sudo tee -a /etc/profile
echo "umask 0077" | sudo tee -a /home/$user/.profile
echo "umask 0077" | sudo tee -a /home/$user/.bashrc
echo "UMASK=0077" | sudo tee -a /etc/defaults/login
echo "soft core 0" | sudo tee -a /etc/security/limits.conf
echo "hard core 0" | sudo tee -a /etc/security/limits.conf

echo
echo

# Disable core dumps
print_bold "Disabling core dumps..."
add_delay
sudo bash -c 'cat <<EOF >> /etc/sysctl.d/99-sysctl.conf
kernel.core_pattern=|/bin/false
fs.suid_dumpable=0
vm.swappiness=1
EOF'
run_command "sudo sysctl --system"
echo
echo

# Secure mount options
print_bold "Configuring secure mount options in /etc/fstab..."
add_delay
if prompt_confirm "Update /etc/fstab with secure mount options?" "y"; then
    sudo bash -c 'cat <<EOF >> /etc/fstab
/        /          ext4    defaults                              1 1
#/home    /home      ext4    defaults,nosuid,noexec,nodev          1 2
/tmp     /tmp       ext4    defaults,bind,nosuid,noexec,nodev     1 2
/var     /var       ext4    defaults,bind,nosuid                  1 2
/boot    /boot      ext4    defaults,nosuid,noexec,nodev          1 2
EOF'
fi
echo
echo
# Function to backup AppArmor profiles
backup_apparmor_profiles() {
    print_bold "Backing Up Existing AppArmor Profiles..."
    
    if prompt_confirm "Do you want to backup the existing AppArmor profiles?" "y"; then
        echo "Backing up /etc/apparmor.d to /etc/apparmor.d.bak"
        run_command "sudo cp -r /etc/apparmor.d /etc/apparmor.d.bak"
        #run_command "sudo mv /etc/apparmor.d /etc/apparmor.d.bak"
        print_bold "Backup completed successfully."
    else
        print_bold "Skipping backup. Proceeding with installation."
    fi
}
echo
# Function to configure AppArmor
configure_apparmor() {
    print_bold "Installing AppArmor Profiles from Source..."
    add_delay
    # Backup existing profiles
    backup_apparmor_profiles

    # Install necessary packages
    run_command "sudo apt install apparmor-profiles apparmor-utils"

    # Reload and enforce profiles
    print_bold "Reloading and Enforcing AppArmor Profiles..."
    run_command "sudo apparmor_parser -r /etc/apparmor.d/*"
    run_command "sudo aa-enforce /etc/apparmor.d/*"

    # Check the status of AppArmor profiles
    print_bold "Checking AppArmor Status..."
    run_command "sudo aa-status"

    print_bold "AppArmor profiles installed and configured successfully."
}

# Add the new AppArmor configuration section
configure_apparmor

echo
echo
# Function to create APT seccomp-bpf configuration
configure_apt_seccomp() {
    print_bold "Configuring APT seccomp-bpf..."

    # Create the /etc/apt/apt.conf.d/40sandbox file with the necessary configuration
    echo 'APT::Sandbox::Seccomp "true";' | sudo tee /etc/apt/apt.conf.d/40sandbox > /dev/null

    print_bold "APT seccomp-bpf configuration added successfully."
}

# Call the function to configure APT seccomp-bpf
configure_apt_seccomp
echo
echo
add_delay
print_bold "To permit users to only see their own processes and not those of other users"
# Define the entry to be added
#fstab_entry="proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0"
fstab_entry="proc /proc proc defaults,nosuid,nodev,noexec,hidepid=2 0 0"
echo
add_delay
# Add the entry to /etc/fstab if it does not already exist
grep -qF "$fstab_entry" /etc/fstab || echo "$fstab_entry" >> /etc/fstab
echo
# Prompt user for removing PulseAudio
if prompt_confirm "Do you want to remove PulseAudio?" "n"; then
    echo "Removing PulseAudio..."
    sudo apt-get remove --purge pulseaudio
else
    echo "PulseAudio removal skipped."
fi
echo
echo
# Check if snapd is installed
if dpkg -l | grep -q "^ii  snapd "; then
    # Prompt user for removing Snapd
    if prompt_confirm "Do you want to remove Snapd?" "n"; then
        echo "Removing Snapd..."
        sudo apt purge snapd
        echo "Blocking snapd installation..."
        sudo apt-mark hold snapd
    else
        echo "Snapd removal skipped."
    fi
else
    echo "Snapd is not installed."
fi
echo

# Function to analyze security and prompt user actions
analyze_security() {
    echo -e "\nAnalyzing security of systemd services..."
    
    # Run the security analysis command
    systemd_analyze_output=$(systemd-analyze security)
    echo
    add_delay
    # Display the output
    echo -e "\nSystemd Security Analysis Output:"
    echo "$systemd_analyze_output"
    add_delay
	echo
	echo -e "\nCarefully review the above security analysis."
    echo "The following levels indicate the security status of services:"
    echo "OK        🙂 - The service is considered secure."
    echo "MEDIUM    😐 - The service has moderate security concerns."
    echo "EXPOSED   🙁 - The service is exposed to potential vulnerabilities."
    echo "UNSAFE    😨 - The service is considered unsafe and needs immediate attention."
    add_delay
    add_delay
    # Extract lines with "EXPOSED" or "UNSAFE"
    critical_services=$(echo "$systemd_analyze_output" | grep -E "EXPOSED|UNSAFE")
	echo
	add_delay
    # Check if there are any critical services
    if [ -z "$critical_services" ]; then
        echo -e "\nAll services are secure or have no critical issues."
        return
    fi

    # Display critical services
    echo -e "\nCritical services to review for security:"
    echo "$critical_services" | while read -r line; do
        # Extract the service name and risk level
        service_name=$(echo "$line" | awk '{print $1}')
        risk_level=$(echo "$line" | awk '{print $2}')
        echo -e "$service_name ($risk_level)"
    done
    add_delay
    echo -e "\nPlease review the services listed and make necessary changes."
    echo "Would you like to proceed with reviewing and addressing security concerns? (yes/no)"
    read -r proceed
    
    if [ "$proceed" = "yes" ]; then
        # Provide guidance on actions
        echo -e "\nPlease take appropriate actions for these services to enhance security:"
        echo "- Ensure you have the latest updates and patches."
        echo "- Restrict access and configure proper permissions."
        echo "- Disable services that are not needed."
        echo "- Implement monitoring and auditing."
    else
        echo -e "\nNo actions will be taken. It's important to address the listed security concerns."
    fi
}

# Call the function to analyze security
analyze_security
add_delay
echo
echo
# Function to display and manage running services
manage_services() {
    echo -e "\nListing all active services..."
    systemctl list-units --type=service --state=running
    add_delay
    echo -e "\nCarefully review the services listed above."
    prompt_confirm "Would you like to manage (stop or disable) any of these services?" "n"

    if [ $? -eq 0 ]; then
        while true; do
            read -p "Enter the name of the service you want to stop and disable (or type 'done' to finish): " service_name
            
            if [ "$service_name" == "done" ]; then
                break
            fi

            if systemctl list-units --type=service --state=running | grep -q "$service_name"; then
                echo "Stopping and disabling $service_name..."
                run_command "systemctl stop $service_name"
                run_command "systemctl disable $service_name"
            else
                echo -e "\033[0;31mService $service_name not found. Please check the service name and try again.\033[0m"
            fi
        done
    fi
}
echo
# Manage services
manage_services
echo
add_delay

#Add Firejail PPA and install
print_bold "Adding Firejail PPA and installing Firejail..."
echo "\nThe earlier version of Firejail had a critical vulnerability so this is bit more safer to use, but its not the ultimate solution for the restrictions. "
add_delay
echo "For Ubuntu 18.04+ and derivatives (such as Linux Mint), users are strongly advised to use the PPA i.e., the below provided method. Reason: The firejail package for Ubuntu 20.04 has been left vulnerable to CVE-2021-26910 for months after a patch for it was posted on Launchpad"
add_delay
run_command "add-apt-repository"
run_command "sudo add-apt-repository ppa:deki/firejail"
add_delay
echo
run_command "sudo apt-get update"
add_delay
echo
run_command "sudo apt-get install firejail firejail-profiles"
echo

# Configure Firejail
print_bold "Configuring Firejail profiles..."
add_delay
run_command "sudo firecfg"

# Confirm installation and configuration
print_bold "Verifying Firejail installation..."
add_delay
run_command "firejail --version"


echo "Update complete."
add_delay
echo

# Finalization
print_bold "OS Hardening Script Completed"
echo "The OS hardening script has finished running."
add_delay