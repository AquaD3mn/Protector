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
#check_root

display_banner() {
    clear
    echo "

 █████  █████             ███                      █████              ████  ████          
░░███  ░░███             ░░░                      ░░███              ░░███ ░░███          
 ░███   ░███  ████████   ████  ████████    █████  ███████    ██████   ░███  ░███          
 ░███   ░███ ░░███░░███ ░░███ ░░███░░███  ███░░  ░░░███░    ░░░░░███  ░███  ░███          
 ░███   ░███  ░███ ░███  ░███  ░███ ░███ ░░█████   ░███      ███████  ░███  ░███          
 ░███   ░███  ░███ ░███  ░███  ░███ ░███  ░░░░███  ░███ ███ ███░░███  ░███  ░███          
 ░░████████   ████ █████ █████ ████ █████ ██████   ░░█████ ░░████████ █████ █████ ██ ██ ██
  ░░░░░░░░   ░░░░ ░░░░░ ░░░░░ ░░░░ ░░░░░ ░░░░░░     ░░░░░   ░░░░░░░░ ░░░░░ ░░░░░ ░░ ░░ ░░ 


    "
}


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

# Function to check and uninstall UFW if installed
check_and_uninstall_ufw() {
    if command -v ufw &> /dev/null; then
        echo "UFW found. Removing..."
        sudo apt-get remove ufw
        if [ $? -ne 0 ]; then
            echo -e "\033[0;31mFailed to remove UFW. Exiting.\033[0m"
            exit 1
        fi
    else
        echo "UFW is not installed."
    fi
}

# Function to restore services
restore_services() {
    local service="$1"
    echo "Restoring $service service..."
    run_command "sudo systemctl enable $service"
    run_command "sudo systemctl start $service"
}

# Function to restore packages
restore_package() {
    local package="$1"
    echo "Restoring $package package..."
    run_command "sudo apt-get install $package"
}

# Function to restore CUPS
restore_cups() {
    echo "Restoring CUPS..."
    restore_package "cups"
    run_command "sudo systemctl enable cups-browsed"
    run_command "sudo systemctl start cups-browsed"
}

# Function to restore Avahi
restore_avahi() {
    echo "Restoring Avahi..."
    restore_package "avahi-daemon"
    run_command "sudo systemctl enable avahi-daemon"
    run_command "sudo systemctl start avahi-daemon"
}

# Function to reset UFW rules
reset_ufw() {
    echo
    echo
    print_bold "Resetting UFW rules..."
    add_delay
    run_command "sudo ufw reset"
    run_command "sudo ufw default allow incoming"
    run_command "sudo ufw default allow outgoing"
    run_command "sudo ufw enable"
}

# Function to add a delay
add_delay() {
    sleep 2.5
}

# Display banner
#clear
display_banner
add_delay
print_bold "Removing Security Hardening Configurations"
echo

# Restore Avahi
restore_avahi

# Restore CUPS
restore_cups

# Reset UFW rules
reset_ufw

# Check and uninstall UFW if installed
check_and_uninstall_ufw

# Function to remove kernel hardening settings
remove_kernel_hardening() {
    echo
    echo
    print_bold "Removing Kernel Hardening Settings..."
    add_delay
    sudo sed -i '/^kernel.kptr_restrict/d' /etc/sysctl.conf
    sudo sed -i '/^kernel.dmesg_restrict/d' /etc/sysctl.conf
    sudo sed -i '/^kernel.printk/d' /etc/sysctl.conf
    sudo sed -i '/^kernel.unprivileged_bpf_disabled/d' /etc/sysctl.conf
    sudo sed -i '/^net.core.bpf_jit_harden/d' /etc/sysctl.conf
    sudo sed -i '/^dev.tty.ldisc_autoload/d' /etc/sysctl.conf
    sudo sed -i '/^vm.unprivileged_userfaultfd/d' /etc/sysctl.conf
    sudo sed -i '/^kernel.kexec_load_disabled/d' /etc/sysctl.conf
    sudo sed -i '/^kernel.sysrq/d' /etc/sysctl.conf
    sudo sed -i '/^kernel.unprivileged_userns_clone/d' /etc/sysctl.conf
    sudo sed -i '/^kernel.perf_event_paranoid/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.tcp_rfc1337/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.all.rp_filter/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.default.rp_filter/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.all.accept_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.default.accept_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.all.secure_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.default.secure_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv6.conf.all.accept_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv6.conf.default.accept_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.all.send_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.default.send_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv6.conf.all.send_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv6.conf.default.send_redirects/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.icmp_echo_ignore_all/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.all.accept_source_route/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.conf.default.accept_source_route/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv6.conf.all.accept_source_route/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv6.conf.default.accept_source_route/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv6.conf.all.accept_ra/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv6.conf.default.accept_ra/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.tcp_sack/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.tcp_dsack/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.tcp_fack/d' /etc/sysctl.conf
    sudo sed -i '/^kernel.yama.ptrace_scope/d' /etc/sysctl.conf
    sudo sed -i '/^vm.mmap_rnd_bits/d' /etc/sysctl.conf
    sudo sed -i '/^vm.mmap_rnd_compat_bits/d' /etc/sysctl.conf
    sudo sed -i '/^fs.protected_symlinks/d' /etc/sysctl.conf
    sudo sed -i '/^fs.protected_hardlinks/d' /etc/sysctl.conf
    sudo sed -i '/^fs.protected_fifos/d' /etc/sysctl.conf
    sudo sed -i '/^fs.protected_regular/d' /etc/sysctl.conf
    sudo sed -i '/^net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
    sudo sysctl -p
}

# Function to revert GRUB boot parameters
revert_grub_boot_parameters() {
    echo
    print_bold "Reverting GRUB Boot Parameters..."
    add_delay
    #sudo sed -i 's/slab_nomerge page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0 spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force ipv6.disable=1 apparmor=1 security=apparmor random.trust_cpu=off intel_iommu=on amd_iommu=on efi=disable_early_pci_dma"/"GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"/' /etc/default/grub
    sudo sed -i 's/slab_nomerge page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0 spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force ipv6.disable=1 apparmor=1 security=apparmor random.trust_cpu=off intel_iommu=on amd_iommu=on efi=disable_early_pci_dma"/' /etc/default/grub
    sudo update-grub
}

# Function to remove blacklisted kernel modules
remove_blacklist_modules() {
    echo
    print_bold "Removing Blacklisted Kernel Modules..."
    add_delay
    sudo sed -i '/^install dccp \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install sctp \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install rds \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install tipc \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install n-hdlc \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install ax25 \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install netrom \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install x25 \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install rose \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install decnet \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install econet \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install af_802154 \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install ipx \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install appletalk \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install psnap \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install p8023 \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install p8022 \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install can \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install atm \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install cramfs \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install freevxfs \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install jffs2 \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install hfs \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install hfsplus \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install squashfs \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install udf \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install cifs \/bin\/true/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install nfs \/bin\/true/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install nfsv3 \/bin\/true/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install nfsv4 \/bin\/true/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install ksmbd \/bin\/true/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install gfs2 \/bin\/true/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install vivid \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install bluetooth \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install btusb \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install uvcvideo \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install firewire-core \/bin\/false/d' /etc/modprobe.d/blacklist.conf
    sudo sed -i '/^install thunderbolt \/bin\/false/d' /etc/modprobe.d/blacklist.conf
}

# Function to remove AppArmor profiles and configuration
remove_apparmor() {
    echo
    print_bold "Removing AppArmor Profiles and Configuration..."
    add_delay
    sudo rm -rf /etc/apparmor.d
    sudo apt autoremove
}

# Function to remove USBGuard
remove_usbguard() {
    echo
    print_bold "Removing USBGuard..."
    add_delay
    sudo systemctl stop usbguard.service
    sudo systemctl disable usbguard.service
    sudo apt remove --purge usbguard
}

# Function to revert file permissions
revert_file_permissions() {
    echo
    print_bold "Reverting File Permissions..."
    add_delay
    sudo dpkg-statoverride --remove /usr/src
    sudo dpkg-statoverride --remove /lib/modules
    sudo dpkg-statoverride --remove /usr/lib/modules
    sudo dpkg-statoverride --remove /boot
}

# Function to revert secure mount options
revert_secure_mount_options() {
    echo
    echo
    print_bold "Reverting Secure Mount Options..."
    add_delay
    sudo sed -i '/^\/        \/          ext4    defaults/d' /etc/fstab
    #sudo sed -i '/^\/home    \/home      ext4    defaults,nosuid,nodev/d' /etc/fstab
    sudo sed -i '/^\/tmp     \/tmp       ext4    defaults,bind,nosuid,noexec,nodev/d' /etc/fstab
    sudo sed -i '/^\/var     \/var       ext4    defaults,bind,nosuid/d' /etc/fstab
    sudo sed -i '/^\/boot    \/boot      ext4    defaults,nosuid,nodev/d' /etc/fstab
}

# Function to revert rfkill configuration
revert_rfkill() {
    echo
    print_bold "Reverting rfkill Configuration..."
    add_delay
    # Uncomment to remove rfkill blocking if it was set
    # sudo rfkill unblock all
}

# Function to revert core dumps configuration
revert_core_dumps() {
    echo
    print_bold "Reverting Core Dumps Configuration..."
    add_delay
    sudo sed -i '/^kernel.core_pattern=|\/bin\/false/d' /etc/sysctl.d/99-sysctl.conf
    sudo sed -i '/^fs.suid_dumpable=0/d' /etc/sysctl.d/99-sysctl.conf
    sudo sed -i '/^vm.swappiness=1/d' /etc/sysctl.d/99-sysctl.conf
    sudo sysctl --system
}

# Function to revert core dumps configuration
revert_core_dumps() {
    echo
    print_bold "Reverting Core Dumps Configuration..."
    add_delay

    # Define parameters
    local params=(
        'kernel.core_pattern=|/bin/false'
        'fs.suid_dumpable=0'
        'vm.swappiness=1'
    )

    # Check and remove parameters from /etc/sysctl.conf
    for param in "${params[@]}"; do
        if grep -q "^$param" /etc/sysctl.conf; then
            echo "Removing $param from /etc/sysctl.conf"
            sudo sed -i "/^$param/d" /etc/sysctl.conf
        fi
    done

    # Check and remove parameters from /etc/sysctl.d/99-sysctl.conf
    for param in "${params[@]}"; do
        if grep -q "^$param" /etc/sysctl.d/99-sysctl.conf; then
            echo "Removing $param from /etc/sysctl.d/99-sysctl.conf"
            sudo sed -i "/^$param/d" /etc/sysctl.d/99-sysctl.conf
        fi
    done

    # Reload sysctl settings
    sudo sysctl --system
}



# Function to revert umask
revert_umask() {
    echo
    print_bold "Reverting umask Configuration..."
    add_delay
    sudo sed -i '/umask 0077/d' /etc/profile
    sudo sed -i '/umask 0077/d'/home/$user/.profile
    sudo sed -i '/umask 0077/d' /home/$user/.bashrc
    sudo sed -i '/UMASK=0077/d' /etc/defaults/login
    sudo sed -i '/soft core 0/d' /etc/security/limits.conf
    sudo sed -i '/hard core 0/d' /etc/security/limits.conf
}

# Function to allow root login via SSH
allow_root_ssh() {
    echo
    print_bold "Allowing Root Login via SSH..."
    add_delay
    sudo sed -i '/^PermitRootLogin/s/.*/PermitRootLogin yes/' /etc/ssh/ssh_config
    sudo systemctl restart sshd
}

# Function to add user back to adm group
add_user_adm_group() {
    echo
    print_bold "Adding User Back to 'adm' Group..."
    read -p "Enter username to add back to 'adm' group: " user
    add_delay
    sudo gpasswd -a $user adm
}

# Function to re-enable and start AppArmor
reinstall_apparmor() {
    print_bold "Reinstalling AppArmor..."
    add_delay
    sudo apt install apparmor
    sudo systemctl enable apparmor.service --now
    sudo systemctl start apparmor.service
}

# Function to re-enable and start USBGuard
reinstall_usbguard() {
    print_bold "Reinstalling USBGuard..."
    add_delay
    sudo apt install usbguard usbutils udisks2
    sudo systemctl enable usbguard.service --now
    sudo systemctl start usbguard.service
}

# Remove kernel hardening settings
remove_kernel_hardening

# Revert GRUB boot parameters
revert_grub_boot_parameters

# Remove blacklisted kernel modules
remove_blacklist_modules

# Remove AppArmor profiles and configuration
remove_apparmor

# Remove USBGuard
remove_usbguard

# Revert file permissions
revert_file_permissions

# Revert secure mount options
revert_secure_mount_options

# Revert rfkill configuration
revert_rfkill

# Revert core dumps configuration
revert_core_dumps

# Revert umask
revert_umask

# Allow root login via SSH
allow_root_ssh

# Add user back to 'adm' group
add_user_adm_group

# Reinstall AppArmor
#reinstall_apparmor

# Reinstall USBGuard
#reinstall_usbguard

# Function to remove a line matching a pattern from a file
remove_fstab_entry() {
    local entry="$1"
    local file="/etc/fstab"
    sudo sed -i "/$entry/d" "$file"
}

# Function to remove the APT seccomp-bpf configuration
remove_apt_seccomp() {
    echo
    print_bold "Removing APT seccomp-bpf configuration..."

    # Remove the /etc/apt/apt.conf.d/40sandbox file
    sudo rm -f /etc/apt/apt.conf.d/40sandbox

    print_bold "APT seccomp-bpf configuration removed successfully."
}

# Function to remove process visibility restrictions from /etc/fstab
remove_fstab_for_process_visibility() {
    echo
    echo
    print_bold "Removing process visibility restrictions from /etc/fstab..."

    # Define the entry to be removed
    #local fstab_entry="proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0"
    local fstab_entry="proc /proc proc defaults,nosuid,nodev,noexec,hidepid=2 0 0"
    local fstab_file="/etc/fstab"

    # Check if the entry exists and remove it
    if grep -qF "$fstab_entry" "$fstab_file"; then
        echo "Entry found in $fstab_file. Removing..."
        sudo sed -i "\|$fstab_entry|d" "$fstab_file"
        echo "Entry removed."
    else
        echo "Entry not found in $fstab_file."
    fi

    print_bold "Process visibility restrictions removed from /etc/fstab."
}


# Remove APT seccomp-bpf configuration
remove_apt_seccomp
add_delay

# Remove process visibility restrictions from /etc/fstab
remove_fstab_for_process_visibility
add_delay

# Function to clean Firejail configurations and uninstall Firejail
clean_firejail() {
    echo
    echo
    echo "Cleaning Firejail configurations..."
    sudo firecfg --clean
    echo

    echo "Removing Firejail package..."
    sudo apt-get remove --purge firejail
    echo
    add_delay

    echo
    echo "Removing unnecessary packages and cleaning up..."
    sudo apt-get autoremove
    #sudo apt-get clean
    echo

 echo "Firejail and its configurations have been successfully removed."
}

# Call the function
clean_firejail


print_bold "Uninstallation completed successfully."
