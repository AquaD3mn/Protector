# 🛡️ DOCUMENTATION - Protector

## **Introduction**
**Protector** is a Bash script designed to enhance security on Linux-based systems such as Ubuntu, Kali Linux, and Parrot OS. Although still in development, this tool consolidates various security implementations practiced by experienced cybersecurity professionals. Please review the script carefully before integrating it into your system, as it has been tested in ideal environments, and issues may arise.

---

## **Contents**
1. [Spoof MAC Address](#spoof-mac-address)
2. [Prompt for Avahi Action](#prompt-for-avahi-action)
3. [Prompt for CUPS Action](#prompt-for-cups-action)
4. [UFW (Uncomplicated Firewall) Configuration](#ufw-uncomplicated-firewall-configuration)
5. [Defend Against Physical Attacks](#defend-against-physical-attacks)
6. [Kernel Hardening](#kernel-hardening)
7. [Update GRUB with Boot Parameters](#update-grub-with-boot-parameters)
8. [Blacklist Kernel Modules](#blacklist-kernel-modules)
9. [Configure File Permissions](#configure-file-permissions)
10. [Deny Root Login via SSH](#deny-root-login-via-ssh)
11. [Remove User from 'adm' Group](#remove-user-from-adm-group)
12. [Set Umask](#set-umask)
13. [Configure Kernel Pointer Leaks](#configure-kernel-pointer-leaks)
14. [Configure Rfkill (Commented Out)](#configure-rfkill-commented-out)
15. [Configuring Kernel Pointer Leaks](#configuring-kernel-pointer-leaks)
16. [Allotting File Permissions](#allotting-file-permissions)
17. [Denying Root Login via SSH](#denying-root-login-via-ssh)
18. [Removing User from 'adm' Group to Restrict Access to Kernel Logs](#removing-user-from-adm-group-to-restrict-access-to-kernel-logs)
19. [Setting Umask to Restrict File Permissions](#setting-umask-to-restrict-file-permissions)
20. [Disabling Core Dumps](#disabling-core-dumps)
21. [Configuring Secure Mount Options in /etc/fstab](#configuring-secure-mount-options-in-etcfstab)
22. [Configure AppArmor Profiles](#configure-apparmor-profiles)
23. [Configure APT seccomp-bpf](#configure-apt-seccomp-bpf)
24. [Secure Proc Filesystem Mount Options](#secure-proc-filesystem-mount-options)
25. [Prompt User for Removing PulseAudio](#prompt-user-for-removing-pulseaudio)
26. [Check and Remove Snapd](#check-and-remove-snapd)
27. [Analyze Security](#analyze-security)
28. [Manage Running Services](#manage-running-services)
29. [Firejail Installation and Configuration](#firejail-installation-and-configuration)

---

## **1. Spoof MAC Address**
**Description**: Instructs the user to manually configure MAC address spoofing via Network Manager.

**Security Measures**:
- **MAC Address Spoofing**: Protects user identity and prevents tracking based on hardware addresses.
- **Manual Instructions**: Ensures users understand how to apply this security measure.

---

## **2. Prompt for Avahi Action**
**Description**: Prompts the user to choose whether to disable or remove Avahi, a service for mDNS/DNS-SD.

**Security Measures**:
- **Disabling/Removing Avahi**: Reduces the attack surface by preventing unnecessary network services.
- **User Choice**: Tailors to the user's security needs.

---

## **3. Prompt for CUPS Action**
**Description**: Prompts the user to decide whether to disable or remove CUPS (Common Unix Printing System).

**Security Measures**:
- **Disabling/Removing CUPS**: Prevents unauthorized access to printer services.
- **User Choice**: Aligns with the principle of least privilege.

---

## **4. UFW (Uncomplicated Firewall) Configuration**
**Description**: Configures UFW to secure the system by defining and enforcing network traffic rules.

---

## **5. Defend Against Physical Attacks**
**Description**: Provides instructions for configuring BIOS/UEFI settings.

**Security Measures**:
- **Secure Boot**: Ensures only trusted software loads during boot.
- **Supervisor Password**: Prevents unauthorized changes to firmware settings.

---

## **6. Kernel Hardening**
**Description**: Configures kernel parameters and system settings for enhanced security.

**Security Measures**:
- Updates kernel parameters to mitigate vulnerabilities.

**Importance**:
- `kernel.kptr_restrict=2`: Restricts access to kernel pointers, reducing information leakage.
- `kernel.dmesg_restrict=1`: Limits access to kernel logs, mitigating potential information exposure.
- `kernel.printk=3 3 3 3`: Controls verbosity of kernel messages, minimizing exposure of sensitive information.
- `net.ipv4.tcp_syncookies=1`: Protects against SYN flood attacks by enabling TCP syncookies.
- `net.ipv4.icmp_echo_ignore_all=1`: Prevents system from responding to ICMP echo requests, reducing attack surface.
- `fs.protected_symlinks=1`: Protects symbolic links from exploitation.
- `vm.mmap_rnd_bits=32`: Randomizes memory mappings to make memory corruption attacks harder.

---

## **7. Update GRUB with Boot Parameters**
**Purpose**: Updates GRUB configuration to include kernel boot parameters that enhance system security.

**Importance**:
- `slab_nomerge`: Disables slab cache merging to avoid certain memory attacks.
- `page_alloc.shuffle=1`: Randomizes memory allocations to prevent exploitation.
- `pti=on`: Enables Page Table Isolation to protect against Spectre variant 2 attacks.
- `randomize_kstack_offset=on`: Randomizes kernel stack offset to complicate stack-based attacks.
- `module.sig_enforce=1`: Enforces module signature verification to prevent unauthorized kernel modules.

---

## **8. Blacklist Kernel Modules**
**Purpose**: Blacklists unnecessary or potentially insecure kernel modules.

**Importance**: Prevents loading of non-essential modules, reducing attack surface and security risks.

---

## **9. Configure File Permissions**
**Purpose**: Sets restrictive file permissions on critical system directories.

**Importance**: Restricts access to sensitive directories to only the root user, reducing unauthorized access risks.

---

## **10. Deny Root Login via SSH**
**Purpose**: Disables root login via SSH to enhance security.

**Importance**: Prevents direct root access over SSH, reducing risk of unauthorized access and brute force attacks.

---

## **11. Remove User from 'adm' Group**
**Purpose**: Removes a specified user from the adm group to limit access to system logs.

**Importance**: Reduces risk of unauthorized access to kernel logs and system information.

---

## **12. Set Umask**
**Purpose**: Configures the default file creation mask to restrict permissions on newly created files.

**Importance**: Ensures new files are created with restrictive permissions, reducing exposure of sensitive data.

---

## **13. Configure Kernel Pointer Leaks**
**Purpose**: Restricts access to specific directories to mitigate kernel pointer leaks.

**Importance**: Ensures sensitive directories are accessible only by root, reducing unauthorized access risks.

---

## **14. Configure Rfkill (Commented Out)**
**Purpose**: Placeholder for configuring rfkill to manage wireless devices.

**Importance**: Could prevent unauthorized use of wireless interfaces.

---

## **15. Configuring Kernel Pointer Leaks**
**Description**: Mitigates kernel pointer leaks, exposing sensitive kernel memory information.

**Security Measures**:
- **File Permissions for User Home Directory**: Restricts access to the user’s home directory.
- **File Permissions for Critical System Directories**: Ensures only root has access to critical directories.

---

## **16. Allotting File Permissions**
**Description**: Sets strict file permissions for specific system directories.

**Security Measures**:
- **File Permissions Configuration**: Uses `dpkg-statoverride` to enforce permissions.
- **Listing Current Rules**: Command to list current `dpkg-statoverride` rules.

---

## **17. Denying Root Login via SSH**
**Description**: Disabling root login over SSH improves security.

**Security Measures**:
- **Configuration Change**: Updates SSH configuration to deny root logins.

---

## **18. Removing User from 'adm' Group to Restrict Access to Kernel Logs**
**Description**: Limits user access to kernel logs.

**Security Measures**:
- **Group Removal**: Prompts for a username and removes them from the adm group.

---

## **19. Setting Umask to Restrict File Permissions**
**Description**: Configures a restrictive umask value for new files.

**Security Measures**:
- **Umask Configuration**: Appends umask value 0077 to `/etc/profile`.

---

## **20. Disabling Core Dumps**
**Description**: Prevents creation of core dump files.

**Security Measures**:
- **Core Dump Settings**: Configures the system to ignore core dump files.

---

## **21. Configuring Secure Mount Options in /etc/fstab**
**Description**: Updates mount options in `/etc/fstab` for security.

**Security Measures**:
- **Mount Options Configuration**: Adds secure mount options for filesystems.

---

## **22. Configure AppArmor Profiles**
**Description**:**Description**: Backing up existing AppArmor profiles ensures that configurations can be restored if needed. Configuring and enforcing AppArmor profiles enhances system security by enforcing mandatory access control policies.

**Security Measures**:
- **Backup Procedure**: Creates a backup of AppArmor profiles for recovery in case of misconfiguration.
- **Configure AppArmor**: Installs and configures AppArmor profiles from a repository, ensuring applications are restricted by the least privilege principle. Reloads and enforces profiles to ensure they are active.
- **AppArmor Status Check**: Checks the status of AppArmor profiles to verify they are properly enforced and operational.

---

## **23. Configure APT seccomp-bpf**
**Description**: Configures APT (Advanced Package Tool) to use seccomp-bpf, providing an additional layer of security by restricting system calls.

**Security Measures**:
- **APT Seccomp-BPF Configuration**: Adds the `APT::Sandbox::Seccomp "true";` directive to the `/etc/apt/apt.conf.d/40sandbox` file, enabling the seccomp-bpf sandbox for APT.

---

## **24. Secure Proc Filesystem Mount Options**
**Description**: Updates `/etc/fstab` to configure secure mount options for the proc filesystem.

**Security Measures**:
- **Mount Options Configuration**: Adds the entry `proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0` to `/etc/fstab` to hide process information from non-root users and restricts setuid programs.

---

## **25. Prompt User for Removing PulseAudio**
**Description**: Prompts the user to decide whether to remove PulseAudio, a sound server, which may be considered a security risk.

**Security Measures**:
- **PulseAudio Removal**: If confirmed, removes PulseAudio using `apt-get remove --purge`, which also deletes configuration files.

---

## **26. Check and Remove Snapd**
**Description**: Checks if Snapd (a package management system for snap packages) is installed and prompts the user to remove it if desired.

**Security Measures**:
- **Snapd Removal**: If Snapd is installed, prompts the user to remove it using `apt purge snapd` and blocks future installations with `apt-mark hold snapd`.

---

## **27. Analyze Security**
**Description**: Analyzes the security status of systemd services using `systemd-analyze security`.

**Security Measures**:
- **Security Analysis**: Displays output categorizing services into levels such as OK, MEDIUM, EXPOSED, and UNSAFE to identify potential security issues.

---

## **28. Manage Running Services**
**Description**: Lists all active systemd services and allows the user to stop and disable unwanted services.

**Security Measures**:
- **Service Management**: Users can stop and disable unnecessary services to reduce potential attack vectors.

---

## **29. Firejail Installation and Configuration**
**Description**: Adds a Personal Package Archive (PPA) for Firejail, a security tool that implements Linux namespaces and seccomp-bpf.

**Security Measures**:
- **Firejail Installation**: Adds the Firejail PPA and installs the Firejail package along with its profiles.
- **Configure Firejail**: Sets up default profiles for installed applications, improving application security by isolating them within restricted environments.
- **Verify Firejail Installation**: Checks the installed version of Firejail to confirm successful installation and configuration.
