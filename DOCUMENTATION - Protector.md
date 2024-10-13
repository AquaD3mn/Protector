# DOCUMENTATION - Protector

**Introduction**
'Protector' is a Bash script which is developed as a tool to improve the security in Linux based systems such as Ubuntu, Kali Linux, Parrot OS, etc.
It is a still an In-development project but i see huge improvements that can be made with the use of this tool. I have practically put together many of the security implementations that is being practised by experienced Individuals in Cyber Security and whom are far advanced as compared to me.
Kindly go through the script before setting up the different implementations into your system. I have tested this in Ideal systems so there might be chance for issues to occur, so be beware of that.

**Content**
1. Spoof MAC Address
Description: Instructs the user to manually configure MAC address spoofing via Network Manager.

Security Measures:
    MAC Address Spoofing: Changing the MAC address helps in protecting user identity and preventing tracking based on hardware addresses. It is particularly useful in environments where users might want to obscure their device’s network presence.

    Manual Instructions: Clear instructions ensure that users understand how to apply this security measure, reducing the risk of improper configuration

2. Prompt for Avahi Action
Description: Prompts the user to choose whether to disable or remove Avahi, a service that provides mDNS/DNS-SD (multicast DNS service discovery).

Security Measures:
    Disabling or Removing Avahi: Avahi can expose the system to network-based attacks such as unwanted service discovery. Disabling or removing it reduces the attack surface by preventing unnecessary network services.
    
    User Choice: Provides flexibility for the user to either disable or fully remove the service, which can be tailored to the user's security needs

3. Prompt for CUPS Action
Description: Prompts the user to decide whether to disable or remove CUPS (Common Unix Printing System), which manages printing tasks.

Security Measures:
    Disabling or Removing CUPS: CUPS can pose security risks if it is not needed, such as unauthorized access to printer services. Disabling or removing it prevents potential exploitation of this service.
    
    User Choice: Allows users to make decisions based on whether printing services are necessary, thus aligning with the principle of least privilege.

4. UFW (Uncomplicated Firewall) Configuration
Description: The script configures UFW, a straightforward firewall management tool, to secure the system by defining and enforcing network traffic rules. The configuration steps include checking for UFW installation, enabling it, setting default rules, allowing specific ports, and reviewing the firewall status.

5. Defend Against Physical Attacks
Description: Provides instructions for configuring BIOS/UEFI settings to protect against physical attacks.

Security Measures:
    Secure Boot: Ensures that only trusted software can be loaded during the system boot process, preventing unauthorized firmware or bootloader modifications.

    Supervisor Password: Adding a BIOS/UEFI password helps prevent unauthorized changes to system firmware settings, further protecting against physical tampering.

6. Kernel Hardening
Description: Kernel hardening involves configuring various kernel parameters and system settings to enhance the security of the operating system. This script covers updating kernel parameters, blacklisting unnecessary kernel modules, configuring file permissions, and adjusting system settings to mitigate potential vulnerabilities.

Security Measures:
Purpose: Updates kernel parameters to enhance security by configuring various settings in /etc/sysctl.conf or /etc/sysctl.d/*.conf.

Importance:
    kernel.kptr_restrict=2: Restricts access to kernel pointers, reducing information leakage.
    kernel.dmesg_restrict=1: Limits access to kernel logs, mitigating potential information exposure.
    kernel.printk=3 3 3 3: Controls the verbosity of kernel messages, minimizing potential exposure of sensitive information.
    net.ipv4.tcp_syncookies=1: Helps protect against SYN flood attacks by enabling TCP syncookies.
    net.ipv4.icmp_echo_ignore_all=1: Prevents the system from responding to ICMP echo requests (pings), reducing the attack surface.
    fs.protected_symlinks=1: Protects symbolic links from being exploited.
    vm.mmap_rnd_bits=32: Randomizes memory mappings to make memory corruption attacks harder.

7. Update GRUB with Boot Parameters
Purpose: Updates GRUB configuration to include kernel boot parameters that enhance system security.

Importance:
    slab_nomerge: Disables slab cache merging to avoid certain memory attacks.
    page_alloc.shuffle=1: Randomizes the order of memory allocations to prevent exploitation of memory layout.
    pti=on: Enables Page Table Isolation to protect against Spectre variant 2 attacks.
    randomize_kstack_offset=on: Randomizes the kernel stack offset to make stack-based attacks more difficult.
    module.sig_enforce=1: Enforces module signature verification to prevent unauthorized kernel modules.

8. Blacklist Kernel Modules
Purpose: Blacklists unnecessary or potentially insecure kernel modules.

Importance: Prevents the loading of modules that are not required, reducing the attack surface and potential security risks. Modules related to obsolete or rarely used functionalities are disabled, while necessary ones (e.g., cifs, nfs) are allowed.

9. Configure File Permissions
Purpose: Sets restrictive file permissions on critical system directories.

Importance: Restricts access to sensitive directories to only the root user, thereby reducing the risk of unauthorized access or modification of kernel and system files.

10. Deny Root Login via SSH
Purpose: Disables root login via SSH to enhance security.

Importance: Prevents direct root access over SSH, reducing the risk of unauthorized access and brute force attacks. Ensures that administrative access is only possible through other users with sudo privileges.

11. Remove User from 'adm' Group
Purpose: Removes a specified user from the adm group to limit access to system logs.

Importance: Reduces the risk of unauthorized access to kernel logs and system information, which can be valuable for attackers looking to exploit system vulnerabilities.

12. Set Umask
Purpose: Configures the default file creation mask to restrict permissions on newly created files.

Importance: Ensures that new files are created with restrictive permissions, reducing the risk of unintentional exposure of sensitive data.

13. Configure Kernel Pointer Leaks
Purpose: Restricts access to specific directories to mitigate kernel pointer leaks.

Importance: Ensures that sensitive directories related to kernel and system files are only accessible by root, reducing the risk of unauthorized access and information leakage.

14. Configure Rfkill (Commented Out)
Purpose: Placeholder for configuring rfkill to manage wireless devices.

Importance: Rfkill configuration could prevent unauthorized use of wireless interfaces, though it's currently commented out.

15. Configuring Kernel Pointer Leaks
Description:
This section aims to mitigate kernel pointer leaks, which can expose sensitive information about kernel memory to unauthorized users. This is crucial for enhancing system security and privacy.

Security Measures:
    File Permissions for User Home Directory: Restricts access to the user’s home directory to the owner only. This prevents other users from reading or modifying files in the user’s home directory, thereby reducing the risk of exposure of sensitive information.

    File Permissions for Critical System Directories: Ensures that only the root user has access to critical system directories like /boot, /usr/src, /lib/modules, and /usr/lib/modules. This prevents unauthorized access or tampering with system files and kernel modules.

16. Allotting File Permissions
Description:
This section sets strict file permissions for specific system directories to enhance security. The permissions are set to 700, meaning only the root user has full access.

Security Measures:
    File Permissions Configuration: Uses dpkg-statoverride to enforce permissions for directories related to system source files, kernel modules, and boot files. This helps in preventing unauthorized access or modifications to these critical files.

    Listing Current Rules: Provides a command to list the current dpkg-statoverride rules, enabling administrators to review and verify the applied permissions.

17. Denying Root Login via SSH
Description:
Disabling root login over SSH improves security by preventing attackers from directly attempting to gain root access.

Security Measures:
    Configuration Change: Updates the SSH configuration to deny root logins and restarts the SSH service. This restricts potential attackers from exploiting SSH vulnerabilities to gain root access.

18. Removing User from 'adm' Group to Restrict Access to Kernel Logs
Description: Removing a user from the adm group limits their access to kernel logs, which can contain sensitive information.

Security Measures:
    Group Removal: Prompts for a username and removes that user from the adm group. This prevents them from accessing kernel logs and related system information.

19. Setting umask to Restrict File Permissions
Description:
Setting a restrictive umask value ensures that new files and directories are created with secure default permissions.

Security Measures:
    Umask Configuration: Appends the umask value 0077 to /etc/profile, setting default permissions for newly created files to be accessible only by the owner. This enhances security by ensuring new files are not readable or writable by other users.

20. Disabling Core Dumps
Description:
Disabling core dumps prevents the creation of core dump files, which can contain sensitive information about the running process.

Security Measures:
    Core Dump Settings: Configures the system to ignore core dump files by setting kernel.core_pattern to /bin/false, and fs.suid_dumpable to 0. This prevents potentially sensitive information from being written to disk in case of application crashes.

21. Configuring Secure Mount Options in /etc/fstab
Description: Updating mount options in /etc/fstab improves system security by enforcing secure mount options.

Security Measures:
    Mount Options Configuration: Adds secure mount options to /etc/fstab for various filesystems, including disabling setuid, executable permissions, and device access. This minimizes security risks associated with writable and executable files in critical directories.

22. Configure AppArmor Profiles
Description:
Backing up existing AppArmor profiles ensures that configurations can be restored if needed. Configuring and enforcing AppArmor profiles enhances system security by enforcing mandatory access control policies.

Security Measures:
    Backup Procedure: Creates a backup of AppArmor profiles, allowing recovery in case of misconfiguration or other issues during profile updates.
    
    Configure AppArmor: Configuring and enforcing AppArmor profiles enhances system security by enforcing mandatory access control policies. Installs and configures AppArmor profiles from a repository, ensuring that applications are restricted by the least privilege principle. Reloads and enforces profiles to ensure they are active.
    
    AppArmor Status Check: Checks the status of AppArmor profiles to verify that they are properly enforced and operational.

23. Configure APT seccomp-bpf
Description:
This section configures APT (Advanced Package Tool) to use seccomp-bpf (Secure Computing with Berkeley Packet Filter), which provides an additional layer of security by restricting the system calls that APT can make.

Security Measures:
    APT Seccomp-BPF Configuration: Adds the APT::Sandbox::Seccomp "true"; directive to the /etc/apt/apt.conf.d/40sandbox file. This configuration enables the seccomp-bpf sandbox for APT, reducing the potential attack surface by limiting the system calls APT can perform.
    
24. Secure Proc Filesystem Mount Options
Description: This section updates the /etc/fstab file to configure secure mount options for the proc filesystem. This configuration helps in restricting process visibility and enhancing security.

Security Measures:
    Mount Options Configuration: Adds the entry proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0 to /etc/fstab if it does not already exist. This configuration hides process information from non-root users (hidepid=2), and restricts the use of setuid programs, device nodes, and executable files within the proc filesystem. This helps to prevent users from viewing the processes of other users and enhances overall system security.

25. Prompt User for Removing PulseAudio
Description:
This section prompts the user to decide whether to remove PulseAudio, a sound server, which may be considered a security risk or an unnecessary component in certain environments.

Security Measures:
    PulseAudio Removal: Prompts the user to remove PulseAudio. If confirmed, PulseAudio is removed using apt-get remove --purge, which also deletes configuration files. Removing unnecessary software reduces the attack surface.

26. Check and Remove Snapd
Description: This section checks if Snapd (a package management system for snap packages) is installed and prompts the user to remove it if desired.

Security Measures:
    Snapd Removal: Checks if Snapd is installed and, if so, prompts the user to remove it. Removal is done using apt purge snapd, and further blocking installation with apt-mark hold snapd prevents future installations. This helps in managing the software and reducing potential security vulnerabilities associated with Snap packages.
    
27. Analyze Security
Description: This section analyzes the security status of systemd services using systemd-analyze security and provides guidance based on the results.

Security Measures:
    Security Analysis: Runs a security analysis on systemd services and displays the output. It categorizes services into levels such as OK, MEDIUM, EXPOSED, and UNSAFE, which helps in identifying and addressing potential security issues.
    
28. Manage Running Services
Description: This section lists all active systemd services and allows the user to stop and disable unwanted services.

Security Measures:
    Service Management: Allows the user to manage running services by stopping and disabling them. This helps in reducing potential attack vectors by disabling unnecessary services.
    
29. Firejail Installation and Configuration
Description: This section adds a Personal Package Archive (PPA) for Firejail, a security tool that implements Linux namespaces and seccomp-bpf to restrict the runtime environment of applications.

Security Measures:
    Firejail Installation: Adds the Firejail PPA and installs the Firejail package along with its profiles. Firejail helps in sandboxing applications to reduce their access to system resources, enhancing security.
    
    Configure Firejail: This section configures Firejail by creating and applying the default profiles for various applications Configures Firejail by setting up default profiles for installed applications. This improves application security by isolating them within restricted environments.
    
    Verify Firejail Installation: This section verifies that Firejail has been installed correctly and is operational. Checks the installed version of Firejail to confirm successful installation and configuration.