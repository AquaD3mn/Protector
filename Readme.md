# 𝑷𝒓𝒐𝒕𝒆𝒄𝒕𝒐𝒓
### _Enhance Your Linux OS Security_

![OS Hardening](https://github.com/AquaD3mn/Protector/blob/main/Os%20hardening.jpeg)

[![Build Status](https://travis-ci.org/your-repo/os-hardening-script.svg?branch=master)](https://github.com/AquaD3mn/Protector/blob/main)

This script is designed to enhance the security of a Linux operating system by applying various hardening techniques.

-  Run the script as root
-  Secure your server effortlessly
- 🔒 Fortify your Linux environment 🔒

## Features

- Spoof MAC Address
- Prompt for Avahi Action
- Prompt for CUPS Action
- Configure UFW (Uncomplicated Firewall) with ease
- Defend Against Physical Attacks
- Kernel Hardening
- Update GRUB with Boot Parameters
- Blacklist Kernel Modules
- Configure File Permissions
- Prevent root login via SSH
- Remove User from 'adm' Group
- Set Umask to Restrict File Permissions
- Configure Kernel Pointer Leaks
- Configure Rfkill (Commented Out)
- Allotting File Permissions
- Secure mount options for sensitive directories
- Install and configure AppArmor for application security
- Configure APT seccomp-bpf
- Prompt User for Removing PulseAudio
- Check and Remove Snapd
- Analyze Service Security
- Manage Running Services
- Firejail Installation and Configuration
- Install and Configure USBGuard
- Install and Configure AIDE (Optional)
- Data at Rest Encryption in MySQL (Manual Setup Required) 

## Instructions
- Run the script as root.
- Carefully Analyse the script and only then execute.
- Chance of over restrictions are a possibility, be aware.
- According to the various OS distributions the configuration might change.
- Don't just automate the script try to learn the effects of hardening.

## Installation

To install the OS hardening script, follow these steps:

```bash
git clone https://github.com/AquaD3mn/Protector.git
cd Protector
chmod +x protector.sh
sudo ./protector.sh
```

## Uninstall

To remove the effects of OS hardening script, follow these steps:
```bash
cd Protector
chmod +x uninstall.sh
sudo ./uninstall.sh
```

> Note: In case of any hardening still remaining try to manually inspect/change in accordance with the script provided.


## Conclusion
This script applies essential hardening techniques to secure a Linux OS. Ensure to review the configurations and adjust them according to your environment. The tool [Lynis](https://cisofy.com/lynis/) can be used to check the overall security of your security. Hoping this would be helpful in your research and implementation.
## References

- [Madaidan's Insecurities: Linux Hardening Guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html) - A comprehensive guide on Linux hardening techniques.
- [UFW Documentation](https://wiki.ubuntu.com/UncomplicatedFirewall) - Official documentation for UFW, a user-friendly firewall.
- [AppArmor Documentation](https://wiki.ubuntu.com/AppArmor) - Official documentation for AppArmor, a security module for the Linux kernel.
- [MySQL Encryption at Rest: Part 2 - InnoDB](https://www.percona.com/blog/mysql-encryption-rest-part-2-innodb/) - A blog post on MySQL encryption at rest.
- [InnoDB Data Encryption](https://dev.mysql.com/doc/refman/8.4/en/innodb-data-encryption.html/) - Official MySQL documentation on InnoDB data encryption.
- [How to Install and Configure AIDE on Ubuntu Linux](https://www.rapid7.com/blog/post/2017/06/30/how-to-install-and-configure-aide-on-ubuntu-linux/) - A tutorial on installing and configuring AIDE on Ubuntu Linux.
- [How to Protect Your Linux Computer from Rogue USB Drives](https://www.howtogeek.com/864896/how-to-protect-your-linux-computer-from-rogue-usb-drives/) - An article on protecting Linux computers from rogue USB drives.
- [AppArmor Cheat Sheet for Linux System Administrators](https://computingforgeeks.com/apparmor-cheat-sheet-for-linux-system-administrators/) - A cheat sheet for AppArmor.
- [How to Setup a Firewall with UFW on Ubuntu 20.04](https://linuxize.com/post/how-to-setup-a-firewall-with-ufw-on-ubuntu-20-04/#ufw-default-policies) - A tutorial on setting up a firewall with UFW on Ubuntu 20.04.
- [Configuring UFW](https://pimylifeup.com/configuring-ufw/) - A tutorial on configuring UFW.
- [Locking Down Linux: Network Attack Defense](https://null-byte.wonderhowto.com/how-to/locking-down-linux-using-ubuntu-as-your-primary-os-part-2-network-attack-defense-0185709/) - An article on locking down Linux for network attack defense.
- [Locking Down Linux: Application Hardening and Sandboxing](https://null-byte.wonderhowto.com/how-to/locking-down-linux-using-ubuntu-as-your-primary-os-part-3-application-hardening-sandboxing-0185710/) - An article on locking down Linux for application hardening and sandboxing.
- And more

## License

MIT License

**Free Software, Secure Your Systems!**