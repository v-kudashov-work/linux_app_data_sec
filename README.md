# app_data_sec — User Data Protection in Linux with eBPF

**app_data_sec** is a system for protecting user data from unauthorized access using eBPF (Extended Berkeley Packet Filter) and LSM (Linux Security Module) technology. The solution provides kernel-level access control to protected folders, blocking read, write, delete, and rename operations for processes not on the allowlist.

# Version 0.5.7

## Main Features

- 🔒 **Folder Protection** — blocks access to specified directories for all processes except allowed ones 
- 📋 **Compatibility** — Access blocking is in addition to standard Linux file access rules
- 📋 **Administration** — Root access is not restricted (UID=0)
- 📋 **Application Whitelist** — ability to specify programs allowed access for each protected folder individually
- 👤 **User Home Directory Support** — automatic application of rules to all users (`~/.folder`)
- 🔄 **Dynamic Reload** — automatic application of configuration changes without system restart
- 📊 **Detailed Logging** — records all access attempts with PID, path, inode, and process tree information
- 🛡️ **Watchdog** — monitors service status and notifies users of failures
- 🏃 **High Performance** — kernel-level operation with minimal overhead
- 👤 **For Developers** — automatic addition of configurations from other program developers

## Architecture
```code
┌────────────────────────────────────────────────────┐
│ User space                                         │
├────────────────────────────────────────────────────┤
│ app_data_sec_loader     │ app_data_sec_watchdog    │
│ (BPF management)        │ (service monitoring)     │
├─────────────────────────┼──────────────────────────┤
│ app_data_sec_merge      │ app_data_sec_unprotect   │
│ (merging configs)       │ (removing protection)    │
├─────────────────────────┼──────────────────────────┤
│ app_data_sec_messages   │ /etc/app_data_sec.conf   │
│ (logging in syslog   )  │ (configuration)          │
└─────────────────────────┴──────────────────────────┘

┌────────────────────────────────────────────────────┐
│ The Linux kernel (eBPF)                            │
├────────────────────────────────────────────────────┤
│ LSM hooks:                                         │
│ - inode_getattr - file_open                        │
│ - path_unlink - path_rmdir                         │
│ - path_mkdir - path_rename                         │
│ - inode_create - inode_mkdir                       │
├────────────────────────────────────────────────────┤
│ eBPF cards:                                        │
│ - folder_config_map - folder configuration         │
│ - folder_allowed_programs_map                      │
│    - permitted programs                            │
│ - log_level_map - logging level                    │
└────────────────────────────────────────────────────┘
```

## System Requirements

- **Linux Kernel**: version 5.8+ with BPF LSM and BTF (CO-RE) support
- **Architecture**: x86_64
- **Distributions**: ALT Linux, Ubuntu, Debian. May work but not tested: RHEL/CentOS. Does not work: Fedora.
- **Dependencies**: libbpf, libelf, zlib, clang, bpftool

## Quick Installation

```bash
# Cloning a repository
git clone https://gitlab.com/v.kudashov.work/linux_app_data_sec.git
cd linux_app_data_sec
```

# Start Installation
```bash
sudo ./install_app_data_sec.sh
```

The installer will automatically:

Check and install necessary dependencies

Compile the BPF program and all utilities

Configure systemd services

Create a configuration file

Offer to add configurations for applications

# Configuration
  The /configs/ folder contains configurations for some popular programs. You can import all with the command:
```bash
  sudo app_data_sec_merge_config ./configs/
```

or run the installation with the --with_defs flag for interactive configuration import mode:
```bash
  sudo install_app_data_sec.sh --with_defs
```

Configuration format:
    Configuration file: /etc/app_data_sec.conf

```text
# enable = yes|no — enables or disables protection
enable = yes

# Folder protection and a list of allowed programs
protect /home/user/.secret_folder /bin/konsole /usr/bin/bash
protect ~/.test_app /bin/my_app
```

    Protect directive format
    protect <path> [allowed_program1] [allowed_program2] ..

    <path> — absolute path to the folder to be protected or ~ for the home directory

    allowed_program — absolute path to the program that can bypass protection 
        (gains access to this folder if access is granted based on standard Linux folder access rules)

## scan_mount Directive

The `scan_mount` directive is designed for automatic detection of new folders when file systems are mounted.

### Syntax
```conf
scan_mount <path>
```

### Parameters

- **path** - the path to the folder whose appearance should be monitored. The use of `~` for the home directory is not supported - all paths must be absolute.

### How it Works

1. The service periodically checks for the existence of specified paths (every 0.5 seconds)
2. Upon detecting a path (e.g., after mounting a USB flash drive or network drive), a full scan is performed
3. As a result of the scan, all `protect` rules that match the found paths are applied

### Usage Examples

```conf
# Tracking external media
scan_mount /mnt/external
scan_mount /media/usb

# Network partition tracking
scan_mount /mnt/nfs/share

# Paths with spaces
scan_mount "/mnt/My Drive"
```

## Automatic Configuration for Other Program Developers (Auto-config)

If you are a developer, you can add automatic configuration for your application. 
Here's how to do it:

For automatic application of configurations during installation/update, the `/etc/app_data_sec.autoconfig/` directory is used.

All `.conf` files from this directory are automatically imported into the main configuration when `install_app_data_sec.sh` is launched, without requiring confirmation.

```code
# Creating an autoconfiguration
sudo mkdir -p /etc/app_data_sec.autoconfig/
sudo chown root:root /etc/app_data_sec.autoconfig/
sudo chmod 750 /etc/app_data_sec.autoconfig/
sudo cp my_config.conf /etc/app_data_sec.autoconfig/
```

In your script for sh or another program, you need to call
```code
sudo app_data_sec_merge_config --autoconfig
sudo app_data_sec_loader --rescan
```
after this, if they exist, for the configuration to be applied. If this is not done, the configuration will be applied within 15 minutes.

Example:
```code
if [ ! -d "$AUTOCONFIG_DIR" ]; then
    mkdir -p "$AUTOCONFIG_DIR"
    chown root:root "$AUTOCONFIG_DIR"
    chmod 750 "$AUTOCONFIG_DIR"
fi

# We check for merge_config and run if there is
if command -v app_data_sec_merge_config &> /dev/null; then
    # Run merge_config with the autoconfig directory (quietly, without unnecessary messages)
    app_data_sec_merge_config --autoconfig -y 2>/dev/null || true
    app_data_sec_loader --rescan # We are sending a command to scan the configuration and files
else
    # The utility was not found - just ignore it (not an error). The config will be applied when installing app_data_sec.
    echo -e "${YELLOW}[INFO]${NC} app_data_sec_merge_config not found, skipping autoconfig import"
fi
```

It is also advisable to wait 5 seconds in the installer for the configuration files to be applied.

# Start/Stop
```bash
sudo systemctl start app_data_sec_loader
sudo systemctl stop app_data_sec_loader
```

# View Logs
```bash
sudo journalctl -u app_data_sec_loader -f
sudo journalctl -u app_data_sec_watchdog -f
sudo journalctl -u app_data_sec_autoconfig -f
sudo journalctl -u app_data_sec_messages -f
```

# Force Configuration Reload and Scan (--rescan)

To force a configuration reload and scan of all protected folders and apply current rules, you can use the `--rescan` flag.

This mechanism allows you to:
- Apply configuration changes
- Apply file system changes without restarting the service
- Detect new folders created since the last scan
- Update file inodes after they are recreated
- Check for new programs in the whitelist

```bash
# Send a signal to re-scan
sudo app_data_sec_loader --rescan
```

## Additional Utilities
## Merging Configurations
# Merging a Single File
```bash
sudo app_data_sec_merge_config /tmp/new.conf
```

# Merging All .conf Files from a Directory
```bash
sudo app_data_sec_merge_config /etc/app_data_sec.d/
```

# Removing Protection
```bash
# Creating a file with a list to delete
echo "protect /home/user/.secret_folder" > /tmp/remove.conf
```

# Removal
```bash
sudo app_data_sec_unprotect /tmp/remove.conf
```

# Disabling
To disable the module, you can set 
    enable = no
in the configuration file /etc/app_data_sec.conf

# View all protected folders
```bash
sudo app_data_sec_unprotect -l
```

# Logging
Logging levels (the -l parameter when starting app_data_sec_loader):

0 — logging is disabled

1 — only blocked access attempts (default)

2 — all access attempts (allowed and blocked)

To view logs in syslog, use the app_data_sec_messages service
sudo journalctl -u app_data_sec_messages -f

To redirect the output of the eBpf module to the system log, you can run app_data_sec_messages_to_syslog as a superuser:
```bash
sudo app_data_sec_messages_to_syslog
```

or run in the console:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

# Watchdog
The watchdog (app_data_sec_watchdog) monitors the status of the main service. If it stops, the file app_data_sec_errors.txt is created on users' desktops with recovery instructions.

# Removal
sudo ./uninstall_app_data_sec.sh

# Security
    Kernel-level operation — protection against user-level bypass

    Process tree verification — blocking access through parent processes

    Root support — root access is not restricted (UID=0)

    Tampering protection — using inode for file identification

# Limitations
    After installing an application that is involved in configuring a folder for protection, you may need to wait 15 seconds before launching the application. This time is necessary for the module data to update.
    Python and sh script programs are not supported. They can be used if launched within a parent process of a regular executable file and access to it is configured.
For the eBPF module
```text
    #define MAX_PROTECTED_PATHS 5000   - maximum number of protected folders
    #define MAX_ALLOWED_PROGRAMS 20  - how many executable files are possible for each folder from MAX_PROTECTED_PATHS
    #define MAX_DEPTH_FOR_APP 8 - maximum nesting level of executable file paths
    #define MAX_DEPTH_FOR_PATH 64 - maximum nesting level of protected folder paths
    #define MAX_NAME_LEN_FOR_LOG 10 - for logging only, the maximum length of the file name
    #define MAX_LOG_PATH_LEN 128 - the maximum length of the path for logging the command to run the executable file
    #define MAX_DEPTH_FOR_APP_LOG 4 - maximum nesting for process nesting logging
```

For the loader
```text
    #define MAX_LINE_LEN 1024 - maximum line length in the configuration file
    #define MAX_PATHS 5000  - maximum number of protected folders
    #define MAX_ALLOWED 20 - how many executable files are possible for each folder from MAX_PROTECTED_PATHS
    #define MAX_PATH_LEN 256 - maximum length of the path to a file or folder
    #define CHECK_INTERVAL 5 - the period of checking the config for changes
    #define RETRY_INTERVAL 15 - the period for checking files for availability or deletion
    #define MAX_SCAN_MOUNT_PATHS 500 - maximum number of paths for scan_mount
    #define MAX_HOME_USERS 1000 - maximum number of folders in the /home/ folder (number of users)
```

# Status
    Alpha version. Written using automatic code generation tools (AI) and subsequent refactoring. There may be errors; the main focus is on the eBpf module itself and its loader.

# License
    GNU General Public License v2.0

# Author
    Vladimir Kudashov, 2026

# Contacts
If you have a question, please [send me an email](mailto:v.kudashov.83@yandex.ru).

# Links
    GitLab repository: https://gitlab.com/v.kudashov.work/linux_app_data_sec
    GitHub repository: https://github.com/v-kudashov-work/linux_app_data_sec