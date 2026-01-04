![_](logo.png)
#### ✉️ umail: Secure Micro SMTP Client

A lightweight, dependency-free SMTP client written in C. Designed for minimal Linux servers, embedded systems, and secure environments where installing full MTAs (like Postfix or Sendmail) is not possible.

##### Key Features
- **Single binary:** No external dependencies (except libssl).
- **Secure:** Supports both **SMTPS** (Implicit SSL, port 465) and **STARTTLS** (port 587).
- **Reliable:** Built-in network timeouts (15s) prevent hanging processes in cron jobs.
- **Attachments:** Support for sending files (MIME Multipart) alongside text/HTML bodies.
- **Debug Friendly:** Detailed verbose mode (`-v`) to trace SMTP conversations and SSL handshakes.
- **Memory Safe:** Passwords are scrubbed from memory immediately after use.
- **Stealthy:** Supports reading credentials from protected files or environment variables.

##### Build
```sh
git clone https://github.com/psqlmaster/umail.git && cd umail && \
gcc -Os -o umail umail.c -lssl -lcrypto && strip umail && ./umail -h
```

##### Quick Start

**1. Setup credentials**

You have two options: a secure file (recommended for cron/scripts) or an environment variable.

*Option A: Secure File (Recommended)*
```sh
mkdir -p /var/tmp/.umail/ && \
echo "your_password_app" > /var/tmp/.umail/.umail && \
chmod 600 /var/tmp/.umail/.umail
```

*Option B: Environment Variable*
```sh
export SMTP_PASS="your_password_app"
```

**2. Send message from pipe (SMTPS / 465)**
Execute a command and send its output directly to email.

```sh
lsblk -f | ./umail \
  --server smtp.gmail.com \
  --user from_address@gmail.com \
  --to to_address@gmail.com \
  --secret /var/tmp/.umail/.umail \
  --subject "Secure Run" \
  --mono \
  --verbose
```

**3. Send file with attachment**
Send a specific file using the `SMTP_PASS` variable.

```sh
export SMTP_PASS="secret_password"
./umail \
  -s smtp.gmail.com \
  -u from@gmail.com \
  -t to@corp.com \
  -S "Daily Log" \
  -b "Please check the attached log file." \
  -a "/var/log/syslog"
```

**4. Use STARTTLS (Port 587)**
Example for Microsoft Exchange / Office365 or legacy Postfix servers.
*Note: The program automatically detects port 587 and switches protocol.*

```sh
./umail \
  --server smtp.office365.com \
  --port 587 \
  --user me@corp.com \
  --to boss@corp.com \
  --subject "Report" \
  --secret /path/to/pass
```

##### Options

```text
Usage: ./umail [OPTIONS]

  -s, --server <host>    SMTP server address (e.g., smtp.gmail.com)
  -P, --port <port>      SMTP port (465 for Implicit SSL, 587 for STARTTLS)
  -u, --user <email>     User email / Login (FROM)
  -t, --to <email>       Recipient email (TO)
  -S, --subject <text>   Email subject
  -b, --body <text>      Email body. If omitted, reads from STDIN.
  -a, --attach <file>    File attachment path
  -p, --secret <file>    Path to file containing password
  -M, --mono             Send as HTML Monospace (great for logs/tables)
  -v, --verbose          Enable verbose debug output
  -h, --help             Show help message

Environment Variables:
  SMTP_PASS              Password or App Password (used if -p is omitted)
```

##### Example send mail: "Full Server Report"

```sh
(
  echo "=== SERVER UPTIME ==="
  uptime
  echo ""
  echo "=== DISK USAGE ==="
  df -h
  echo ""
  echo "=== MEMORY ==="
  free -h
) | ./umail \
  --server smtp.gmail.com \
  --user from_address@gmail.com \
  --to to_address@gmail.com \
  --secret /var/tmp/.umail/.umail \
  --subject "Full Server Report" \
  --mono
```  

***mail body***
```text
=== SERVER UPTIME ===
 21:42:00 up  8:59,  1 user,  load average: 3.92, 3.75, 3.74

=== DISK USAGE ===
Filesystem      Size  Used Avail Use% Mounted on
udev             16G     0   16G   0% /dev
tmpfs           3.2G  1.9M  3.2G   1% /run
efivarfs        128K   64K   60K  52% /sys/firmware/efi/efivars
/dev/md0        193G  107G   77G  59% /
tmpfs            16G   49M   16G   1% /dev/shm
none            1.0M     0  1.0M   0% /run/credentials/systemd-journald.service
none            1.0M     0  1.0M   0% /run/credentials/systemd-resolved.service
tmpfs            16G   24M   16G   1% /tmp
/dev/nvme1n1p3  274G  217G   44G  84% /mnt/backup
/dev/nvme0n1p4  247G   68G  167G  29% /mnt/new_free
/dev/nvme1n1p2  511M   50M  462M  10% /boot/efi
/dev/sda1       916G  509G  363G  59% /mnt/share
s3fs             64P     0   64P   0% /mnt/s3_nata
s3fs             64P     0   64P   0% /mnt/s3
none            1.0M     0  1.0M   0% /run/credentials/getty@tty1.service
tmpfs           3.2G  4.1M  3.2G   1% /run/user/1001

=== MEMORY ===
               total        used        free      shared  buff/cache   available
Mem:            31Gi        20Gi       1.4Gi       209Mi         9Gi        10Gi
Swap:           27Gi          0B        27Gi
```
