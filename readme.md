![_](logo.png)
#### ✉️ umail: Secure Micro SMTP Client

A lightweight, dependency-free SMTP client written in C. Designed for minimal Linux servers, embedded systems, and secure environments where installing full MTAs (like Postfix or Sendmail) is not possible.

- Use umail if: You need to send alerts, logs, backup logs from servers, Docker containers, Raspberry Pi, or routers. You don't want to configure Postfix. You want nice one-line HTML reports. 
- Bottom line: No dependencies. No Postfix. Just a binary and the internet.

##### Key Features
- **Single binary:** No external dependencies (except libssl).
- **Secure:** Supports both **SMTPS** (Implicit SSL, port 465) and **STARTTLS** (port 587).
- **Reliable:** Built-in network timeouts (15s) prevent hanging processes in cron jobs.
- **Resilient:** Automatically retries sending 3 times (with 5s delay) in case of network or server failures.
- **Attachments:** Support for sending files (can be used multiple times) alongside text/HTML bodies.
- **Mass Mailing:** Support for multiple recipients (multiple `-t` flags).
- **Debug Friendly:** Detailed verbose mode (`-v`) to trace SMTP conversations and SSL handshakes.
- **Memory Safe:** Passwords are scrubbed from memory immediately after use.
- **Stealthy:** Supports reading credentials from protected files or environment variables.

##### Build
```sh
git clone --depth 1 https://github.com/psqlmaster/umail.git && cd umail && \
gcc -Os -o umail umail.c -lssl -lcrypto && strip umail && ./umail -h
```
OR
```sh
make && sudo make install && umail -h
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
Send specific files using the `SMTP_PASS` variable.

```sh
export SMTP_PASS="secret_password"
./umail \
  -s smtp.gmail.com \
  -u from@gmail.com \
  -t to@corp.com \
  -S "Daily Log" \
  -b "Please check the attached log files." \
  -a "/var/log/syslog" \
  -a "/var/log/auth.log"
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
  -t, --to <email>       Recipient email. Multiple allowed, example: -t user1@ya.ru -t user2@gmail.com
  -c, --cc <email>       Carbon Copy (cc). Multiple allowed.
  --bcc <email>          Blind Carbon Copy (bcc). Multiple allowed.
  -S, --subject <text>   Email subject
  -b, --body <text>      Email body. If omitted, reads from STDIN.
  -a, --attach <file>    File attachment path. Multiple allowed.
  -p, --secret <file>    Path to file containing password
  -M, --mono             Send as HTML Monospace (great for logs/tables)
  -v, --verbose          Enable verbose debug output
  -h, --help             Show help message

Environment Variables:
  SMTP_PASS              Password or App Password (used if -p is omitted)
```

##### Example: "Full Server Report"

You can group multiple commands to create a beautiful HTML report.

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

***Result (Email Body):***
```text
=== SERVER UPTIME ===
 21:42:00 up  8:59,  1 user,  load average: 3.92, 3.75, 3.74

=== DISK USAGE ===
Filesystem      Size  Used Avail Use% Mounted on
udev             16G     0   16G   0% /dev
tmpfs           3.2G  1.9M  3.2G   1% /run
/dev/md0        193G  107G   77G  59% /
/dev/nvme1n1p3  274G  217G   44G  84% /mnt/backup
/dev/sda1       916G  509G  363G  59% /mnt/share

=== MEMORY ===
               total        used        free      shared  buff/cache   available
Mem:            31Gi        20Gi       1.4Gi       209Mi         9Gi        10Gi
Swap:           27Gi          0B        27Gi
```

##### Example: "Global Bash Config" (Wrapper)

Create a shell wrapper to avoid typing credentials and server details every time.

**1. Create a script file (e.g., `um`)**

```bash
#!/bin/bash

# usage example:
# ./um -S "Backup Failed" -b "Check logs" -a file1 -a file2

/usr/bin/umail \
  --server smtp.gmail.com \
  --user from_address@gmail.com \
  --to to_address1@gmail.com \
  --cc to_address2@gmail.com \
  --secret /var/tmp/.umail/.umail \
  "$@"
```

**2. Make it executable**

```bash
chmod +x um
```

**3. Usage**

Now you can send emails with attachments using just the subject and body:

```bash
./um -S "Critical Error" -b "See attached logs" -a /var/log/syslog
```
