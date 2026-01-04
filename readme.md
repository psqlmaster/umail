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
