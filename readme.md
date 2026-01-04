![_](logo.png)
#### 🛡️ umail: Secure Micro SMTP Client

A lightweight, dependency-free SMTP client written in C. Designed for minimal Linux servers, embedded systems, and secure environments where installing full MTAs (like Postfix or Sendmail) is not possible.

##### Key Features
- **Single binary:** No external dependencies (except libssl).
- **Secure:** Support for SMTPS (port 465) and secure authentication.
- **Attachments:** Support for sending files (MIME Multipart) alongside text/HTML bodies.
- **Memory Safe:** Passwords are scrubbed from memory immediately after use.
- **Stealthy:** Supports reading credentials from protected files or environment variables.
- **Pipeline friendly:** Easy integration with cron, bash, and backup scripts.

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

**2. Send message from pipe**
Execute a command and send its output directly to email using a secret file.

```sh
lsblk -f | ./umail \
  --server smtp.gmail.com \
  --user from_address@gmail.com \
  --to to_address@gmail.com \
  --secret /var/tmp/.umail/.umail \
  --subject "Secure Run" \
  --mono
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

##### Options

```text
Usage: ./umail [OPTIONS]

  -s, --server <host>    SMTP server address (e.g., smtp.gmail.com)
  -P, --port <port>      SMTP port (default: 465)
  -u, --user <email>     User email / Login (FROM)
  -t, --to <email>       Recipient email (TO)
  -S, --subject <text>   Email subject
  -b, --body <text>      Email body. If omitted, reads from STDIN.
  -a, --attach <file>    File attachment path
  -p, --secret <file>    Path to file containing password
  -M, --mono             Send as HTML Monospace (great for logs/tables)
  -h, --help             Show help message

Environment Variables:
  SMTP_PASS              Password or App Password (used if -p is omitted)
```
