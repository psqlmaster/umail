![_](logo.png)
#### 🛡️ umail: Secure Micro SMTP Client

A lightweight, dependency-free SMTP client written in C. Designed for minimal Linux servers, embedded systems, and secure environments where installing full MTAs (like Postfix or Sendmail) is not possible.

##### Key Features
- **Single binary:** No external dependencies (except libssl).
- **Secure:** Support for SMTPS (port 465) and secure authentication.
- **Memory Safe:** Passwords are scrubbed from memory immediately after use.
- **Stealthy:** Supports reading credentials from protected files to avoid process listing leaks.
- **Pipeline friendly:** Easy integration with cron, bash, and backup scripts.

##### Build
```sh
git clone https://github.com/psqlmaster/umail.git && cd umail && \
gcc -Os -o umail umail.c -lssl -lcrypto && strip umail && ./umail -h
```

##### Quick Start

1. **Setup credentials**
Create a secure file containing only your password (or App Password).
*Note: We use chmod 600 to ensure only the owner can read the password.*

```sh
mkdir -p /var/tmp/.umail/ && \
echo "your_password_app" > /var/tmp/.umail/.umail && \
chmod 600 /var/tmp/.umail/.umail
```

2. **Send message from pipe**
Execute a command and send its output directly to email.

```sh
lsblk -f | ./umail \
  --server smtp.gmail.com \
  --user from_address@gmail.com \
  --to to_address@gmail.com \
  --secret /var/tmp/.umail/.umail \
  --subject "Secure Run"
  --mono
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
  -p, --secret <file>    Path to file containing password
  -M, --mono             Send as HTML Monospace (great for logs/tables)
  -h, --help             Show help message
```
