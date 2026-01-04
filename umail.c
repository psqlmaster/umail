#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#define BUF_SIZE 4096

/* --- Base64 Helpers --- */
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }
    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';
    encoded_data[output_length] = '\0';
    return encoded_data;
}

/* --- Helper to get filename from path --- */
const char *get_filename(const char *path) {
    const char *filename = strrchr(path, '/');
    if (filename == NULL)
        filename = path;
    else
        filename++;
    return filename;
}

/* --- Network Helpers --- */
void read_response(SSL *ssl) {
    char buffer[BUF_SIZE];
    int bytes;
    memset(buffer, 0, BUF_SIZE);
    bytes = SSL_read(ssl, buffer, BUF_SIZE - 1);
    
    if (bytes > 0) {
        printf("\033[0;33mSERVER:\033[0m %s", buffer);
    }
}

void send_cmd(SSL *ssl, const char *cmd) {
    if (strncmp(cmd, "AUTH", 4) == 0 || strlen(cmd) > 100) { 
        printf("\033[0;32mCLIENT:\033[0m AUTH/DATA ...\n"); 
    } else {
        printf("\033[0;32mCLIENT:\033[0m %s", cmd);
    }
    SSL_write(ssl, cmd, strlen(cmd));
    read_response(ssl);
}

void print_help(const char *prog_name) {
    printf("Secure SMTP Mailer (SSL/TLS)\n");
    printf("Copyright (c) 2026, Alexander Shcheglov @sqlmaster\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  -s, --server <host>    SMTP server address (e.g. smtp.gmail.com)\n");
    printf("  -P, --port <port>      SMTP port (default: 465)\n");
    printf("  -u, --user <email>     User email / Login (FROM)\n");
    printf("  -t, --to <email>       Recipient email (TO)\n");
    printf("  -S, --subject <text>   Email subject\n");
    printf("  -b, --body <text>      Email body (optional). If omitted, reads from STDIN\n");
    printf("  -a, --attach <file>    File attachment path\n");
    printf("  -M, --mono             Send as HTML Monospace (great for logs/tables)\n");
    printf("  -p, --secret <file>    File containing password\n");
    printf("  -h, --help             Show this help message and exit\n\n");
    printf("Environment Variables:\n");
    printf("  SMTP_PASS              Password or App Password (REQUIRED)\n\n");
    printf("Example:\n");
    printf("  %s -s smtp.gmail.com -u me@gmail.com -t user@corp.com -S 'Log' -a ./log.txt\n", prog_name);
}

int read_password_from_file(const char *filename, char *buffer, size_t size) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("Error opening secret file");
        return 0;
    }

    if (fgets(buffer, size, f) == NULL) {
        fclose(f);
        return 0;
    }
    fclose(f);

    buffer[strcspn(buffer, "\r\n")] = 0;
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        print_help(argv[0]);
        return 1;
    }

    int opt;
    int option_index = 0;

    char *server = NULL;
    int port = 465;
    char *user = NULL;
    char *to = NULL;
    char *subject = "No Subject";
    char *body = NULL;
    char *attachment_path = NULL;
    char *secret_file = NULL;
    int use_mono = 0;
    
    char password[256]; 
    OPENSSL_cleanse(password, sizeof(password));

    struct option long_options[] = {
        {"server",  required_argument, 0, 's'},
        {"port",    required_argument, 0, 'P'},
        {"user",    required_argument, 0, 'u'},
        {"to",      required_argument, 0, 't'},
        {"subject", required_argument, 0, 'S'},
        {"body",    required_argument, 0, 'b'},
        {"attach",  required_argument, 0, 'a'},
        {"secret",  required_argument, 0, 'p'},
        {"mono",    no_argument,       0, 'M'}, 
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "s:P:u:t:S:b:a:p:hM", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's': server = optarg; break;
            case 'P': port = atoi(optarg); break;
            case 'u': user = optarg; break;
            case 't': to = optarg; break;
            case 'S': subject = optarg; break;
            case 'b': body = optarg; break;
            case 'a': attachment_path = optarg; break;
            case 'p': secret_file = optarg; break;
            case 'M': use_mono = 1; break;
            case 'h': print_help(argv[0]); return 0;
            case '?':
            default: 
                print_help(argv[0]); 
                return 1;
        }
    }

    // Check attachment existence before connecting
    long file_size = 0;
    FILE *att_fp = NULL;
    if (attachment_path) {
        att_fp = fopen(attachment_path, "rb");
        if (!att_fp) {
            fprintf(stderr, "Error: Cannot open attachment file: %s\n", attachment_path);
            return 1;
        }
        fseek(att_fp, 0, SEEK_END);
        file_size = ftell(att_fp);
        fseek(att_fp, 0, SEEK_SET);
    }

    if (secret_file) {
        if (!read_password_from_file(secret_file, password, sizeof(password))) {
            fprintf(stderr, "Failed to read password from file: %s\n", secret_file);
            if(att_fp) fclose(att_fp);
            return 1;
        }
    } else {
        char *env_pass = getenv("SMTP_PASS");
        if (env_pass) {
            strncpy(password, env_pass, sizeof(password) - 1);
        } else {
            fprintf(stderr, "Error: Password not provided. Use --secret <file> or set SMTP_PASS env var.\n");
            if(att_fp) fclose(att_fp);
            return 1;
        }
    }

    if (!server || !user || !to) {
        fprintf(stderr, "Error: Missing required arguments.\n");
        fprintf(stderr, "Use -h or --help for info.\n");
        if(att_fp) fclose(att_fp);
        return 1;
    }

    /* init SSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) { ERR_print_errors_fp(stderr); if(att_fp) fclose(att_fp); return 1; }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *host = gethostbyname(server);
    if (!host) {
        fprintf(stderr, "Error: Cannot resolve hostname %s\n", server);
        if(att_fp) fclose(att_fp);
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = *((struct in_addr *)host->h_addr);
    memset(&(addr.sin_zero), 0, 8);

    printf("Connecting to %s:%d...\n", server, port);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != 0) {
        perror("Unable to connect");
        if(att_fp) fclose(att_fp);
        return 1;
    }

    /* SSL Handshake */
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        if(att_fp) fclose(att_fp);
        return 1;
    }

    read_response(ssl);

    /* SMTP Flow */
    send_cmd(ssl, "EHLO mylinuxserver\r\n");
    send_cmd(ssl, "AUTH LOGIN\r\n");

    char *b64_user = base64_encode((unsigned char*)user, strlen(user));
    char *b64_pass = base64_encode((unsigned char*)password, strlen(password));
    
    OPENSSL_cleanse(password, sizeof(password));  
    
    char auth_buf[BUF_SIZE];
    snprintf(auth_buf, sizeof(auth_buf), "%s\r\n", b64_user);
    send_cmd(ssl, auth_buf);

    snprintf(auth_buf, sizeof(auth_buf), "%s\r\n", b64_pass);
    send_cmd(ssl, auth_buf);

    free(b64_user);
    free(b64_pass);

    char cmd_buf[BUF_SIZE];
    snprintf(cmd_buf, sizeof(cmd_buf), "MAIL FROM: <%s>\r\n", user);
    send_cmd(ssl, cmd_buf);

    snprintf(cmd_buf, sizeof(cmd_buf), "RCPT TO: <%s>\r\n", to);
    send_cmd(ssl, cmd_buf);

    send_cmd(ssl, "DATA\r\n");

    /* --- Sending MIME Headers --- */
    char boundary[64];
    snprintf(boundary, sizeof(boundary), "----_=_NextPart_%lx_%lx", (long)time(NULL), (long)getpid());

    if (attachment_path) {
        /* Multipart Header */
        snprintf(cmd_buf, sizeof(cmd_buf), 
            "Subject: %s\r\n"
            "From: %s <%s>\r\n"
            "To: %s\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", 
            subject, "System Alert", user, to, boundary
        );
        SSL_write(ssl, cmd_buf, strlen(cmd_buf));

        /* Part 1: Body */
        snprintf(cmd_buf, sizeof(cmd_buf), 
            "--%s\r\n"
            "Content-Type: %s; charset=UTF-8\r\n\r\n", 
            boundary, use_mono ? "text/html" : "text/plain"
        );
        SSL_write(ssl, cmd_buf, strlen(cmd_buf));
    } else {
        /* Simple Header (Legacy) */
        snprintf(cmd_buf, sizeof(cmd_buf), 
            "Subject: %s\r\nFrom: %s <%s>\r\nTo: %s\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: %s; charset=UTF-8\r\n\r\n", 
            subject, "System Alert", user, to,
            use_mono ? "text/html" : "text/plain"
        );
        SSL_write(ssl, cmd_buf, strlen(cmd_buf));
    }

    /* Write Body Content */
    if (use_mono) {
        const char *html_start = 
            "<div style='background-color:#f5f5f5; padding:10px; border-radius:5px;'>"
            "<pre style='font-family: Consolas, monospace; font-size: 14px; color: #333;'>";
        SSL_write(ssl, html_start, strlen(html_start));
    }

    if (body) {
        SSL_write(ssl, body, strlen(body));
    } else {
        if (isatty(fileno(stdin))) {
            printf("Reading body from STDIN. Type message, Ctrl+D to send.\n");
        }
        char read_buf[1024];
        while(fgets(read_buf, sizeof(read_buf), stdin) != NULL) {
            SSL_write(ssl, read_buf, strlen(read_buf));
        }
    }

    if (use_mono) {
        const char *html_end = "</pre></div>";
        SSL_write(ssl, html_end, strlen(html_end));
    }

    /* Part 2: Attachment */
    if (attachment_path && att_fp) {
        SSL_write(ssl, "\r\n", 2); 
        
        snprintf(cmd_buf, sizeof(cmd_buf), 
            "--%s\r\n"
            "Content-Type: application/octet-stream; name=\"%s\"\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n",
            boundary, get_filename(attachment_path), get_filename(attachment_path)
        );
        SSL_write(ssl, cmd_buf, strlen(cmd_buf));

        /* Read file, encode and send in chunks */
        unsigned char *file_content = malloc(file_size);
        if (file_content) {
            if (fread(file_content, 1, file_size, att_fp) == file_size) {
                char *b64_file = base64_encode(file_content, file_size);
                if (b64_file) {
                    size_t b64_len = strlen(b64_file);
                    size_t chunk_size = 72; // MIME max line length
                    for (size_t i = 0; i < b64_len; i += chunk_size) {
                        size_t remaining = b64_len - i;
                        size_t to_write = (remaining < chunk_size) ? remaining : chunk_size;
                        SSL_write(ssl, b64_file + i, to_write);
                        SSL_write(ssl, "\r\n", 2);
                    }
                    free(b64_file);
                }
            }
            free(file_content);
        }
        fclose(att_fp);

        /* Closing Boundary */
        snprintf(cmd_buf, sizeof(cmd_buf), "--%s--\r\n", boundary);
        SSL_write(ssl, cmd_buf, strlen(cmd_buf));
    }

    send_cmd(ssl, "\r\n.\r\n");
    send_cmd(ssl, "QUIT\r\n");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
