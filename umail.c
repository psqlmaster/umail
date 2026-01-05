#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/time.h> 
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#define BUF_SIZE 4096
#define TIMEOUT_SEC 15

/* --- Global & Macros --- */
int verbose = 0;
#define LOG_S(type, fmt, ...) \
    do { if (verbose) printf("\033[0;33mSERVER(%s):\033[0m " fmt, type, ##__VA_ARGS__); } while (0)
#define LOG_C(type, fmt, ...) \
    do { if (verbose) printf("\033[0;32mCLIENT(%s):\033[0m " fmt, type, ##__VA_ARGS__); } while (0)
#define LOG_I(fmt, ...) \
    do { if (verbose) printf(fmt, ##__VA_ARGS__); } while (0)

/* --- Linked List for Attachments --- */
typedef struct Attachment {
    char *path;
    struct Attachment *next;
} Attachment;

void add_attachment(Attachment **head, const char *path) {
    Attachment *new_node = malloc(sizeof(Attachment));
    if (!new_node) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        exit(1);
    }
    new_node->path = strdup(path);
    new_node->next = NULL;

    if (*head == NULL) {
        *head = new_node;
    } else {
        Attachment *current = *head;
        while (current->next) current = current->next;
        current->next = new_node;
    }
}

void free_attachments(Attachment *head) {
    Attachment *tmp;
    while (head != NULL) {
        tmp = head;
        head = head->next;
        free(tmp->path);
        free(tmp);
    }
}

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

const char *get_filename(const char *path) {
    const char *filename = strrchr(path, '/');
    return (filename == NULL) ? path : filename + 1;
}

/* --- Network Helpers (SSL) --- */
int read_response(SSL *ssl) {
    char buffer[BUF_SIZE];
    int bytes;
    memset(buffer, 0, BUF_SIZE);
    bytes = SSL_read(ssl, buffer, BUF_SIZE - 1);
    
    if (bytes > 0) {
        LOG_S("SSL", "%s", buffer);
        return 1;
    }
    return 0;
}

void send_cmd(SSL *ssl, const char *cmd) {
    if (strncmp(cmd, "AUTH", 4) == 0 || strlen(cmd) > 100) { 
        LOG_C("SSL", "AUTH/DATA/BLOB ...\n");
    } else {
        LOG_C("SSL", "%s", cmd);
    }

    if (SSL_write(ssl, cmd, strlen(cmd)) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    read_response(ssl);
}

/* --- Network Helpers (Raw Socket for STARTTLS) --- */
int raw_read_response(int sock) {
    char buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);
    int bytes = recv(sock, buffer, BUF_SIZE - 1, 0);
    if (bytes > 0) {
        LOG_S("RAW", "%s", buffer);
        if (buffer[0] == '2' || buffer[0] == '3') return 1;
    }
    return 0;
}

void raw_send_cmd(int sock, const char *cmd) {
    LOG_C("RAW", "%s", cmd);
    send(sock, cmd, strlen(cmd), 0);
    raw_read_response(sock);
}

void print_help(const char *prog_name) {
    printf("Secure SMTP Mailer (SSL & STARTTLS)\n");
    printf("Copyright (c) 2026, Alexander Shcheglov @sqlmaster\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  -s, --server <host>    SMTP server address\n");
    printf("  -P, --port <port>      SMTP port (465=SSL, 587=STARTTLS)\n");
    printf("  -u, --user <email>     User email / Login (FROM)\n");
    printf("  -t, --to <email>       Recipient email (TO)\n");
    printf("  -S, --subject <text>   Email subject\n");
    printf("  -b, --body <text>      Email body (optional)\n");
    printf("  -a, --attach <file>    File attachment path (can be used multiple times)\n");
    printf("  -p, --secret <file>    File containing password\n");
    printf("  -M, --mono             Send as HTML Monospace\n");
    printf("  -v, --verbose          Enable verbose debug output\n");
    printf("  -h, --help             Show this help message\n\n");
}

int read_password_from_file(const char *filename, char *buffer, size_t size) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;
    if (fgets(buffer, size, f) == NULL) { fclose(f); return 0; }
    fclose(f);
    buffer[strcspn(buffer, "\r\n")] = 0;
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        const char *prog_name = (argc > 0 && argv[0]) ? argv[0] : "umail";
        print_help(prog_name);
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
    char *secret_file = NULL;
    Attachment *att_head = NULL; /* Head of the linked list */
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
        {"verbose", no_argument,       0, 'v'}, 
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "s:P:u:t:S:b:a:p:hMv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's': server = optarg; break;
            case 'P': port = atoi(optarg); break;
            case 'u': user = optarg; break;
            case 't': to = optarg; break;
            case 'S': subject = optarg; break;
            case 'b': body = optarg; break;
            case 'a': add_attachment(&att_head, optarg); break; /* Add to list */
            case 'p': secret_file = optarg; break;
            case 'M': use_mono = 1; break;
            case 'v': verbose = 1; break;
            case 'h': print_help(argv[0]); free_attachments(att_head); return 0;
            case '?': default: print_help(argv[0]); free_attachments(att_head); return 1;
        }
    }

    if (!server || !user || !to) {
        fprintf(stderr, "Error: Missing required arguments.\n");
        free_attachments(att_head);
        return 1;
    }

    /* Validate Attachments Access before starting network */
    Attachment *curr = att_head;
    while (curr) {
        FILE *test_fp = fopen(curr->path, "rb");
        if (!test_fp) {
            fprintf(stderr, "Error: Cannot open attachment file: %s\n", curr->path);
            free_attachments(att_head);
            return 1;
        }
        fclose(test_fp);
        curr = curr->next;
    }

    if (secret_file) {
        if (!read_password_from_file(secret_file, password, sizeof(password))) {
            fprintf(stderr, "Failed to read password from file\n");
            free_attachments(att_head);
            return 1;
        }
    } else {
        char *env_pass = getenv("SMTP_PASS");
        if (env_pass) {
            strncpy(password, env_pass, sizeof(password) - 1);
        } else {
            fprintf(stderr, "Error: Password not provided (use --secret or SMTP_PASS)\n");
            free_attachments(att_head);
            return 1;
        }
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) { ERR_print_errors_fp(stderr); free_attachments(att_head); return 1; }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *host = gethostbyname(server);
    if (!host) {
        fprintf(stderr, "Error: Cannot resolve hostname %s\n", server);
        free_attachments(att_head); return 1;
    }

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC; timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = *((struct in_addr *)host->h_addr);
    memset(&(addr.sin_zero), 0, 8);

    LOG_I("Connecting to %s:%d (Timeout: %ds)...\n", server, port, TIMEOUT_SEC);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != 0) {
        perror("Unable to connect");
        free_attachments(att_head); return 1;
    }

    int starttls_mode = (port == 587);
    
    if (starttls_mode) {
        raw_read_response(sock);
        raw_send_cmd(sock, "EHLO mylinuxserver\r\n");
        
        LOG_C("RAW", "STARTTLS\r\n");
        send(sock, "STARTTLS\r\n", 10, 0);
        
        char buf[1024];
        int n = recv(sock, buf, sizeof(buf)-1, 0);
        if (n > 0) buf[n] = 0;
        LOG_S("RAW", "%s", buf);

        if (n <= 0 || strstr(buf, "220") == NULL) {
            fprintf(stderr, "Error: STARTTLS rejected.\n");
            close(sock); free_attachments(att_head); return 1;
        }
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sock); free_attachments(att_head); return 1;
    }

    if (!starttls_mode) read_response(ssl);

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
    free(b64_user); free(b64_pass);

    char cmd_buf[BUF_SIZE];
    snprintf(cmd_buf, sizeof(cmd_buf), "MAIL FROM: <%s>\r\n", user);
    send_cmd(ssl, cmd_buf);
    snprintf(cmd_buf, sizeof(cmd_buf), "RCPT TO: <%s>\r\n", to);
    send_cmd(ssl, cmd_buf);
    send_cmd(ssl, "DATA\r\n");

    char boundary[64];
    snprintf(boundary, sizeof(boundary), "----_=_NextPart_%lx_%lx", (long)time(NULL), (long)getpid());

    if (att_head != NULL) {
        /* Multipart Header if there are attachments */
        snprintf(cmd_buf, sizeof(cmd_buf), 
            "Subject: %s\r\nFrom: %s <%s>\r\nTo: %s\r\n"
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", 
            subject, "System Alert", user, to, boundary);
        SSL_write(ssl, cmd_buf, strlen(cmd_buf));

        /* Part 1: Body */
        snprintf(cmd_buf, sizeof(cmd_buf), "--%s\r\nContent-Type: %s; charset=UTF-8\r\n\r\n", 
            boundary, use_mono ? "text/html" : "text/plain");
        SSL_write(ssl, cmd_buf, strlen(cmd_buf));
    } else {
        /* Simple Header if no attachments */
        snprintf(cmd_buf, sizeof(cmd_buf), 
            "Subject: %s\r\nFrom: %s <%s>\r\nTo: %s\r\n"
            "MIME-Version: 1.0\r\nContent-Type: %s; charset=UTF-8\r\n\r\n", 
            subject, "System Alert", user, to, use_mono ? "text/html" : "text/plain");
        SSL_write(ssl, cmd_buf, strlen(cmd_buf));
    }

    if (use_mono) {
        const char *html_start = 
            "<div style='background-color:#f5f5f5; padding:10px; border-radius:5px;'>"
            "<pre style='font-family: Consolas, monospace; font-size: 14px; color: #333;'>";
        SSL_write(ssl, html_start, strlen(html_start));
    }
    
    if (body) {
        SSL_write(ssl, body, strlen(body));
    } else {
        if (isatty(fileno(stdin))) LOG_I("Reading body from STDIN...\n");
        char read_buf[1024];
        while(fgets(read_buf, sizeof(read_buf), stdin) != NULL) SSL_write(ssl, read_buf, strlen(read_buf));
    }
    
    if (use_mono) {
        const char *html_end = "</pre></div>";
        SSL_write(ssl, html_end, strlen(html_end));
    }

    /* Loop through attachments */
    curr = att_head;
    while (curr) {
        SSL_write(ssl, "\r\n", 2); 
        
        FILE *att_fp = fopen(curr->path, "rb");
        if (att_fp) {
            fseek(att_fp, 0, SEEK_END);
            long file_size = ftell(att_fp);
            fseek(att_fp, 0, SEEK_SET);

            snprintf(cmd_buf, sizeof(cmd_buf), 
                "--%s\r\nContent-Type: application/octet-stream; name=\"%s\"\r\n"
                "Content-Disposition: attachment; filename=\"%s\"\r\n"
                "Content-Transfer-Encoding: base64\r\n\r\n",
                boundary, get_filename(curr->path), get_filename(curr->path));
            SSL_write(ssl, cmd_buf, strlen(cmd_buf));

            unsigned char *file_content = malloc(file_size);
            if (file_content && fread(file_content, 1, file_size, att_fp) == file_size) {
                char *b64_file = base64_encode(file_content, file_size);
                if (b64_file) {
                    size_t b64_len = strlen(b64_file);
                    for (size_t i = 0; i < b64_len; i += 72) {
                        size_t chunk = (b64_len - i < 72) ? b64_len - i : 72;
                        SSL_write(ssl, b64_file + i, chunk);
                        SSL_write(ssl, "\r\n", 2);
                    }
                    free(b64_file);
                }
            }
            if(file_content) free(file_content);
            fclose(att_fp);
        } else {
             fprintf(stderr, "Warning: Failed to read attachment during send: %s\n", curr->path);
        }
        
        curr = curr->next;
    }

    /* Only send closing boundary if we had attachments */
    if (att_head != NULL) {
        snprintf(cmd_buf, sizeof(cmd_buf), "--%s--\r\n", boundary);
        SSL_write(ssl, cmd_buf, strlen(cmd_buf));
    }

    send_cmd(ssl, "\r\n.\r\n");
    send_cmd(ssl, "QUIT\r\n");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    free_attachments(att_head);

    return 0;
}
