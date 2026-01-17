#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/time.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#define BUF_SIZE 4096
#define TIMEOUT_SEC 15
#define MAX_RETRIES 3
#define RETRY_DELAY_SEC 5

int verbose = 0;

/* --- Macros --- */
#define LOG_S(type, fmt, ...) \
    do { if (verbose) printf("\033[0;33mSERVER(%s):\033[0m " fmt, type, ##__VA_ARGS__); } while (0)

#define LOG_C(type, fmt, ...) \
    do { if (verbose) printf("\033[0;32mCLIENT(%s):\033[0m " fmt, type, ##__VA_ARGS__); } while (0)

#define LOG_I(fmt, ...) \
    do { if (verbose) printf(fmt, ##__VA_ARGS__); } while (0)

#define LOG_ERR(fmt, ...) \
    fprintf(stderr, "\033[0;31mERROR:\033[0m " fmt, ##__VA_ARGS__)

/* --- Data Structures --- */
typedef struct ListNode {
    char *value;
    struct ListNode *next;
} ListNode;

typedef struct {
    char *server;
    int port;
    char *user;
    char *password;
    ListNode *rcpt_head; /* To */
    ListNode *cc_head;   /* Cc */
    ListNode *bcc_head;  /* Bcc */
    ListNode *att_head;  /* Attachments */
    char *subject;
    char *body;
    int use_mono;
} EmailConfig;

/* --- List Helpers --- */
void add_node(ListNode **head, const char *value) {
    ListNode *new_node = malloc(sizeof(ListNode));
    if (!new_node) exit(1);
    new_node->value = strdup(value);
    new_node->next = NULL;

    if (*head == NULL) {
        *head = new_node;
    } else {
        ListNode *current = *head;
        while (current->next) current = current->next;
        current->next = new_node;
    }
}

void free_list(ListNode *head) {
    ListNode *tmp;
    while (head != NULL) {
        tmp = head;
        head = head->next;
        free(tmp->value);
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

/* --- Network Logic --- */
int read_response(SSL *ssl) {
    char buffer[BUF_SIZE];
    int bytes;
    memset(buffer, 0, BUF_SIZE);
    bytes = SSL_read(ssl, buffer, BUF_SIZE - 1);
    if (bytes > 0) {
        LOG_S("SSL", "%s", buffer);
        /* Simple SMTP error check: 4xx or 5xx usually means error */
        if (buffer[0] == '4' || buffer[0] == '5') return 0; // Fail
        return 1;
    }
    return 0;
}

int send_cmd(SSL *ssl, const char *cmd) {
    if (strncmp(cmd, "AUTH", 4) == 0 || strlen(cmd) > 100) { 
        LOG_C("SSL", "AUTH/DATA/BLOB ...\n");
    } else {
        LOG_C("SSL", "%s", cmd);
    }
    if (SSL_write(ssl, cmd, strlen(cmd)) <= 0) {
        if(verbose) ERR_print_errors_fp(stderr);
        return 0;
    }
    return read_response(ssl);
}

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

/* Helper to iterate lists and send RCPT TO */
int send_rcpt_list(SSL *ssl, ListNode *head) {
    char cmd_buf[BUF_SIZE];
    ListNode *curr = head;
    while (curr) {
        snprintf(cmd_buf, sizeof(cmd_buf), "RCPT TO: <%s>\r\n", curr->value);
        if (!send_cmd(ssl, cmd_buf)) return 0;
        curr = curr->next;
    }
    return 1;
}

/* Helper to build header string (e.g. "To: a, b, c") */
void build_address_header(char *buffer, size_t size, const char *prefix, ListNode *head) {
    if (!head) {
        buffer[0] = '\0';
        return;
    }
    snprintf(buffer, size, "%s", prefix);
    ListNode *curr = head;
    while (curr) {
        if (strlen(buffer) + strlen(curr->value) + 5 < size) {
            strcat(buffer, curr->value);
            if (curr->next) strcat(buffer, ", ");
        }
        curr = curr->next;
    }
}

/* --- Core Sending Function --- */
/* Returns 0 on Success, 1 on Error */
int send_email_attempt(EmailConfig *cfg) {
    int sock = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int ret_code = 1; // Default to error
    struct addrinfo hints, *res = NULL, *p = NULL;

    /* 1. Init SSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) return 1;

    /* 2. Resolve (IPv4/IPv6) & Connect */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", cfg->port);

    LOG_I("Resolving %s...\n", cfg->server);
    if (getaddrinfo(cfg->server, port_str, &hints, &res) != 0) {
        LOG_ERR("Cannot resolve hostname %s\n", cfg->server);
        goto cleanup;
    }

    /* Loop through results and try to connect */
    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) continue;

        struct timeval timeout;
        timeout.tv_sec = TIMEOUT_SEC; timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        char ipstr[INET6_ADDRSTRLEN];
        void *addr;
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        LOG_I("Connecting to %s [%s]:%d...\n", cfg->server, ipstr, cfg->port);

        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            break; /* Success */
        }
        
        if (verbose) perror("Connection attempt failed");
        close(sock);
        sock = -1;
    }

    if (res) freeaddrinfo(res);
    if (sock == -1) {
        LOG_ERR("Failed to connect to any address for %s\n", cfg->server);
        goto cleanup;
    }

    /* 3. Handshake (STARTTLS logic) */
    int starttls_mode = (cfg->port == 587 || cfg->port == 25);
    if (starttls_mode) {
        if (!raw_read_response(sock)) goto cleanup;
        send(sock, "EHLO mylinuxserver\r\n", 20, 0);
        if (!raw_read_response(sock)) goto cleanup;
        
        LOG_C("RAW", "STARTTLS\r\n");
        send(sock, "STARTTLS\r\n", 10, 0);
        char buf[1024];
        int n = recv(sock, buf, sizeof(buf)-1, 0);
        if (n <= 0) goto cleanup;
        buf[n] = 0;
        LOG_S("RAW", "%s", buf);
        if (strstr(buf, "220") == NULL) goto cleanup;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        if (verbose) ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (!starttls_mode) if (!read_response(ssl)) goto cleanup;

    /* 4. SMTP Flow */
    if (!send_cmd(ssl, "EHLO mylinuxserver\r\n")) goto cleanup;
    if (!send_cmd(ssl, "AUTH LOGIN\r\n")) goto cleanup;

    char *b64_user = base64_encode((unsigned char*)cfg->user, strlen(cfg->user));
    char *b64_pass = base64_encode((unsigned char*)cfg->password, strlen(cfg->password));
    
    char auth_buf[BUF_SIZE];
    snprintf(auth_buf, sizeof(auth_buf), "%s\r\n", b64_user);
    if (!send_cmd(ssl, auth_buf)) { free(b64_user); free(b64_pass); goto cleanup; }
    snprintf(auth_buf, sizeof(auth_buf), "%s\r\n", b64_pass);
    if (!send_cmd(ssl, auth_buf)) { free(b64_user); free(b64_pass); goto cleanup; }
    free(b64_user); free(b64_pass);

    char cmd_buf[BUF_SIZE];
    snprintf(cmd_buf, sizeof(cmd_buf), "MAIL FROM: <%s>\r\n", cfg->user);
    if (!send_cmd(ssl, cmd_buf)) goto cleanup;

    if (!send_rcpt_list(ssl, cfg->rcpt_head)) goto cleanup;
    if (!send_rcpt_list(ssl, cfg->cc_head)) goto cleanup;
    if (!send_rcpt_list(ssl, cfg->bcc_head)) goto cleanup;

    if (!send_cmd(ssl, "DATA\r\n")) goto cleanup;

    /* 5. Headers & Body */
    char date_str[128];
    time_t now = time(NULL);
    strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S %z", localtime(&now));

    char boundary[64];
    snprintf(boundary, sizeof(boundary), "----_=_NextPart_%lx_%lx", (long)time(NULL), (long)getpid());

    char to_header[BUF_SIZE];
    char cc_header[BUF_SIZE];
    build_address_header(to_header, BUF_SIZE, "To: ", cfg->rcpt_head);
    build_address_header(cc_header, BUF_SIZE, "Cc: ", cfg->cc_head);

    snprintf(cmd_buf, sizeof(cmd_buf), 
        "Date: %s\r\n"
        "Subject: %s\r\n"
        "From: %s <%s>\r\n",
        date_str, cfg->subject, "System Alert", cfg->user);
    SSL_write(ssl, cmd_buf, strlen(cmd_buf));

    if (strlen(to_header) > 0) { SSL_write(ssl, to_header, strlen(to_header)); SSL_write(ssl, "\r\n", 2); }
    if (strlen(cc_header) > 0) { SSL_write(ssl, cc_header, strlen(cc_header)); SSL_write(ssl, "\r\n", 2); }

    snprintf(cmd_buf, sizeof(cmd_buf), 
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", 
        boundary);
    SSL_write(ssl, cmd_buf, strlen(cmd_buf));

    /* 5.4 Body Part */
    int is_html = 0;
    if (cfg->use_mono) {
        is_html = 1;
    } else if (cfg->body && (strncasecmp(cfg->body, "<html>", 6) == 0 || strncasecmp(cfg->body, "<!DOCTYPE", 9) == 0)) {
        is_html = 1;
    }

    snprintf(cmd_buf, sizeof(cmd_buf), "--%s\r\nContent-Type: %s; charset=UTF-8\r\n\r\n", 
        boundary, is_html ? "text/html" : "text/plain");
    SSL_write(ssl, cmd_buf, strlen(cmd_buf));

    if (cfg->use_mono) {
        const char *html_start = "<div style='font-family:monospace;white-space:pre;'>";
        SSL_write(ssl, html_start, strlen(html_start));
    }
    
    if (cfg->body) {
        SSL_write(ssl, cfg->body, strlen(cfg->body));
    }
    
    if (cfg->use_mono) {
        const char *html_end = "</div>";
        SSL_write(ssl, html_end, strlen(html_end));
    }

    /* 6. Attachments */
    ListNode *curr = cfg->att_head;
    while (curr) {
        SSL_write(ssl, "\r\n", 2); 
        FILE *att_fp = fopen(curr->value, "rb");
        if (att_fp) {
            fseek(att_fp, 0, SEEK_END);
            long file_size = ftell(att_fp);
            fseek(att_fp, 0, SEEK_SET);

            snprintf(cmd_buf, sizeof(cmd_buf), 
                "--%s\r\nContent-Type: application/octet-stream; name=\"%s\"\r\n"
                "Content-Disposition: attachment; filename=\"%s\"\r\n"
                "Content-Transfer-Encoding: base64\r\n\r\n",
                boundary, get_filename(curr->value), get_filename(curr->value));
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
        }
        curr = curr->next;
    }

    snprintf(cmd_buf, sizeof(cmd_buf), "\r\n--%s--\r\n", boundary);
    SSL_write(ssl, cmd_buf, strlen(cmd_buf));

    if (!send_cmd(ssl, "\r\n.\r\n")) goto cleanup;
    send_cmd(ssl, "QUIT\r\n");

    ret_code = 0; /* SUCCESS */

cleanup:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (sock != -1) close(sock);
    if (ctx) SSL_CTX_free(ctx);
    return ret_code;
}

void print_help(const char *prog_name) {
    printf("Secure SMTP Mailer (SSL & STARTTLS)\n");
    printf("Copyright (c) 2026, Alexander Shcheglov @sqlmaster\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  -s, --server <host>    SMTP server address\n");
    printf("  -P, --port <port>      SMTP port (465=SSL, 25=587=STARTTLS)\n");
    printf("  -u, --user <email>     User email / Login (FROM)\n");
    printf("  -t, --to <email>       Recipient (To). Multiple allowed.\n");
    printf("  -c, --cc <email>       Carbon Copy (Cc). Multiple allowed.\n");
    printf("  --bcc <email>          Blind Carbon Copy (Bcc). Multiple allowed.\n");
    printf("  -S, --subject <text>   Email subject\n");
    printf("  -b, --body <text>      Email body\n");
    printf("  -a, --attach <file>    Attachment path (multiple allowed)\n");
    printf("  -p, --secret <file>    Password file\n");
    printf("  -M, --mono             HTML Monospace mode\n");
    printf("  -v, --verbose          Verbose mode\n");
    printf("  -h, --help             Show help\n\n");
}

int read_password_from_file(const char *filename, char *buffer, size_t size) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;
    if (fgets(buffer, size, f) == NULL) { fclose(f); return 0; }
    fclose(f);
    buffer[strcspn(buffer, "\r\n")] = 0;
    return 1;
}

#define OPT_BCC 1001

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        const char *prog_name = (argc > 0 && argv[0]) ? argv[0] : "umail";
        print_help(prog_name); return 1;
    }

    EmailConfig cfg;
    memset(&cfg, 0, sizeof(EmailConfig));
    cfg.port = 465;
    cfg.subject = "No Subject";
    char *secret_file = NULL;

    int opt; 
    int option_index = 0;
    struct option long_options[] = {
        {"server",  required_argument, 0, 's'},
        {"port",    required_argument, 0, 'P'},
        {"user",    required_argument, 0, 'u'},
        {"to",      required_argument, 0, 't'},
        {"cc",      required_argument, 0, 'c'},
        {"bcc",     required_argument, 0, OPT_BCC},
        {"subject", required_argument, 0, 'S'},
        {"body",    required_argument, 0, 'b'},
        {"attach",  required_argument, 0, 'a'},
        {"secret",  required_argument, 0, 'p'},
        {"mono",    no_argument,       0, 'M'},
        {"verbose", no_argument,       0, 'v'}, 
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "s:P:u:t:c:S:b:a:p:hMv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's': cfg.server = optarg; break;
            case 'P': cfg.port = atoi(optarg); break;
            case 'u': cfg.user = optarg; break;
            case 't': add_node(&cfg.rcpt_head, optarg); break;
            case 'c': add_node(&cfg.cc_head, optarg); break;
            case OPT_BCC: add_node(&cfg.bcc_head, optarg); break;
            case 'S': cfg.subject = optarg; break;
            case 'b': cfg.body = optarg; break;
            case 'a': add_node(&cfg.att_head, optarg); break;
            case 'p': secret_file = optarg; break;
            case 'M': cfg.use_mono = 1; break;
            case 'v': verbose = 1; break;
            case 'h': print_help(argv[0]); return 0;
            default: print_help(argv[0]); return 1;
        }
    }

    if (!cfg.server || !cfg.user || (!cfg.rcpt_head && !cfg.cc_head && !cfg.bcc_head)) {
        LOG_ERR("Missing required arguments (server, user, and at least one recipient).\n");
        return 1;
    }

    /* Handle Password */
    char password_buf[256];
    if (secret_file) {
        if (!read_password_from_file(secret_file, password_buf, sizeof(password_buf))) {
            LOG_ERR("Failed to read password from file\n"); return 1;
        }
    } else {
        char *env_pass = getenv("SMTP_PASS");
        if (env_pass) strncpy(password_buf, env_pass, sizeof(password_buf) - 1);
        else { LOG_ERR("Password not provided\n"); return 1; }
    }
    cfg.password = password_buf;

    /* Handle Body (Read STDIN once if needed) */
    char *stdin_buf = NULL;
    if (!cfg.body) {
        if (!isatty(fileno(stdin))) {
            size_t size = 1024;
            size_t len = 0;
            stdin_buf = malloc(size);
            if (!stdin_buf) return 1;
            stdin_buf[0] = '\0';
            
            char buf[1024];
            while (fgets(buf, sizeof(buf), stdin)) {
                size_t chunk_len = strlen(buf);
                if (len + chunk_len >= size) {
                    size *= 2;
                    char *new_buf = realloc(stdin_buf, size);
                    if (!new_buf) { free(stdin_buf); return 1; }
                    stdin_buf = new_buf;
                }
                strcat(stdin_buf, buf);
                len += chunk_len;
            }
            cfg.body = stdin_buf;
        } else {
            cfg.body = "";
        }
    }

    /* --- RETRY LOOP --- */
    int attempt = 1;
    int success = 0;

    while (attempt <= MAX_RETRIES) {
        if (attempt > 1) LOG_I("Retry attempt %d/%d in %ds...\n", attempt, MAX_RETRIES, RETRY_DELAY_SEC);
        
        if (send_email_attempt(&cfg) == 0) {
            success = 1;
            LOG_I("Email sent successfully.\n");
            break;
        } else {
            LOG_ERR("Attempt %d failed.\n", attempt);
            if (attempt < MAX_RETRIES) sleep(RETRY_DELAY_SEC);
        }
        attempt++;
    }

    /* Cleanup */
    OPENSSL_cleanse(password_buf, sizeof(password_buf));
    if (stdin_buf) free(stdin_buf);
    free_list(cfg.att_head);
    free_list(cfg.rcpt_head);
    free_list(cfg.cc_head);
    free_list(cfg.bcc_head);

    return success ? 0 : 1;
}
