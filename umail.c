#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h> // Для обработки аргументов
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 4096

// --- Base64 Helpers ---
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

    for (int i = 0, j = 0; i < input_length;) {
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

// --- Network Helpers ---
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
    if (strncmp(cmd, "AUTH", 4) == 0 || strlen(cmd) > 50) { 
        printf("\033[0;32mCLIENT:\033[0m AUTH/DATA ...\n"); 
    } else {
        printf("\033[0;32mCLIENT:\033[0m %s", cmd);
    }
    SSL_write(ssl, cmd, strlen(cmd));
    read_response(ssl);
}

// --- Help & Usage ---
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
    printf("  -h, --help             Show this help message and exit\n\n");
    printf("Environment Variables:\n");
    printf("  SMTP_PASS              Password or App Password (REQUIRED)\n\n");
    printf("Example:\n");
    printf("  export SMTP_PASS='secret'\n");
    printf("  %s -s smtp.gmail.com -u me@gmail.com -t admin@corp.com -S 'Alert' -b 'Error!'\n", prog_name);
}

int main(int argc, char *argv[]) {
    int opt;
    int option_index = 0;

    // Параметры по умолчанию
    char *server = NULL;
    int port = 465;
    char *user = NULL;
    char *to = NULL;
    char *subject = "No Subject";
    char *body = NULL; 

    struct option long_options[] = {
        {"server",  required_argument, 0, 's'},
        {"port",    required_argument, 0, 'P'},
        {"user",    required_argument, 0, 'u'},
        {"to",      required_argument, 0, 't'},
        {"subject", required_argument, 0, 'S'},
        {"body",    required_argument, 0, 'b'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    // Разбор аргументов
    while ((opt = getopt_long(argc, argv, "s:P:u:t:S:b:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's': server = optarg; break;
            case 'P': port = atoi(optarg); break;
            case 'u': user = optarg; break;
            case 't': to = optarg; break;
            case 'S': subject = optarg; break;
            case 'b': body = optarg; break;
            case 'h':
                print_help(argv[0]);
                return 0;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    // Проверка обязательных полей
    if (!server || !user || !to) {
        fprintf(stderr, "Error: Missing required arguments.\n");
        fprintf(stderr, "Use -h or --help for info.\n");
        return 1;
    }

    // Получение пароля
    char *pass = getenv("SMTP_PASS");
    if (pass == NULL) {
        fprintf(stderr, "Error: SMTP_PASS environment variable is not set.\n");
        return 1;
    }

    // Инициализация SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) { ERR_print_errors_fp(stderr); return 1; }

    // Сокет
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *host = gethostbyname(server);
    if (!host) {
        fprintf(stderr, "Error: Cannot resolve hostname %s\n", server);
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
        return 1;
    }

    // SSL Handshake
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    read_response(ssl);

    // SMTP Flow
    send_cmd(ssl, "EHLO mylinuxserver\r\n");
    send_cmd(ssl, "AUTH LOGIN\r\n");

    char *b64_user = base64_encode((unsigned char*)user, strlen(user));
    char *b64_pass = base64_encode((unsigned char*)pass, strlen(pass));
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

    // Headers
    snprintf(cmd_buf, sizeof(cmd_buf), 
        "Subject: %s\r\nFrom: %s <%s>\r\nTo: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n", 
        subject, "System Alert", user, to);
    SSL_write(ssl, cmd_buf, strlen(cmd_buf));

    // Body
    if (body) {
        SSL_write(ssl, body, strlen(body));
    } else {
        // Читаем из stdin, если body не задан аргументом
        char read_buf[1024];
        while(fgets(read_buf, sizeof(read_buf), stdin) != NULL) {
            SSL_write(ssl, read_buf, strlen(read_buf));
        }
    }

    send_cmd(ssl, "\r\n.\r\n");
    send_cmd(ssl, "QUIT\r\n");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
