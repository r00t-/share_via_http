/*
 * share_via_http.c - Share a file via HTTP using libmicrohttpd
 *
 * initially generated using by Claude 3.7 Sonnet,
 * from the following prompt:
 * write a program, "share_via_http.c",
 * that makes a file passed on the command-line available via http.
 * in C, for running on linux, using libmicrohttpd.
 * break up the code into sensibly sized functions in a single source file.
 * use port 9999 by default, but allow it to be changed by a command-line option.
 * print the url the file is available at to stdout,
 * the printed url should not contain the filename (for brevity).
 * when a request without filename is received, generate a http redirect to
 * the url with the full filename.
 * the url should refer to the host the program is run on using an ip address
 * (prefer ipv4 but support ipv6)
 * parse `/proc/net/route` to find the interface the default-route points to,
 * use the appropriate userspace API of the linux kernel to
 * find the ip address of the interface.
 * if the default-route interface is a mobile internet connection
 * (identified by an "rmnet" or "umts" name or a 10.0.0.0/24 address,
 *  do not use it, but instead use other interfaces that are
 *  up, not loopback, and have a route assigned.)
 * if there are multiple possible ip addresses, generate a url for all of those.
 * 
 * use simple heuristics to generate a mime-type for serving the file.
 * 
 * optionally (at compile-time) use libqrencode to create a qr-code for the url,
 * and print it to the terminal using ANSI codes
 * like the `qrencde` program does in ANSI output mode.
 *
 * Compile with:
 *   Without QR code support:
 *     gcc -o share_via_http share_via_http.c -lmicrohttpd
 *   
 *   With QR code support:
 *     gcc -o share_via_http share_via_http.c -lmicrohttpd -lqrencode -DUSE_QRCODE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <microhttpd.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <ctype.h>
#include <limits.h>

#ifdef USE_QRCODE
#include <qrencode.h>
#endif

#define DEFAULT_PORT 9999
#define MAX_IPS 16
#define MAX_URL_LENGTH 256
#define BUFFER_SIZE 1024

/* Global variables */
static char *filename = NULL;
static char *basename_only = NULL;
static const char *urls[MAX_IPS];
static int num_urls = 0;
static int port = DEFAULT_PORT;

struct MimeType {
    const char *extension;
    const char *mime_type;
};

/* Common MIME types */
static struct MimeType mime_types[] = {
    {".html", "text/html"},
    {".htm", "text/html"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".txt", "text/plain"},
    {".md", "text/markdown"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".png", "image/png"},
    {".gif", "image/gif"},
    {".svg", "image/svg+xml"},
    {".ico", "image/x-icon"},
    {".mp3", "audio/mpeg"},
    {".mp4", "video/mp4"},
    {".webm", "video/webm"},
    {".ogg", "application/ogg"},
    {".ogv", "video/ogg"},
    {".oga", "audio/ogg"},
    {".pdf", "application/pdf"},
    {".zip", "application/zip"},
    {".tar", "application/x-tar"},
    {".gz", "application/gzip"},
    {".doc", "application/msword"},
    {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".xls", "application/vnd.ms-excel"},
    {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {NULL, NULL}
};

/* Function prototypes */
static int request_handler(void *cls, struct MHD_Connection *connection, 
                          const char *url, const char *method,
                          const char *version, const char *upload_data,
                          size_t *upload_data_size, void **con_cls);
static int send_file(struct MHD_Connection *connection, const char *filename);
static char *get_mime_type(const char *filename);
static void get_default_route_interface(char *interface, size_t size);
static int is_inappropriate_interface(const char *interface, const char *ip_addr);
static void find_ip_addresses();
static void print_urls();
static void extract_basename();
static void print_usage(const char *program_name);
static void parse_arguments(int argc, char *argv[]);
#ifdef USE_QRCODE
static void print_qrcode(const char *url);
#endif

int main(int argc, char *argv[]) {
    struct MHD_Daemon *daemon;
    
    /* Parse command-line arguments */
    parse_arguments(argc, argv);

    /* Extract basename from filename */
    extract_basename();

    /* Find the server's IP addresses */
    find_ip_addresses();

    /* Print URLs */
    print_urls();

    /* Start the HTTP daemon */
    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL,
                             &request_handler, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "Error starting MHD daemon\n");
        return 1;
    }

    /* Wait for Ctrl+C */
    printf("\nPress Ctrl+C to stop sharing\n");
    while (1) {
        sleep(1);
    }

    /* Stop the daemon */
    MHD_stop_daemon(daemon);
    return 0;
}

/* Parse command-line arguments */
static void parse_arguments(int argc, char *argv[]) {
    int opt;

    while ((opt = getopt(argc, argv, "p:h")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                if (port <= 0 || port > 65535) {
                    fprintf(stderr, "Invalid port number\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: No file specified\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    filename = argv[optind];

    /* Check if the file exists and is readable */
    if (access(filename, R_OK) != 0) {
        fprintf(stderr, "Error: Cannot read file '%s'\n", filename);
        exit(EXIT_FAILURE);
    }
}

/* Print usage information */
static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [-p PORT] FILE\n", program_name);
    fprintf(stderr, "Share a file via HTTP\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p PORT    Port to use (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -h         Display this help and exit\n");
}

/* Extract basename from the full path */
static void extract_basename() {
    char *last_slash = strrchr(filename, '/');
    
    if (last_slash == NULL) {
        basename_only = filename;
    } else {
        basename_only = last_slash + 1;
    }
}

/* HTTP request handler */
static int request_handler(void *cls, struct MHD_Connection *connection, 
                          const char *url, const char *method,
                          const char *version, const char *upload_data,
                          size_t *upload_data_size, void **con_cls) {
    struct MHD_Response *response;
    int ret;
    char redirect_url[PATH_MAX];

    /* Only handle GET requests */
    if (strcmp(method, "GET") != 0) {
        return MHD_NO;
    }

    /* If URL is "/" or empty, redirect to the file */
    if (strcmp(url, "/") == 0 || strlen(url) == 0) {
        snprintf(redirect_url, sizeof(redirect_url), "/%s", basename_only);
        response = MHD_create_response_from_buffer(0, (void*)"", MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Location", redirect_url);
        ret = MHD_queue_response(connection, MHD_HTTP_FOUND, response);
        MHD_destroy_response(response);
        return ret;
    }

    /* If URL matches our file, serve it */
    if (strcmp(url + 1, basename_only) == 0) {
        return send_file(connection, filename);
    }

    /* If URL doesn't match, return 404 */
    response = MHD_create_response_from_buffer(
        strlen("File not found"), (void*)"File not found", MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response(response);
    
    return ret;
}

/* Send a file in response to an HTTP request */
static int send_file(struct MHD_Connection *connection, const char *filename) {
    struct MHD_Response *response;
    int ret;
    int fd;
    struct stat stat_buf;
    char *mime_type;

    /* Open the file */
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        response = MHD_create_response_from_buffer(
            strlen("Cannot open file"), (void*)"Cannot open file", MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }

    /* Get file size */
    if (fstat(fd, &stat_buf) != 0 || !S_ISREG(stat_buf.st_mode)) {
        close(fd);
        response = MHD_create_response_from_buffer(
            strlen("Not a regular file"), (void*)"Not a regular file", MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }

    /* Create response from file */
    response = MHD_create_response_from_fd(stat_buf.st_size, fd);
    if (response == NULL) {
        close(fd);
        return MHD_NO;
    }

    /* Set MIME type */
    mime_type = get_mime_type(filename);
    if (mime_type != NULL) {
        MHD_add_response_header(response, "Content-Type", mime_type);
    }

    /* Queue response */
    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}

/* Determine MIME type based on file extension */
static char *get_mime_type(const char *filename) {
    char *ext = strrchr(filename, '.');
    int i;
    
    if (ext == NULL) {
        return "application/octet-stream";
    }
    
    for (i = 0; mime_types[i].extension != NULL; i++) {
        if (strcasecmp(ext, mime_types[i].extension) == 0) {
            return (char*)mime_types[i].mime_type;
        }
    }
    
    return "application/octet-stream";
}

/* Get the name of the interface used for the default route */
static void get_default_route_interface(char *interface, size_t size) {
    FILE *route_file;
    char line[BUFFER_SIZE];
    char *iface;
    
    /* Initialize with empty string */
    if (interface && size > 0) {
        interface[0] = '\0';
    }
    
    route_file = fopen("/proc/net/route", "r");
    if (!route_file) {
        return;
    }
    
    /* Skip the header line */
    if (fgets(line, sizeof(line), route_file) == NULL) {
        fclose(route_file);
        return;
    }
    
    /* Parse each line */
    while (fgets(line, sizeof(line), route_file)) {
        char iface_name[IF_NAMESIZE];
        unsigned int dest, gw;
        int num_fields;
        
        /* Parse the line for interface name, destination, and gateway */
        num_fields = sscanf(line, "%s %x %x", iface_name, &dest, &gw);
        
        /* If this is the default route (destination 0.0.0.0), use it */
        if (num_fields == 3 && dest == 0) {
            strncpy(interface, iface_name, size - 1);
            interface[size - 1] = '\0';
            break;
        }
    }
    
    fclose(route_file);
}

/* Check if an interface is inappropriate (mobile connection) */
static int is_inappropriate_interface(const char *interface, const char *ip_addr) {
    /* Check for mobile connection interface prefixes */
    if (strncmp(interface, "rmnet", 5) == 0 ||
        strncmp(interface, "umts", 4) == 0) {
        return 1;
    }
    
    /* Check for 10.0.0.0/24 address range */
    if (ip_addr && strncmp(ip_addr, "10.0.0.", 7) == 0) {
        return 1;
    }
    
    return 0;
}

/* Find valid IP addresses to broadcast */
static void find_ip_addresses() {
    struct ifaddrs *ifaddr, *ifa;
    char default_if[IF_NAMESIZE] = {0};
    int have_default_if_addr = 0;
    
    /* Get the default route interface */
    get_default_route_interface(default_if, sizeof(default_if));
    
    /* Get all network interfaces */
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    
    /* First, try to use the default interface if it's appropriate */
    if (default_if[0] != '\0') {
        for (ifa = ifaddr; ifa != NULL && !have_default_if_addr && num_urls < MAX_IPS; ifa = ifa->ifa_next) {
            char ip_str[INET6_ADDRSTRLEN];
            
            if (ifa->ifa_addr == NULL) continue;
            
            /* Skip non-matching interfaces */
            if (strcmp(ifa->ifa_name, default_if) != 0) continue;
            
            /* Skip interfaces that are not up or don't have a route */
            if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_RUNNING)) continue;
            
            /* Skip loopback */
            if (ifa->ifa_flags & IFF_LOOPBACK) continue;
            
            /* Process IPv4 address */
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in*)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
                
                /* Skip inappropriate interfaces */
                if (is_inappropriate_interface(ifa->ifa_name, ip_str)) continue;
                
                char *url = malloc(MAX_URL_LENGTH);
                if (url) {
                    snprintf(url, MAX_URL_LENGTH, "http://%s:%d", ip_str, port);
                    urls[num_urls++] = url;
                    have_default_if_addr = 1;
                }
            }
            /* Process IPv6 address */
            else if (ifa->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *addr = (struct sockaddr_in6*)ifa->ifa_addr;
                
                /* Skip link-local IPv6 addresses */
                if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) continue;
                
                inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, sizeof(ip_str));
                
                char *url = malloc(MAX_URL_LENGTH);
                if (url) {
                    snprintf(url, MAX_URL_LENGTH, "http://[%s]:%d", ip_str, port);
                    urls[num_urls++] = url;
                    have_default_if_addr = 1;
                }
            }
        }
    }
    
    /* If we couldn't use the default interface, try all other interfaces */
    if (!have_default_if_addr) {
        for (ifa = ifaddr; ifa != NULL && num_urls < MAX_IPS; ifa = ifa->ifa_next) {
            char ip_str[INET6_ADDRSTRLEN];
            
            if (ifa->ifa_addr == NULL) continue;
            
            /* Skip interfaces that are not up or don't have a route */
            if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_RUNNING)) continue;
            
            /* Skip loopback */
            if (ifa->ifa_flags & IFF_LOOPBACK) continue;
            
            /* Process IPv4 address */
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in*)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
                
                /* Skip inappropriate interfaces */
                if (is_inappropriate_interface(ifa->ifa_name, ip_str)) continue;
                
                char *url = malloc(MAX_URL_LENGTH);
                if (url) {
                    snprintf(url, MAX_URL_LENGTH, "http://%s:%d", ip_str, port);
                    urls[num_urls++] = url;
                }
            }
            /* Process IPv6 address - only if we don't have IPv4 */
            else if (ifa->ifa_addr->sa_family == AF_INET6 && num_urls == 0) {
                struct sockaddr_in6 *addr = (struct sockaddr_in6*)ifa->ifa_addr;
                
                /* Skip link-local IPv6 addresses */
                if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) continue;
                
                inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, sizeof(ip_str));
                
                char *url = malloc(MAX_URL_LENGTH);
                if (url) {
                    snprintf(url, MAX_URL_LENGTH, "http://[%s]:%d", ip_str, port);
                    urls[num_urls++] = url;
                }
            }
        }
    }
    
    /* Fall back to localhost if no interfaces found */
    if (num_urls == 0) {
        char *url = malloc(MAX_URL_LENGTH);
        if (url) {
            snprintf(url, MAX_URL_LENGTH, "http://127.0.0.1:%d", port);
            urls[num_urls++] = url;
        }
    }
    
    freeifaddrs(ifaddr);
}

#ifdef USE_QRCODE
/* Print a QR code to the terminal */
static void print_qrcode(const char *url) {
    QRcode *qrcode;
    int x, y;

    qrcode = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (qrcode == NULL) {
        fprintf(stderr, "Failed to generate QR code\n");
        return;
    }

    /* Print top quiet zone */
    printf("\n");
    for (x = 0; x < qrcode->width + 4; x++) {
        printf("  ");
    }
    printf("\n");

    /* Print QR code with quiet zone on the sides */
    for (y = 0; y < qrcode->width; y++) {
        printf("  "); /* Left quiet zone */
        printf("  ");
        
        for (x = 0; x < qrcode->width; x++) {
            unsigned char dot = qrcode->data[y * qrcode->width + x] & 1;
            if (dot) {
                printf("\033[40m  \033[0m"); /* Black */
            } else {
                printf("\033[47m  \033[0m"); /* White */
            }
        }
        
        printf("  "); /* Right quiet zone */
        printf("\n");
    }

    /* Print bottom quiet zone */
    for (x = 0; x < qrcode->width + 4; x++) {
        printf("  ");
    }
    printf("\n");

    QRcode_free(qrcode);
}
#endif

/* Print the URLs where the file is being shared */
static void print_urls() {
    int i;
    
    if (num_urls == 0) {
        printf("Could not determine any network addresses.\n");
        return;
    }
    
    printf("Sharing file '%s' at:\n", filename);
    
    for (i = 0; i < num_urls; i++) {
        printf("%s\n", urls[i]);
        
#ifdef USE_QRCODE
        print_qrcode(urls[i]);
#endif
    }
}
