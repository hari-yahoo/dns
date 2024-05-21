#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define DNS_PORT 53
#define BUFFER_SIZE 512
#define PUBLIC_DNS "8.8.8.8"  // Google Public DNS

// DNS header structure
struct DNSHeader {
    unsigned short id; // Identification number

    unsigned char rd :1; // Recursion desired
    unsigned char tc :1; // Truncated message
    unsigned char aa :1; // Authoritative answer
    unsigned char opcode :4; // Purpose of message
    unsigned char qr :1; // Query/Response flag

    unsigned char rcode :4; // Response code
    unsigned char cd :1; // Checking disabled
    unsigned char ad :1; // Authenticated data
    unsigned char z :1; // Reserved
    unsigned char ra :1; // Recursion available

    unsigned short q_count; // Number of question entries
    unsigned short ans_count; // Number of answer entries
    unsigned short auth_count; // Number of authority entries
    unsigned short add_count; // Number of resource entries
};

// DNS question structure
struct DNSQuestion {
    unsigned short qtype;
    unsigned short qclass;
};

// Function to parse DNS name
void parse_dns_name(unsigned char *reader, unsigned char *buffer, char *name) {
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    name[0] = '\0';

    while (*reader != 0) {
        if (*reader >= 192) { // Pointer
            offset = (*reader) * 256 + *(reader + 1) - 49152; // Calculate the offset
            reader = buffer + offset - 1;
            jumped = 1; // We have jumped to another location
        } else {
            name[p++] = *reader;
        }
        reader++;
    }

    name[p] = '\0'; // Null-terminate the name
}

// Function to forward DNS query to public DNS server
int forward_dns_query(unsigned char *query, int query_len, unsigned char *response, struct sockaddr_in *client_addr) {
    int sockfd;
    struct sockaddr_in dest;
    socklen_t len = sizeof(dest);

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Setup destination address structure
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr.s_addr = inet_addr(PUBLIC_DNS);

    // Send DNS query to public DNS server
    if (sendto(sockfd, query, query_len, 0, (struct sockaddr *)&dest, len) < 0) {
        perror("Send to public DNS failed");
        close(sockfd);
        return -1;
    }

    // Receive DNS response
    int response_len = recvfrom(sockfd, response, BUFFER_SIZE, 0, NULL, NULL);
    if (response_len < 0) {
        perror("Receive from public DNS failed");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return response_len;
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char response[BUFFER_SIZE];
    socklen_t client_len = sizeof(client_addr);

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Setup server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);

    // Bind the socket to the address and port
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DNS server started on port %d\n", DNS_PORT);

    while (1) {
        // Receive DNS query
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (n < 0) {
            perror("Receive failed");
            continue;
        }

        // Process DNS query
        struct DNSHeader *dns = (struct DNSHeader *)buffer;
        unsigned char *qname = (unsigned char *)&buffer[sizeof(struct DNSHeader)];
        char name[256];

        parse_dns_name(qname, buffer, name);
        printf("Received DNS query for: %s\n", name);

        // Filter requests (example: block "example.com")
        if (strcmp(name, "example.com") == 0) {
            printf("Blocked request for: %s\n", name);
            continue;
        }

        // Forward query to public DNS server
        int response_len = forward_dns_query(buffer, n, response, &client_addr);
        if (response_len < 0) {
            printf("Failed to forward query for: %s\n", name);
            continue;
        }

        // Send DNS response back to the client
        if (sendto(sockfd, response, response_len, 0, (struct sockaddr *)&client_addr, client_len) < 0) {
            perror("Send failed");
        }
    }

    close(sockfd);
    return 0;
}
