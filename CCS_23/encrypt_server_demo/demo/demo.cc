// libgcrypt DSE demo
// Yufei Du <yufeidu@cs.unc.edu>

#include <arpa/inet.h>
// #include "gcry.hh"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>

#include "hydrogen.h"

int init_net (uint16_t port);
void *process_client(void *args);

static int info_set; // Flag to ensure info is only set once

int hex_to_str(uint8_t hex[], char* str, int hex_size) {
    int i;
    char temp_buf[32];
    // Convert crypto to printable format
    for (i = 0; i < hex_size; i++) {
        sprintf(temp_buf, "%02x", (unsigned char) hex[i]);
        strcat(str, temp_buf);
        memset(temp_buf, '\0', 32);
    }
    return 0;
}

int str_to_hex(char* str, uint8_t hex[], int str_size) {
    int i;
    char temp_buf[32];
    memset(temp_buf, '\0', 32);
    // Convert the string to hex
    for (i = 0; i < str_size / 2; i++) {
        temp_buf[0] = str[2*i];
        temp_buf[1] = str[2*i+1];
        hex[i] = (unsigned char) strtoul(temp_buf, NULL, 16);
    }
    return 0;
}

int main(int argc, char** argv) {
    // gcry_cipher_hd_t encryptor, decryptor;
    int sock, client_sock;
    socklen_t client_size;
    // size_t msg_size, response_size;
    struct sockaddr_in client_name;
    // char msg[1024], response_msg[1024], gcry_buf[512], temp_buf[32];
    // char *payload;
    // void *info; // The pretended info which lives on tempPtr - 64
    pthread_t temp_thread;

    info_set = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    

    // Set up socket
    sock = init_net(atoi(argv[1]));

    // Listen to socket
    // We don't deal with multi-client mess in the demo
    if (listen(sock, 1) < 0) {
        perror("listen");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Ready for connection at port %s\n", argv[1]);

    client_size = sizeof(client_name);
    // Start a thread for each client
    while (1) {
        client_sock = accept(sock, (struct sockaddr *) &client_name, &client_size);

        if (client_sock < 0) {
            perror("accept");
            close(sock);
            exit(EXIT_FAILURE);
        }

        printf("Connected: %s:%i\n", inet_ntoa(client_name.sin_addr), ntohs(client_name.sin_port));

        if (!pthread_create(&temp_thread, NULL, process_client, &client_sock)) {
            // Detach the thread to do its own work
            pthread_detach(temp_thread);
        } else {
            perror("pthread");
            close(client_sock);
            close(sock);
            exit(EXIT_FAILURE);
        }
    }
    

    

    printf("Shutting down the connection\n");

    close(client_sock);
    close(sock);
    return 0;

}

int init_net(uint16_t port) {
    int sock;
    struct sockaddr_in name;

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror ("socket");
        exit (EXIT_FAILURE);
    }

    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *) &name, sizeof (name)) < 0)
    {
        perror("bind");
        exit (EXIT_FAILURE);
    }

    return sock;
}

void *process_client(void *args) {
    char context[9];
    uint8_t key[hydro_secretbox_KEYBYTES], ciphertext[hydro_secretbox_HEADERBYTES + 1024];
    int client_sock, cond, i, j, initialized = 0;
    size_t msg_size, response_size;
    char msg[1024], response_msg[1024], gcry_buf[512], temp_buf[32];
    char *payload;

    // Get argument
    client_sock = *(int*)args;
    
    // Loop for infinite client messages
    cond = 1;
    while (cond) {
        // Clear msg
        memset(msg, '\0', 1024);
        memset(response_msg, '\0', 1024);
        memset(gcry_buf, '\0', 512);
        memset(temp_buf, '\0', 32);
        memset(ciphertext, '\0', hydro_secretbox_HEADERBYTES + 1024);
        msg_size = recv(client_sock, msg, 1024, 0);
        if (msg_size <= 0) {
            perror("recv");
            close(client_sock);
            return (void*) EXIT_FAILURE;
        }

        printf("DEBUG: Message received %s\n", msg);
        
        // Ignore empty message or messages without all fields
        if (msg_size < 3 && msg[0] != 'q' && msg[0] != 'p') {
            continue;
        }
        payload = msg + 1;
        // Decide action based on msg
        switch(msg[0]) {
            // Set context
            case 's':
                if (strlen(payload) != 8) {
                    strcpy(response_msg, "ERROR: Context must be 8 characters");
                    response_size = strlen(response_msg);
                    break;
                }
                strncpy(context, payload, 8); // Context needs to be exactly 8 characters

                // Enable flag
                initialized = 1;

                strcpy(response_msg, "SUCCESS");
                response_size = strlen(response_msg);
                break;
            // Generate password
            case 'p':
                // Empty payload == generate new password
                if (strlen(payload) == 0) {
                    hydro_secretbox_keygen(key);
                    hex_to_str(key, response_msg, hydro_secretbox_KEYBYTES);
                } else {
                    str_to_hex(payload, key, strlen(payload));
                    strcpy(response_msg, "SUCCESS");
                }
                response_size = strlen(response_msg);
                break;
            // Encrypt message
            case 'e':
                if (!initialized) {
                    // Early failure
                    strcpy(response_msg, "ERROR: You must set password before encryption/decryption!\n");
                    response_size = strlen(response_msg);
                    break;
                }
                hydro_secretbox_encrypt(ciphertext, payload, strlen(payload), 0, context, key);

                // memcpy(gcry_buf, payload, strlen(payload));
                // if (gcry_cipher_encrypt(encryptor, gcry_buf, 512, NULL, 0)) {
                //     perror("encrypt");
                //     strcpy(response_msg, "ERROR");
                // }
                // Determine the size of the crypto
                for (i = 0; i < 512; i++) {
                    if (ciphertext[i] != '\0')
                        continue;
                    for (j = i; j < 512; j++){
                        if (ciphertext[j] != '\0')
                            break;
                    }
                    if (j == 512) {
                        j = i;
                        break;
                    }
                }

                // Convert crypto to printable format
                for (i = 0; i < j; i++) {
                    sprintf(temp_buf, "%02x", (unsigned char) ciphertext[i]);
                    strcat(response_msg, temp_buf);
                }
                response_size = strlen(response_msg);
                // // Reset the handle
                // gcry_cipher_reset(encryptor);
                break;
            // Decrypt message
            case 'd':
                if (!initialized) {
                    // Early failure
                    strcpy(response_msg, "ERROR: You must set password before encryption/decryption!\n");
                    response_size = strlen(response_msg);
                    break;
                }
                // Encrypted text must be an even number
                if (strlen(payload) % 2 != 0) {
                    fprintf(stderr, "Illegal encrypted text size %lu\n", strlen(payload));
                    strcpy(response_msg, "ERROR");
                } else {
                    // First convert the string to hex
                    for (i = 0; i < strlen(payload) / 2; i++) {
                        temp_buf[0] = payload[2*i];
                        temp_buf[1] = payload[2*i+1];
                        ciphertext[i] = strtoul(temp_buf, NULL, 16);
                    }
                    if (hydro_secretbox_decrypt(response_msg, ciphertext, i, 0, context, key)) {
                        fprintf(stderr, "Failed to decrypt message\n");
                        strcpy(response_msg, "ERROR");
                    }
                    // if (gcry_cipher_decrypt(decryptor, response_msg, 1024, gcry_buf, 512)) {
                    //     perror("decrypt");
                    //     strcpy(response_msg, "ERROR");
                    // }
                }
                response_size = strlen(response_msg);
                printf("Decryption msg: %s\n", response_msg);
                // // Reset the handle
                // gcry_cipher_reset(decryptor);
                break;
            // Quit connection
            case 'q':
                cond = 0;
                strcpy(response_msg, "bye");
                response_size = strlen(response_msg);
                break;
            default:
                fprintf(stderr, "Unknown message: %s\n", msg);
        }
        // Send response unless the command is quit
        if (send(client_sock, response_msg, response_size, 0) < 0) {
            perror("send");
            close(client_sock);
            return (void*) EXIT_FAILURE;
        }

        // Close client port if the session ends
        if (!cond) {
            close(client_sock);
        }
    }
    return (void*) EXIT_SUCCESS;
}