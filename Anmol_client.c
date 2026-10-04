// RFMP - C client (unencrypted, openRead only)
// Group members: 
// Anmol Preet Singh
// Ahmed Elshennawy
// Aditya Kadhi
// Shubhi Attal
//
// This client connects,

// do the Start-Packet handshake, ask the user for a file, read it back,
// then send the End packet and close.

#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")   // needed so the linker finds Winsock

#define SERVER_IP   "127.0.0.1"   // change once we know the real server IP
#define SERVER_PORT 2040          // matches Server.py's PORT = 2040

// Reads one full packet from the socket, stopping at the '\n' that marks
// the end of every packet (per PROTOCOL.txt). Reading one byte at a time
// like this is slow, but it's simple and makes sure we never accidentally
// read past the end of this packet into the start of the next one.
// Returns 1 on success, 0 if the server hung up early, -1 on error.
int recvPacket(SOCKET sock, char *outBuf, int outBufSize) {
    int total = 0;
    while (total < outBufSize - 1) {
        char c;
        int n = recv(sock, &c, 1, 0);
        if (n == 0) {
            outBuf[total] = '\0';
            return total > 0 ? 1 : 0;      // server closed before finishing a packet
        } else if (n < 0) {
            return -1;
        }
        if (c == '\n') {
            break;                          // found the end of this packet
        }
        outBuf[total++] = c;
    }
    outBuf[total] = '\0';
    return 1;
}

// A Data Packet looks like: (DP, <file text>)
// This strips the "(DP, " prefix and the trailing ")" so we're left with
// just the file text itself. Modifies and returns a pointer into packet.
char *parseDataPacket(char *packet) {
    char *start = strchr(packet, ',');     // find the comma after "(DP"
    if (start == NULL) return packet;       // unexpected format - just show it raw
    start++;                                 // move past the comma
    while (*start == ' ') start++;          // skip the space after the comma

    int len = (int)strlen(start);
    if (len > 0 && start[len - 1] == ')') {
        start[len - 1] = '\0';              // chop off the trailing ')'
    }
    return start;
}

// Decodes a base64 string into out. Returns the number of bytes written,
// or -1 if out isn't big enough. The server always base64-encodes file
// content (even unencrypted) to keep commas/newlines from breaking the
// packet format, so this has to run on whatever we read back before
// it's actually readable.
int base64Decode(const char *in, unsigned char *out, int outSize) {
    static const char *alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int table[256];
    for (int i = 0; i < 256; i++) table[i] = -1;
    for (int i = 0; i < 64; i++) table[(unsigned char)alphabet[i]] = i;
 
    int len = (int)strlen(in);
    int outLen = 0;
    int val = 0, bits = -8;
 
    for (int i = 0; i < len; i++) {
        char c = in[i];
        if (c == '=') break;                            // padding marks the end of real data
        if (table[(unsigned char)c] == -1) continue;      // skip anything unexpected
 
        val = (val << 6) + table[(unsigned char)c];
        bits += 6;
        if (bits >= 0) {
            if (outLen >= outSize) return -1;              // output buffer too small
            out[outLen++] = (unsigned char)((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return outLen;
}

int main(void) {

    // Windows needs Winsock turned on before we can use any socket
    // functions at all - this is just the setup step for that.
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    // Create the socket - basically our "phone" for talking over the network.
    // AF_INET = IPv4, SOCK_STREAM = TCP (reliable, ordered byte stream)
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Set up the address we're connecting to (server IP + port), then connect.
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));             // zero it out first, just to be safe
    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);             // htons puts the port in the byte order networks expect
    server.sin_addr.s_addr = inet_addr(SERVER_IP);    // turns "127.0.0.1" into the binary form sockets need

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Connected to server!\n");

    // Ask the user what file they want instead of hardcoding one -
    // the assignment wants the client to give the user actual options.
    char filename[256];
    printf("Enter the filename to read: ");
    fgets(filename, sizeof(filename), stdin);

    // fgets grabs the Enter key's newline too, so I have to strip it off
    // or it ends up stuck inside the packet text below.
    filename[strcspn(filename, "\n")] = '\0';

    // Setup-Phase: send the Start-Packet.
    // (SS, RFMP, v1.0, 0) -> packet type, protocol name, version, security=0
    // (this client never encrypts, so security is always 0)
    // spacing after each comma matches PROTOCOL.txt exactly
    const char *startPacket = "(SS, RFMP, v1.0, 0)\n";
    send(sock, startPacket, (int)strlen(startPacket), 0);

    // Now read the server's reply - should just be (CC) since security is off.
    // Using recvPacket so this works even if the reply arrives in more
    // than one chunk - it keeps reading until it sees the '\n'.
    char buf[65536];
    int result = recvPacket(sock, buf, sizeof(buf));
    if (result == 1) {
        printf("Server replied: %s\n", buf);
    } else if (result == 0) {
        printf("Server closed the connection unexpectedly.\n");
    } else {
        printf("recv() failed: %d\n", WSAGetLastError());
    }

    // Now send the actual openRead request, built using whatever
    // filename the user typed in above. Spacing matches PROTOCOL.txt.
    char readRequest[300];
    snprintf(readRequest, sizeof(readRequest), "(CM, openRead, %s)\n", filename);
    send(sock, readRequest, (int)strlen(readRequest), 0);

    // Read the server's reply to openRead. Per PROTOCOL.txt this is one
    // packet ending in '\n' - either (DP, text) with the file contents,
    // or (EE, code, description) if something went wrong (e.g. file not
    // found). The connection stays open either way, so we do NOT wait
    // for the server to hang up like before.
    result = recvPacket(sock, buf, sizeof(buf));
    if (result == 1) {
                if (strncmp(buf, "(EE", 3) == 0) {
            printf("\nServer reported an error: %s\n", buf);
        } else {
            char *fileText = parseDataPacket(buf);

            unsigned char decoded[65536];
            int decodedLen = base64Decode(fileText, decoded, sizeof(decoded) - 1);

            if (decodedLen >= 0) {
                decoded[decodedLen] = '\0';
                printf("\n--- File contents ---\n%s\n--- End of file ---\n", decoded);
            } else {
                printf("\n--- File contents (could not decode) ---\n%s\n--- End of file ---\n", fileText);
            }
        }
    } else if (result == 0) {
        printf("Server closed the connection before replying.\n");
    } else {
        printf("recv() failed: %d\n", WSAGetLastError());
    }

    // Closing-Phase: let the server know I'm done.
    // PROTOCOL.txt specifies this packet has NO parentheses - just "End".
    const char *endPacket = "End\n";
    send(sock, endPacket, (int)strlen(endPacket), 0);

    // clean up - close the socket and shut Winsock back down
    closesocket(sock);
    WSACleanup();
    return 0;
}


   