#include <iostream>
#include <string>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fstream>
#define PORT 7777

class Segment{
/*TODO: It carries the origin, port number of the destination, port of the source and payload.*/
};
class Datagram{
    /*TODO: Implement the logic to handle the datagram, which have the source IP address, the destination IP address and a segment.*/
};

int main() {
    int server_socket = socket(AF_INET, SOCK_DGRAM, 0), client_socket = -1, n = 0;
    const char* ip_address = "127.0.0.1";
    const char* message = "Hello, client!";
    char buffer[1024] = {0};
    struct sockaddr_in server_addr, client_addr;
    socklen_t len = 0;
    in_addr_t ip_addr_num = inet_addr(ip_address);

    if (server_socket == -1){
        std::cerr << "Error creating socket" << std::endl;
        close(server_socket);
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = ip_addr_num;

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1){
        std::cerr << "Error binding socket" << std::endl;
        close(server_socket);
        return -1;
    }

    len = sizeof(client_addr);
    n = recvfrom(server_socket, (char*) buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr*) &client_addr, &len);
    buffer[n] = '\0';
    std::cout << buffer << std::endl;

    std::string buffer_str = buffer;
    size_t file_pos_0 = buffer_str.find('/') + 1;
    size_t file_pos_end = buffer_str.length() - file_pos_0;
    std::string file_name = buffer_str.substr(file_pos_0, file_pos_end - file_pos_0);
    std::ifstream file(file_name);

    if (!file.is_open()){
        message = "File not found";
        sendto(server_socket, (const char*) message, strlen(message), MSG_CONFIRM, (struct sockaddr*) &client_addr, len);
        close(server_socket);
        return -1;
    }
    // std::cout << "Client socket: " << client_socket << std::endl;
    // std::cout << "Client address: " << client_addr.sin_addr.s_addr << std::endl;
    // std::cout << "Client port: " << client_addr.sin_port << std::endl;
    sendto(server_socket, (const char*) message, strlen(message), MSG_CONFIRM, (struct sockaddr*) &client_addr, len);
    file.close();

    return 0;
}

void losing_segments(void){
    /*TODO: Implement the function that will lose some segments and show the IDs of which ones are lost*/
    return;
}
