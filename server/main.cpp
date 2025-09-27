#include <iostream>
#include <string>
#include <vector>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fstream>
#define PORT 7777
#define BYTES_PER_SEGMENT 1024

class Segment{
public:
    std::string dst_port, src_port, payload, hash;
    int id;

    Segment(int dst_port = PORT, int src_port = PORT, std::string payload = std::string(), int id = 0){
        this->dst_port = dst_port;
        this->src_port = src_port;
        this->payload = payload;
        // std::cout << "segment payload: " << this->payload.data() << std::endl;
        this->id = id;
        this->setHash();
        // std::cout << "segment hash: " << this->hash << std::endl;
    }
    ~Segment(){
        payload.clear();
    }
    void setHash(){
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, this->payload.c_str(), this->payload.size());
        SHA256_Final(hash, &sha256);

        std::stringstream ss;

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++){
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        this->hash = ss.str();
    }
};
class Datagram{
public:
    Segment* segment;
    std::string src_ip, dst_ip;

    Datagram(std::string src_ip = "127.0.0.1", std::string dst_ip = "127.0.0.1"){
        this->segment = nullptr;
        this->src_ip = src_ip;
        this->dst_ip = dst_ip;
    }
    ~Datagram(){
        delete segment;
    }
    void add_segment(Segment* segment){
        this->segment = segment;
    }
};

void losing_segments(void){
    /*TODO: Implement the function that will lose some segments and show the IDs of which ones are lost*/
    return;
}
std::string return_file_name(std::string buffer){
    size_t file_pos_0 = buffer.find('/') + 1;
    size_t file_pos_end = buffer.length() - file_pos_0;

    return buffer.substr(file_pos_0, file_pos_end - file_pos_0);
}

int main() {
    int server_socket = socket(AF_INET, SOCK_DGRAM, 0), client_socket = -1, n = 0, id = 0;
    const char* ip_address = "127.0.0.1";
    const char* message = "Hello, client!";
    char buffer[1024] = {0};
    struct sockaddr_in server_addr, client_addr;
    socklen_t len = 0;
    in_addr_t ip_addr_num = inet_addr(ip_address);
    std::vector<Segment*> segments;
    Segment* segment = nullptr;

    if (server_socket == -1){
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = ip_addr_num;

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0){
        std::cerr << "Error binding socket" << std::endl;
        close(server_socket);
        return -1;
    }
    while(true){
        len = sizeof(client_addr);
        n = 0;

        while(n == 0){
            n = recvfrom(server_socket, (char*) buffer, sizeof(buffer), 0, (struct sockaddr*) &client_addr, &len);
        }

        //  std::cout << "Client address: " << inet_ntoa(client_addr.sin_addr) << std::endl;
        //  std::cout << "Client port: " << ntohs(client_addr.sin_port) << std::endl;

        buffer[n] = '\0';
        // std::cout << buffer << std::endl;

        std::string buffer_str = buffer;
        std::string file_name = return_file_name(buffer_str);
        std::ifstream file(file_name, std::ios::binary);

        if (!file.is_open()){
            message = "File not found";
            sendto(server_socket, (const char*) message, strlen(message), MSG_CONFIRM, (struct sockaddr*) &client_addr, len);
            close(server_socket);
            return -1;
        }

        std::string seg_payload(BYTES_PER_SEGMENT, '\0');

        while(file){
            file.read(seg_payload.data(), BYTES_PER_SEGMENT);
            std::streamsize bytes_read = file.gcount();

            if (bytes_read <= 0) break;

            segment = new Segment(ntohs(client_addr.sin_port), PORT, std::string(seg_payload.data(), bytes_read), id++);
            segments.push_back(segment);
            //std::cout << "segment payload: " << segment->payload.data() << std::endl;
            //std::cout.write(seg_payload.data(), bytes_read);
            //std::cout << std::endl;
        }


        Datagram* datagram = new Datagram(ip_address, inet_ntoa(client_addr.sin_addr));
        // std::cout << "Client socket: " << client_socket << std::endl;
        // std::cout << "Client address: " << datagram->dst_ip << std::endl;
        int i = 0;
        size_t buffer_size, number_of_bytes = 0;

        while(i < segments.size()){
            datagram->add_segment(segments[i++]);
            buffer_size = datagram->segment->payload.size();
            char* buffer_for_file = new char[buffer_size];
            std::string payload(datagram->segment->payload.c_str(), datagram->segment->payload.size());
            // std::cout << "payload: " << datagram->segment->payload.data() << std::endl;
            //std::cout << "buffer_size: " << buffer_size << std::endl;
            memcpy(buffer_for_file, payload.data(), buffer_size);
            number_of_bytes = sendto(server_socket, buffer_for_file, buffer_size, MSG_CONFIRM, (struct sockaddr*) &client_addr, len);
            if (number_of_bytes == -1){
                std::cerr << "Error sending file to client" << std::endl;
                close(server_socket);
                return -1;
            }
            else{
                std::cout << "Bytes sent: " << number_of_bytes << std::endl;
            }
            delete[] buffer_for_file;
        }
        std::cout << "File sent successfully" << std::endl;
        delete datagram;
        segments.clear();
        file.close();
    }

    close(server_socket);


    return 0;
}


