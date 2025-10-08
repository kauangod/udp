#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <string>
#include <sys/socket.h>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <cstring>
#include <regex>
#include <arpa/inet.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#define PORT 7777
#define SERVER_IP_ADDRESS "127.0.0.1"
#define BYTES_PER_SEGMENT 1024
#define TIMEOUT 10000000

class Segment{
public:
    std::string dst_port, src_port, payload, hash;
    int id;
    size_t length;

    Segment(std::string dst_port = "7777", std::string src_port = "7777", std::string payload = std::string(), int id = 0){
        this->dst_port = dst_port;
        this->src_port = src_port;
        this->payload = payload;
        // std::cout << "segment payload: " << this->payload.data() << std::endl;
        this->id = id;
        this->setHash();
        // std::cout << "segment hash: " << this->hash << std::endl;
        this->length = sizeof(payload) + sizeof(id) + sizeof(hash) + sizeof(dst_port) + sizeof(src_port);
    }
    ~Segment(){
        payload.clear();
    }
    std::string generateHash(){
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, this->payload.c_str(), this->payload.size());
        SHA256_Final(hash, &sha256);

        std::stringstream ss;

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++){
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        return ss.str();
    }
    bool checkHash(std::string originalHash, std::string receivedHash){
        return originalHash == receivedHash;
    }
    void setHash(){
        this->hash = generateHash();
    }
};
class Datagram{
public:
    Segment* segment;
    std::string src_ip, dst_ip;
    Datagram(std::string src_ip = "127.0.0.1", std::string dst_ip = "127.0.0.1"){
      this->src_ip = src_ip;
      this->dst_ip = dst_ip;
      this->segment = nullptr;
    }
    ~Datagram(){
        delete segment;
    }
    void add_segment(Segment* segment){
        this->segment = segment;
    }
};

int parse_command(std::string command, int* o1, int* o2, int* o3, int* o4){
  size_t p1 = command.find('.');
  size_t p2 = command.find('.', p1 + 1);
  size_t p3 = command.find('.', p2 + 1);

  int at_pos = command.find('@');

  *o1 = std::stoi(command.substr(at_pos + 1, p1-(at_pos + 1)));
  *o2 = std::stoi(command.substr(p1 + 1, p2 - (p1 + 1)));
  *o3 = std::stoi(command.substr(p2 + 1, p3 - (p2 + 1)));
  *o4 = std::stoi(command.substr(p3 + 1));

  if (*o1 > 255 || *o2 > 255 || *o3 > 255 || *o4 > 255) {
    return -1;
  }
  return 0;
}

void losing_segments(void) {
  /*TODO: Implement the function that will lose some segments and show the IDs
   * of which ones are lost*/
  return;
}

int main() {
  std::string command = "", ip_address = "", file_name = "", request = "";
  std::regex ip_pattern("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");
  struct sockaddr_in server_addr;
  socklen_t len = 0;
  in_addr_t ip_addr_num = 0;
  int client_socket = socket(AF_INET, SOCK_DGRAM, 0), port = 0, n = 1, o1 = 0, o2 = 0, o3 = 0, o4 = 0;
  char buffer[BYTES_PER_SEGMENT] = {0};
  std::string buffer_for_file_str = "";
  Datagram* datagram = nullptr;

  if (client_socket == -1){
    std::cerr << "Error creating socket" << std::endl;
    close(client_socket);
    return -1;
  }

  std::cout << "Enter your request: ";
  std::getline(std::cin >> std::ws, command);

  if (parse_command(command, &o1, &o2, &o3, &o4) == -1) {
    std::cerr << "Invalid IP address: octet exceeds 255." << std::endl;
    close(client_socket);
    return -1;
  }

  ip_address = std::to_string(o1) + "." + std::to_string(o2) + "." + std::to_string(o3) + "." + std::to_string(o4);

  if (!std::regex_match(ip_address, ip_pattern)){
    std::cerr << "Invalid pattern of IP address." << std::endl;
    close(client_socket);
    return -1;
  }

  size_t port_pos_0 = command.find(':') + 1;
  size_t port_pos_end = command.find('/', port_pos_0);
  port = std::stoi(command.substr(port_pos_0, port_pos_end - port_pos_0));

  if (port < 1024 || port > 65535) {
    std::cerr << "Invalid port number." << std::endl;
    close(client_socket);
    return -1;
  }
  else if (port != PORT or ip_address != SERVER_IP_ADDRESS){
    std::cerr << "Connection timeout." << std::endl;
    close(client_socket);
    return -1;
  }
  request = command.substr(0, 3);
  if (request != "GET"){
    std::cerr << "Invalid command." << std::endl;
    close(client_socket);
    return -1;
  }

  // std::cout << "command: " << command << std::endl;
  size_t p4 = command.find('/');
  size_t command_size = command.length();
  size_t file_nm_size = command_size - (p4 + 1);

  for (int i = 0; i < file_nm_size; i++){
    file_name += command[p4 + i + 1];
  }

  std::ifstream existing_file_check(file_name, std::ios::binary);

  if (existing_file_check.good()){
    existing_file_check.close();
    std::remove(file_name.c_str());
  }


  ip_addr_num = (in_addr_t) inet_addr(ip_address.c_str());
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = ip_addr_num;
  const char* command_c = command.c_str();

  len = sizeof(server_addr);
  clock_t start = clock();

  while(recvfrom(client_socket, buffer, 4, MSG_DONTWAIT, (struct sockaddr*)&server_addr, &len) != 3 && memcmp(buffer, "ACK", 3) != 0){
    sendto(client_socket, "SYNC", 4, 0,
           (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (clock() - start > TIMEOUT){
      std::cerr << "Connection timeout." << std::endl;
      close(client_socket);
      return -1;
    }
  }

  sendto(client_socket, (const char*)command_c, strlen(command_c), 0,
        (struct sockaddr*)&server_addr, sizeof(server_addr));

  char buffer_for_file[BYTES_PER_SEGMENT];


  // std::cout << "Server address: " << inet_ntoa(server_addr.sin_addr) << std::endl;
  // std::cout << "Server port: " << ntohs(server_addr.sin_port) << std::endl;
  // Configure a receive timeout to avoid infinite blocking and avoid DONTWAIT corruption

  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  std::ofstream file(file_name, std::ios::binary);

  for(;;){
    n = recvfrom(client_socket, buffer_for_file, BYTES_PER_SEGMENT, 0, (struct sockaddr*)&server_addr, &len);
    if (n == 0) break;
    if (memcmp(buffer_for_file, "ACK", 3) == 0) continue;
    file.write(buffer_for_file, n);
  }

  file.close();
  close(client_socket);

  return 0;
}


