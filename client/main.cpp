#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <cstring>
#include <regex>
#include <arpa/inet.h>
#define PORT 7777
#define SERVER_IP_ADDRESS "127.0.0.1"

class Segment {
  /*TODO: It carries the origin, port number of the destination, port of the
   * source and payload.*/
};
class Datagram {
  /*TODO: Implement the logic to handle the datagram, which have the source IP
   * address, the destination IP address and a segment.*/
};

int main() {
  std::string command = "", ip_address = "", file_name = "", get_request = "";
  std::regex ip_pattern("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");
  struct sockaddr_in server_addr;
  socklen_t len = 0;
  in_addr_t ip_addr_num = 0;
  int client_socket = socket(AF_INET, SOCK_DGRAM, 0), port = 0, n = 0, at_pos = 0;
  char buffer[1024] = {0};

  if (client_socket == -1){
    std::cerr << "Error creating socket" << std::endl;
    close(client_socket);
    return -1;
  }

  std::cout << "Enter your request: ";
  std::getline(std::cin >> std::ws, command);

  size_t p1 = command.find('.');
  size_t p2 = command.find('.', p1 + 1);
  size_t p3 = command.find('.', p2 + 1);
  get_request = command.substr(0, 3);
  at_pos = command.find('@');

  int o1 = std::stoi(command.substr(at_pos + 1, p1-(at_pos + 1)));
  int o2 = std::stoi(command.substr(p1 + 1, p2 - (p1 + 1)));
  int o3 = std::stoi(command.substr(p2 + 1, p3 - (p2 + 1)));
  int o4 = std::stoi(command.substr(p3 + 1));

  ip_address = std::to_string(o1) + "." + std::to_string(o2) + "." + std::to_string(o3) + "." + std::to_string(o4);
  size_t port_pos_0 = command.find(':') + 1;
  size_t port_pos_end = command.find('/', port_pos_0);
  port = std::stoi(command.substr(port_pos_0, port_pos_end - port_pos_0));

  if (get_request != "GET"){
    std::cerr << "Invalid command." << std::endl;
    close(client_socket);
    return -1;
  }

  std::cout << "command: " << command << std::endl;
  size_t p4 = command.find('/');
  size_t command_size = command.length();
  size_t file_nm_size = command_size - (p4 + 1);
  std::cout << "file_nm_size: " << file_nm_size << std::endl;
  for (int i = 0; i < file_nm_size; i++){
    file_name += command[p4 + i + 1];
  }

  if (!std::regex_match(ip_address, ip_pattern)){
    std::cerr << "Invalid pattern of IP address." << std::endl;
    close(client_socket);
    return -1;
  }

  if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255) {
    std::cerr << "Invalid IP address: octet exceeds 255." << std::endl;
    close(client_socket);
    return -1;
  }

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

  ip_addr_num = (in_addr_t) inet_addr(ip_address.c_str());
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = ip_addr_num;
  const char* command_c = command.c_str();

  sendto(client_socket, (const char*)command_c, strlen(command_c), MSG_CONFIRM,
          (struct sockaddr*)&server_addr, sizeof(server_addr));

  std::cout << "file_name: " << file_name << std::endl;

  len = sizeof(server_addr);
  n = recvfrom(client_socket, (char*)buffer, 1024, MSG_WAITALL, (struct sockaddr*)&server_addr, &len);
  buffer[n] = '\0';

  std::cout << buffer << std::endl;
  // std::cout << "Server address: " << server_addr.sin_addr.s_addr << std::endl;
  // std::cout << "Server port: " << ntohs(server_addr.sin_port) << std::endl;
  close(client_socket);

  return 0;
}

void losing_segments(void) {
  /*TODO: Implement the function that will lose some segments and show the IDs
   * of which ones are lost*/
  return;
}
