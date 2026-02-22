#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <regex>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define ACK_SIZE 3
#define PORT 7777
#define SERVER_IP_ADDRESS "127.0.0.1"
#define BYTES_PER_SEGMENT 1024
#define MAX_BUFFER_SIZE 4096

std::string compute_sha256(const std::string &path,
                           const std::string *content = nullptr) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  if (!ctx)
    throw std::runtime_error("erro ao criar o contexto");

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
    throw std::runtime_error("erro no digestInit");

  if (content) {
    if (EVP_DigestUpdate(ctx, content->data(), content->size()) != 1)
      throw std::runtime_error("erro no digestUpdate");
  } else {
    std::ifstream f(path, std::ios::binary);

    if (!f)
      throw std::runtime_error("erro ao abrir o arquivo");

    char buf[4096];
    while (f.good()) {
      f.read(buf, sizeof(buf));
      std::streamsize s = f.gcount();
      if (s > 0) {
        if (EVP_DigestUpdate(ctx, buf, s) != 1)
          throw std::runtime_error("erro no digestUpdate");
      }
    }
  }

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len = 0;

  if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1)
    throw std::runtime_error("erro no digestFinal");

  EVP_MD_CTX_free(ctx);

  std::ostringstream oss;
  oss << std::hex << std::setfill('0');

  for (unsigned i = 0; i < hash_len; ++i)
    oss << std::setw(2) << (int)hash[i];

  return oss.str();
}

int parse_command(std::string command, int *o1, int *o2, int *o3, int *o4) {
  size_t p1 = command.find('.');
  size_t p2 = command.find('.', p1 + 1);
  size_t p3 = command.find('.', p2 + 1);

  int at_pos = command.find('@');

  *o1 = std::stoi(command.substr(at_pos + 1, p1 - (at_pos + 1)));
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
  std::string request, ip, file_name;
  std::regex ip_pattern("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");
  struct sockaddr_in server_addr;
  int clientfd, con_status, bytes = 0;
  int o1 = 0, o2 = 0, o3 = 0, o4 = 0, parse_result;
  socklen_t len = 0;
  memset(&server_addr, 0, sizeof(server_addr));
  std::cout
      << "Faça uma requisição ao servidor: "; /* GET
                                                 @127.0.0.1:7777/nome_arquivo
                                               */
  std::getline(std::cin, request);
  parse_result = parse_command(request, &o1, &o2, &o3, &o4);
  ip = std::to_string(o1) + "." + std::to_string(o2) + "." +
       std::to_string(o3) + "." + std::to_string(o4);
  if (!std::regex_match(ip, ip_pattern)) {
    std::cerr << "Erro: Digite um IP válido." << std::endl;
  }
  int port_pos = 0, slash_pos = 0, port;
  std::string port_str;

  port_pos = request.find(':') + 1;
  slash_pos = request.find('/', port_pos);
  port_str = request.substr(port_pos, slash_pos - port_pos);
  port = std::stoi(port_str);
  if (port < 1024 || port > 65535) {
    std::cerr << "Erro: Porta inválida." << std::endl;
    exit(1);
  }
  clientfd = socket(AF_INET, SOCK_DGRAM, 0);
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
    std::cerr << "Erro: IP inválido: " << ip << std::endl;
    close(clientfd);
    return 1;
  }
  len = sizeof(server_addr);

  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;

  if (setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    std::cerr << "Erro ao configurar timeout" << std::endl;
  }

  std::string buf;
  buf.resize(MAX_BUFFER_SIZE);

  sendto(clientfd, "ACK", ACK_SIZE, 0, (sockaddr *)&server_addr, len);
  bytes = recvfrom(clientfd, buf.data(), buf.size(), 0,
                   (sockaddr *)&server_addr, &len);

  if (bytes < 0) {
    std::cerr << "Erro: A conexão com o servidor expirou." << std::endl;
    return 0;
  }
  if (bytes > 0) {
    buf.resize(bytes);
  }
  if (buf.substr(0, 3) == "ACK") {
    std::cout << "Status: Conexão com o servidor efetuada!\n";
    size_t space_pos = buf.find(' ');
    if (space_pos != std::string::npos) {
      int new_port = std::stoi(buf.substr(space_pos + 1));
      server_addr.sin_port = htons(new_port);
      len = sizeof(server_addr);
    }
  }

  file_name = request.substr(slash_pos + 1, request.size() - slash_pos);
  std::ifstream existing_file_check(file_name, std::ios::binary);

  if (existing_file_check.good()) {
    existing_file_check.close();
    std::remove(file_name.data());
    std::cout << "Aviso: Arquivo já existia localmente e foi removido para "
                 "evitar conflitos."
              << std::endl;
  }
  std::string err_str;
  bool request_succeeded = true;
  err_str.resize(MAX_BUFFER_SIZE);
  std::cout << request << "\n";
  sendto(clientfd, request.data(), request.size(), 0,
         (struct sockaddr *)&server_addr, len);
  bytes = recvfrom(clientfd, err_str.data(), MAX_BUFFER_SIZE, 0,
                   (struct sockaddr *)&server_addr, &len);
  if (err_str.substr(0, 4) == "Erro") {
    std::cout << err_str << "\n";
    std::cout << "Faça uma nova requisição ao servidor: ";
    std::getline(std::cin, request);
    request_succeeded = false;
  } else {
    std::cout << err_str << "\n";
  }

  if (!request_succeeded) {
    sendto(clientfd, request.data(), request.size(), 0,
           (struct sockaddr *)&server_addr, len);
    bytes = recvfrom(clientfd, err_str.data(), MAX_BUFFER_SIZE, 0,
                     (struct sockaddr *)&server_addr, &len);
  }
  int file_size, bytes_recv, temp_size = 0;
  buf.resize(MAX_BUFFER_SIZE);
  bytes_recv = recvfrom(clientfd, buf.data(), MAX_BUFFER_SIZE, 0,
                        (struct sockaddr *)&server_addr, &len);
  if (bytes_recv < 0) {
    perror("recvfrom");
    close(clientfd);
    return 0;
  }
  buf.resize(static_cast<size_t>(bytes_recv));
  std::cout << buf << "\n";
  file_size = std::stoi(buf);
  int current_chunk = 0, delimiter_pos, package_chunk;

  for (;;) {
    std::string chunk_hash = "";
    std::string hash;
    hash.resize(64);
    buf.resize(MAX_BUFFER_SIZE);
    bytes_recv = recvfrom(clientfd, buf.data(), MAX_BUFFER_SIZE, 0,
                          (struct sockaddr *)&server_addr, &len);
    if (bytes_recv < 0) {
      perror("recvfrom");
      break;
    }
    std::cout << bytes_recv << "\n";
    buf.resize(static_cast<size_t>(bytes_recv));
    std::ofstream ofs(file_name, std::ios::binary | std::ios::app);
    if (!ofs.is_open()) {
      std::cerr << "Não foi possível abrir o arquivo!" << std::endl;
    }
    delimiter_pos = buf.find(' ');
    chunk_hash = buf.substr(0, delimiter_pos);
    std::cout << chunk_hash << "\n";
    size_t second_space = buf.find(' ', delimiter_pos + 1);
    package_chunk = std::stoi(
        buf.substr(delimiter_pos + 1, second_space - (delimiter_pos + 1)));
    delimiter_pos = second_space;
    std::string payload = buf.substr(delimiter_pos + 1);
    std::string package_ack = "ACK";
    size_t header_size = 0;

    hash = compute_sha256("UNINITIALIZED", &payload);
    std::cout << hash << "\n";
    if (current_chunk == package_chunk && chunk_hash == hash) {
      ofs.write(
          payload.data(),
          bytes_recv -
              (delimiter_pos + 1 +
               header_size)); // Atenção para aqui quando adicionar o header.
      ofs.close();

      temp_size += payload.size();
      package_ack += std::to_string(++current_chunk) + ' ';
    } else {
      package_ack += std::to_string(package_chunk) + ' ';
    }
    sendto(clientfd, package_ack.data(), package_ack.size(), 0,
           (struct sockaddr *)&server_addr, len);
    if (package_ack.length() != 0) {
      package_ack.clear();
    }
    std::cout << temp_size << "\n";
    if (temp_size >= file_size) {
      std::cout << "Aviso: Arquivo [" << file_name << "] recebido.\n";
      std::string local_hash = compute_sha256(file_name);
      hash.resize(64);
      recvfrom(clientfd, hash.data(), hash.size(), 0,
               (struct sockaddr *)&server_addr, &len);
      std::cout << "hash calculado no cliente: " << local_hash << std::endl;
      std::cout << "hash calculado na thread do server: " << hash << std::endl;
      std::cout << "nome do arquivo: " << file_name << std::endl;
      std::cout << "tamanho do arquivo: " << std::fixed << std::setprecision(2)
                << (float)temp_size / 1000000 << "MB" << std::endl;
      if (local_hash == hash) {
        std::cout << "Arquivo íntegro" << std::endl;
      } else {
        std::cerr << "Arquivo corrompido" << std::endl;
      }
      break;
    }
  }
  close(clientfd);
  return 0;
}
