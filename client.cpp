#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mqueue.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <regex>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ACK_SIZE 3
#define PORT 7777
#define MAX_BUFFER_SIZE 4096
#define DROP_CHANCE 20 /* % chance of simulating a dropped packet */

typedef struct {
  int fd;
  struct sockaddr_in server_addr;
  socklen_t addr_len;
  char queue_name[32];
  struct mq_attr attr;
  std::string file_name;
  int file_size;
  bool finished;
} client_thread_args;

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

  if (*o1 > 255 || *o2 > 255 || *o3 > 255 || *o4 > 255)
    return -1;
  return 0;
}

void *recv_client_thread(void *arg) {
  client_thread_args *args = (client_thread_args *)arg;
  std::string buf;
  ssize_t bytes_recv;

  mqd_t mq = mq_open(args->queue_name, O_CREAT | O_WRONLY, 0666, &args->attr);
  if (mq == (mqd_t)-1) {
    perror("mq_open (recv_thread)");
    return nullptr;
  }

  for (;;) {
    if (args->finished)
      break;
    buf.resize(MAX_BUFFER_SIZE);
    bytes_recv =
        recvfrom(args->fd, buf.data(), MAX_BUFFER_SIZE, 0,
                 (struct sockaddr *)&args->server_addr, &args->addr_len);
    if (bytes_recv < 0) {
      perror("recvfrom");
      continue;
    }
    mq_send(mq, buf.data(), static_cast<size_t>(bytes_recv), 0);
  }

  mq_close(mq);
  return nullptr;
}

void *send_client_thread(void *arg) {
  sleep(1);
  client_thread_args *args = (client_thread_args *)arg;
  std::string buf;
  ssize_t msg_size;
  int current_chunk = 0, temp_size = 0;

  mqd_t mq = mq_open(args->queue_name, O_RDONLY, 0666, &args->attr);
  if (mq == (mqd_t)-1) {
    perror("mq_open (send_thread)");
    return nullptr;
  }

  for (;;) {
    buf.resize(MAX_BUFFER_SIZE);
    msg_size = mq_receive(mq, buf.data(), MAX_BUFFER_SIZE, NULL);
    if (msg_size < 0) {
      perror("mq_receive");
      continue;
    }
    buf.resize(static_cast<size_t>(msg_size));

    int delimiter_pos = buf.find(' ');
    std::string chunk_hash = buf.substr(0, delimiter_pos);
    size_t second_space = buf.find(' ', delimiter_pos + 1);
    int package_chunk = std::stoi(
        buf.substr(delimiter_pos + 1, second_space - (delimiter_pos + 1)));
    delimiter_pos = second_space;
    std::string payload = buf.substr(delimiter_pos + 1);

    std::string package_ack = "ACK";
    std::string hash = compute_sha256("", &payload);

    if (current_chunk == package_chunk && chunk_hash == hash) {
      bool simulated_drop = (std::rand() % 100) < DROP_CHANCE;
      if (simulated_drop) {
        std::cout << "[SIM] Pacote " << package_chunk
                  << " descartado (simulacao).\n";
        package_ack += std::to_string(package_chunk) + ' ';
      } else {
        std::ofstream ofs(args->file_name, std::ios::binary | std::ios::app);
        if (!ofs.is_open())
          std::cerr << "Nao foi possivel abrir o arquivo!\n";
        ofs.write(payload.data(), payload.size());
        ofs.close();
        temp_size += static_cast<int>(payload.size());
        package_ack += std::to_string(++current_chunk) + ' ';
      }
    } else {
      package_ack += std::to_string(package_chunk) + ' ';
    }

    sendto(args->fd, package_ack.data(), package_ack.size(), 0,
           (struct sockaddr *)&args->server_addr, args->addr_len);

    if (temp_size >= args->file_size) {
      /* Next message from recv_thread is the server's final file hash. */
      buf.resize(MAX_BUFFER_SIZE);
      msg_size = mq_receive(mq, buf.data(), MAX_BUFFER_SIZE, NULL);
      if (msg_size > 0)
        buf.resize(static_cast<size_t>(msg_size));

      std::string local_hash = compute_sha256(args->file_name);
      bool intact = (local_hash == buf);
      std::cout << "\n--------------------------------------------------\n";
      std::cout << "  Arquivo  : " << args->file_name << "\n";
      std::cout << "  Tamanho  : " << std::fixed << std::setprecision(2)
                << (float)args->file_size / 1000000.0f << " MB\n";
      std::cout << "  SHA-256  : " << local_hash << " (local)\n";
      std::cout << "             " << buf << " (servidor)\n";
      std::cout << "  Status   : "
                << (intact ? "[OK] Arquivo integro"
                           : "[ERRO] Arquivo corrompido")
                << "\n";
      std::cout << "--------------------------------------------------\n";
      args->finished = true;
      break;
    }
  }

  mq_close(mq);
  return nullptr;
}

int main() {
  std::srand(static_cast<unsigned>(std::time(nullptr)));
  std::string request, ip, file_name;
  std::regex ip_pattern("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");
  struct sockaddr_in server_addr;
  int clientfd, bytes = 0;
  int o1 = 0, o2 = 0, o3 = 0, o4 = 0;
  socklen_t len = 0;
  memset(&server_addr, 0, sizeof(server_addr));

  std::cout
      << "Faca uma requisicao ao servidor: "; /* GET
                                                 @127.0.0.1:7777/nome_arquivo */
  std::getline(std::cin, request);
  parse_command(request, &o1, &o2, &o3, &o4);
  ip = std::to_string(o1) + "." + std::to_string(o2) + "." +
       std::to_string(o3) + "." + std::to_string(o4);
  if (!std::regex_match(ip, ip_pattern)) {
    std::cerr << "Erro: Digite um IP valido." << std::endl;
  }

  int port_pos = 0, slash_pos = 0, port;
  std::string port_str;
  port_pos = request.find(':') + 1;
  slash_pos = request.find('/', port_pos);
  port_str = request.substr(port_pos, slash_pos - port_pos);
  port = std::stoi(port_str);
  if (port < 1024 || port > 65535) {
    std::cerr << "Erro: Porta invalida." << std::endl;
    exit(1);
  }

  clientfd = socket(AF_INET, SOCK_DGRAM, 0);
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
    std::cerr << "Erro: IP invalido: " << ip << std::endl;
    close(clientfd);
    return 1;
  }
  len = sizeof(server_addr);

  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  if (setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    std::cerr << "Erro ao configurar timeout" << std::endl;

  /* ── Handshake ─────────────────────────────────────────────────────── */
  std::string buf;
  buf.resize(MAX_BUFFER_SIZE);
  sendto(clientfd, "ACK", ACK_SIZE, 0, (sockaddr *)&server_addr, len);
  bytes = recvfrom(clientfd, buf.data(), buf.size(), 0,
                   (sockaddr *)&server_addr, &len);
  if (bytes < 0) {
    std::cerr << "Erro: A conexao com o servidor expirou." << std::endl;
    return 0;
  }
  buf.resize(bytes);
  if (buf.substr(0, 3) == "ACK") {
    std::cout << "[OK] Conexao com o servidor estabelecida.\n";
    size_t space_pos = buf.find(' ');
    if (space_pos != std::string::npos) {
      int new_port = std::stoi(buf.substr(space_pos + 1));
      server_addr.sin_port = htons(new_port);
      len = sizeof(server_addr);
    }
  }

  /* ── Request ───────────────────────────────────────────────────────── */
  file_name = request.substr(slash_pos + 1, request.size() - slash_pos);
  std::ifstream existing_file_check(file_name, std::ios::binary);
  if (existing_file_check.good()) {
    existing_file_check.close();
    std::remove(file_name.data());
    std::cout
        << "[!]  Arquivo local existente removido para evitar conflitos.\n";
  }

  std::string err_str;
  bool request_succeeded = true;
  err_str.resize(MAX_BUFFER_SIZE);
  sendto(clientfd, request.data(), request.size(), 0,
         (struct sockaddr *)&server_addr, len);
  bytes = recvfrom(clientfd, err_str.data(), MAX_BUFFER_SIZE, 0,
                   (struct sockaddr *)&server_addr, &len);
  err_str.resize(bytes);
  if (err_str.substr(0, 4) == "Erro") {
    std::cerr << err_str << "\n";
    std::cout << "Nova requisicao: ";
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

  /* ── Receive file size ─────────────────────────────────────────────── */
  int file_size, bytes_recv;
  buf.resize(MAX_BUFFER_SIZE);
  bytes_recv = recvfrom(clientfd, buf.data(), MAX_BUFFER_SIZE, 0,
                        (struct sockaddr *)&server_addr, &len);
  if (bytes_recv < 0) {
    perror("recvfrom");
    close(clientfd);
    return 0;
  }
  buf.resize(static_cast<size_t>(bytes_recv));
  file_size = std::stoi(buf);

  /* ── Start threads ─────────────────────────────────────────────────── */
  client_thread_args args;
  args.fd = clientfd;
  args.server_addr = server_addr;
  args.addr_len = len;
  args.file_name = file_name;
  args.file_size = file_size;
  args.finished = false;
  snprintf(args.queue_name, sizeof(args.queue_name), "/cliente_queue");
  args.attr.mq_flags = 0;
  args.attr.mq_maxmsg = 10;
  args.attr.mq_msgsize = MAX_BUFFER_SIZE;
  args.attr.mq_curmsgs = 0;
  mq_unlink(args.queue_name);

  pthread_t recv_thread, send_thread;
  pthread_create(&recv_thread, NULL, recv_client_thread, &args);
  pthread_create(&send_thread, NULL, send_client_thread, &args);

  pthread_join(send_thread, NULL); /* wait for transfer to complete */
  pthread_cancel(recv_thread);     /* unblock the recv loop */
  pthread_join(recv_thread, NULL);

  mq_unlink(args.queue_name);
  close(clientfd);
  return 0;
}
