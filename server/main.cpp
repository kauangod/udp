#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <mqueue.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#define PORT 7777
#define BUFF_SIZ 4096
#define MAX_TRANSFER_UNIT 4096
#define PAYLOAD_MAX_SIZE 2048
#define ACK_SIZE 3
#define GET_SIZE 3
int serverfd;
bool finished = false;
size_t client_id = 0;

void *send_client_thread(void *arg);
void *recv_client_thread(void *arg);

typedef struct {
  struct sockaddr_in *client_addr;
  socklen_t *client_len;
  int client_fd;
  char queue_name[32];
  struct mq_attr attr;
} thread_args;

class ServerDispatcher {
public:
  unsigned int reuse;
  unsigned int fd;
  socklen_t addr_len;
  struct sockaddr_in addr;
  ServerDispatcher() {
    this->reuse = 1;
    this->fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&this->addr, 0, sizeof(this->addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    this->addr_len = sizeof(this->addr);
    this->bind_main_port();
    this->configure_opt();
  }
  ~ServerDispatcher() {}
  void bind_main_port() {
    int status;
    status = bind(this->fd, (struct sockaddr *)&this->addr, this->addr_len);
    if (status < 0) {
      perror("Erro no bind: ");
      close(this->fd);
      exit(EXIT_FAILURE);
    }
  }

  void configure_opt() {
    if (setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &this->reuse,
                   sizeof(this->reuse)) < 0) {
      perror("Erro ao setar opcional SOL_SOCKET: ");
      close(this->fd);
      exit(EXIT_FAILURE);
    }
  }
};

class Client {
public:
  struct sockaddr_in *addr;
  struct sockaddr_in *client_server_ref;
  socklen_t *len;
  socklen_t *len_ref;
  int fd;
  int id;
  int reuse;
  bool finished;
  Client() {
    this->fd = 0;
    this->addr = new sockaddr_in();
    this->len = new socklen_t(sizeof(*addr));
    this->client_server_ref = new sockaddr_in();
    this->len_ref = new socklen_t(sizeof(*client_server_ref));
    this->reuse = 1;
    this->set_socket();
    this->finished = false;
  }
  ~Client() {}
  void set_socket() {
    this->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &this->reuse,
                   sizeof(this->reuse)) < 0) {
      perror("Erro ao setar opcional SO_REUSEADDR");
      close(this->fd);
    }
  }
};

class ConManager {
public:
  ServerDispatcher *dispat;
  Client *client;
  thread_args *args;
  std::vector<Client *> client_list;
  std::string request;
  std::string ack_msg;
  ConManager() {
    this->dispat = new ServerDispatcher();
    this->args = new thread_args();
    this->request.resize(BUFF_SIZ);
    this->args->attr.mq_flags = 0;
    this->args->attr.mq_maxmsg = 10;
    this->args->attr.mq_msgsize = BUFF_SIZ;
    this->args->attr.mq_curmsgs = 0;
    this->wait_con(this->dispat);
  }
  ~ConManager() {
    close(dispat->fd);
    delete dispat;
    for (Client *c : client_list) {
      close(client->fd);
      delete c;
    }
  }
  void wait_con(ServerDispatcher *d) {
    int status;
    for (;;) {
      this->client = new Client();
      status = recvfrom(d->fd, this->request.data(), request.size(), 0,
                        (sockaddr *)this->client->addr, this->client->len);
      if (this->client->fd > 0) {
        std::cout << "Socket do cliente " << this->client->id
                  << " instanciado com sucesso.\n";
      }
      client_list.push_back(this->client);
      this->bind_client_port(this->client);
      this->connect_client(this->client);
    }
  }

  void bind_client_port(Client *c) {
    int status;
    c->client_server_ref->sin_family = AF_INET;
    c->client_server_ref->sin_port = htons(0);
    c->client_server_ref->sin_addr.s_addr = INADDR_ANY;

    status =
        bind(c->fd, (struct sockaddr *)c->client_server_ref, *(c->len_ref));
    if (status < 0) {
      perror("Erro no bind do client_fd");
      close(c->fd);
      return;
    }
    if (getsockname(c->fd, (struct sockaddr *)c->client_server_ref,
                    c->len_ref) < 0) {
      perror("Erro ao obter porta do client_fd");
      close(c->fd);
    }
  }
  void connect_client(Client *c) {
    if (connect(c->fd, (struct sockaddr *)c->addr, *(c->len)) < 0) {
      perror("Erro ao conectar socket ao cliente");
      close(c->fd);
      exit(EXIT_FAILURE);
    }
    this->confirm_con(c);
  }
  void confirm_con(Client *c) {
    this->ack_msg =
        "ACK " + std::to_string(ntohs(c->client_server_ref->sin_port));
    sendto(c->fd, this->ack_msg.data(), this->ack_msg.size(), 0,
           (sockaddr *)c->addr, *(c->len));
    std::cout << "Cliente " << client_id << " conectado na porta "
              << ntohs(c->client_server_ref->sin_port) << "!\n";
    c->id = client_id++;
    define_args(this->args, c);
    this->request.clear();
  }
  void define_args(thread_args *args, Client *c) {
    ((thread_args *)args)->client_addr = c->addr;
    ((thread_args *)args)->client_len = c->len;
    ((thread_args *)args)->client_fd = c->fd;
    snprintf(this->args->queue_name, sizeof(this->args->queue_name),
             "/cliente_%d", c->id);
    mq_unlink(this->args->queue_name);
    this->thread_init();
  }
  void thread_init() {
    unsigned int status;
    pthread_t send_thread, recv_thread;

    status =
        pthread_create(&send_thread, NULL, send_client_thread, (void *)args);

    if (status != 0) {
      perror("Erro na criação da thread de envio do cliente!");
      exit(EXIT_FAILURE);
    }

    status =
        pthread_create(&recv_thread, NULL, recv_client_thread, (void *)args);

    if (status != 0) {
      perror("Erro na criação da thread de envio do cliente!");
      exit(EXIT_FAILURE);
    }
  }
};

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

void *recv_client_thread(void *arg) {
  std::string request;
  int recv_status;
  struct sockaddr_in *client_addr = ((thread_args *)arg)->client_addr;
  socklen_t *client_len = ((thread_args *)arg)->client_len;
  int client_fd = ((thread_args *)arg)->client_fd;
  mqd_t mq = mq_open(((thread_args *)arg)->queue_name, O_CREAT | O_WRONLY, 0666,
                     &(((thread_args *)arg)->attr));
  for (;;) {
    if (finished)
      break;
    int send_status;
    request.resize(BUFF_SIZ);
    *client_len = sizeof(*client_addr);
    recv_status = recvfrom(client_fd, request.data(), request.size(), 0,
                           (sockaddr *)client_addr, client_len);
    if (recv_status < 0) {
      perror("recvfrom");
      continue;
    }
    if (request.substr(0, 3) != "ACK") {
      std::cout << request << "\n";
    }
    if (request.substr(0, GET_SIZE) == "GET" ||
        request.substr(0, ACK_SIZE) == "ACK") {
      send_status =
          mq_send(mq, request.data(), static_cast<size_t>(recv_status), 0);
      if (send_status == -1) {
        perror("mq_send");
      }
      request.clear();
    }
  }
  return nullptr;
}

void *send_client_thread(void *arg) {
  sleep(1);
  std::string request, file_name = "UNINITIALIZED", con_status;
  ssize_t msg_size = 0;
  int i = 0, bytes;
  std::streamsize size = 0;
  std::string content;
  std::ifstream ifs;
  struct sockaddr_in *client_addr = ((thread_args *)arg)->client_addr;
  socklen_t *client_len = ((thread_args *)arg)->client_len;
  int client_fd = ((thread_args *)arg)->client_fd;
  bool first_interaction = true;
  mqd_t mq = mq_open(((thread_args *)arg)->queue_name, O_RDONLY, 0666,
                     &(((thread_args *)arg)->attr));

  for (;;) {
    if (finished)
      break;
    request.resize(BUFF_SIZ);
    msg_size = mq_receive(mq, request.data(), request.size(), NULL);
    if (msg_size >= 0) {
    } else {
      perror("mq_receive");
      continue;
    }
    if (!std::strcmp(request.data(), "ACK") && first_interaction) {
      bytes = sendto(client_fd, request.data(), ACK_SIZE, 0,
                     (sockaddr *)client_addr, *client_len);

      if (bytes < 0) {
        perror("Erro no sendto");
      }
      first_interaction = false;
      continue;
    }
    if (!std::strcmp(file_name.data(), "UNINITIALIZED")) {
      client_addr = ((thread_args *)arg)->client_addr;
      client_len = ((thread_args *)arg)->client_len;
      size_t pos = request.find('/') + 1; /* GET @127.0.0.1:7777/nome_arquivo */
      size_t file_name_size = request.size() - pos;
      file_name = request.substr(pos, file_name_size);
      ifs.open(file_name, std::ios::binary | std::ios::ate);
      if (!ifs) {
        con_status =
            "Erro: O arquivo [" + file_name + "] requisitado não existe!";
        sendto(client_fd, con_status.data(), con_status.size(), 0,
               (sockaddr *)client_addr, *client_len);
        file_name = "UNINITIALIZED";
        continue;
      } else {
        con_status = "Aviso: Iniciando o envio do arquivo [" + file_name +
                     "] requisitado.";
        std::cout << con_status << "\n";
        sendto(client_fd, con_status.data(), con_status.size(), 0,
               (sockaddr *)client_addr, *client_len);
      }
      size = ifs.tellg();
      ifs.seekg(0, std::ios::beg);
      content.resize(PAYLOAD_MAX_SIZE);
      std::string size_str = std::to_string(size);
      std::cout << "Tamanho total do arquivo: " + size_str << "\n";
      sendto(client_fd, size_str.data(), size_str.size(), 0,
             (struct sockaddr *)client_addr, *client_len);
    }
    /* Fazer IF do ACK aqui para o envio dos segmentos */
    size_t temp_size = 0;
    int current_chunk = 0;
    std::string ack_buf;
    std::string hash = "";

    unsigned int chunk_size = 0;

    for (;;) {
      ack_buf.resize(BUFF_SIZ);
      if (temp_size >= size) {
        break;
      }
      ifs.read(content.data(), PAYLOAD_MAX_SIZE);
      chunk_size = ifs.gcount();
      content.resize(chunk_size);
      hash = compute_sha256(file_name, &content);
      if (chunk_size <= 0) {
        break;
      }
      content = hash + ' ' + std::to_string(current_chunk) + ' ' + content;
      sendto(client_fd, content.data(), content.size(), 0,
             (struct sockaddr *)client_addr, *client_len);

      for (;;) {
        msg_size = mq_receive(mq, ack_buf.data(), ack_buf.size(), NULL);
        if (msg_size >= 0) {
        } else {
          perror("mq_receive");
          continue;
        }
        if (ack_buf.substr(0, 3) == "ACK") {
          int delimiter_pos = ack_buf.find(' ');
          int client_chunk = std::stoi(ack_buf.substr(3, delimiter_pos));
          if (client_chunk == current_chunk) {
            sendto(client_fd, content.data(), content.size(), 0,
                   (struct sockaddr *)client_addr, *client_len);
          } else {
            current_chunk++;
            break;
          }
        }
      }
      temp_size += static_cast<size_t>(chunk_size);
    }
    std::cout << "Aviso: Envio do arquivo [" << file_name
              << "] foi completo.\n";
    hash = compute_sha256(file_name);
    sendto(client_fd, hash.data(), hash.size(), 0,
           (struct sockaddr *)client_addr, *client_len);
    request.clear();
    finished = true;
  }
  ifs.close();
  close(client_fd);
  return nullptr;
}

int main() {
  pthread_t send_thread, recv_thread;
  ConManager *mng = new ConManager();
  return 0;
}
