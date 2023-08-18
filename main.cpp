#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <string.h>
#include <sys/eventfd.h>
#include <stdint.h>

#include <iostream>
#include <vector>
#include <list>
#include <thread>
#include <mutex>
#include <sstream>

using namespace std;

#define LOG_INFO( X )                           \
  cout << X << "\n"

/* Global SSL context */
SSL_CTX *ctx;

#define DEFAULT_BUF_SIZE 64



/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */
enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL};


enum sslstatus do_ssl_handshake();


void handle_error(const char *file, int lineno, const char *msg) {
  fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
  ERR_print_errors_fp(stderr);
  exit(-1);
}

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

void die(const char *msg) {
  perror(msg);
  exit(1);
}

void print_unencrypted_data(char *buf, size_t len) {
  printf("%.*s", (int)len, buf);
}


/* This enum contols whether the SSL connection needs to initiate the SSL
 * handshake. */
enum ssl_mode { SSLMODE_SERVER, SSLMODE_CLIENT };

void ssl_init(const char * certfile, const char* keyfile)
{
  /* SSL library initialisation */

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
#if OPENSSL_VERSION_MAJOR < 3
  ERR_load_BIO_strings(); // deprecated since OpenSSL 3.0
#endif
  ERR_load_crypto_strings();

  /* create the SSL server context */
  ctx = SSL_CTX_new(TLS_method());
  if (!ctx)
    die("SSL_CTX_new()");

  /* Load certificate and private key files, and check consistency */
  if (certfile && keyfile) {
    if (SSL_CTX_use_certificate_file(ctx, certfile,  SSL_FILETYPE_PEM) != 1)
      int_error("SSL_CTX_use_certificate_file failed");

    if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1)
      int_error("SSL_CTX_use_PrivateKey_file failed");

    /* Make sure the key and certificate file match. */
    if (SSL_CTX_check_private_key(ctx) != 1)
      int_error("SSL_CTX_check_private_key failed");
    else
      printf("certificate and private key loaded and verified\n");
  }


  /* Recommended to avoid SSLv2 & SSLv3 */
  SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
}
/* An instance of this object is created each time a client connection is
 * accepted. It stores the client file descriptor, the SSL objects, and data
 * which is waiting to be either written to socket or encrypted. */
struct ssl_client
{
  int fd;

  SSL *ssl;

  BIO *rbio; /* SSL reads from, we write to. */
  BIO *wbio; /* SSL writes to, we read from. */

  /* Bytes waiting to be written to socket. This is data that has been generated
   * by the SSL object, either due to encryption of user input, or, writes
   * requires due to peer-requested SSL renegotiation. */
  char* write_buf;
  size_t write_len;

  /* Bytes waiting to be encrypted by the SSL object. */
  char* encrypt_buf;
  size_t encrypt_len;

  /* Store the previous state string */
  const char * last_state;

  /* Method to invoke when unencrypted bytes are available. */
  void (*io_on_read)(char *buf, size_t len);
} client;



void ssl_client_init(struct ssl_client *p,
                     int fd,
                     enum ssl_mode mode)
{
  memset(p, 0, sizeof(struct ssl_client));

  p->fd = fd;

  p->rbio = BIO_new(BIO_s_mem());
  p->wbio = BIO_new(BIO_s_mem());
  p->ssl = SSL_new(ctx);

  if (mode == SSLMODE_SERVER)
    SSL_set_accept_state(p->ssl);  /* ssl server mode */
  else if (mode == SSLMODE_CLIENT)
    SSL_set_connect_state(p->ssl); /* ssl client mode */

  SSL_set_bio(p->ssl, p->rbio, p->wbio);

  p->io_on_read = print_unencrypted_data;
}


void ssl_client_cleanup(struct ssl_client *p)
{
  SSL_free(p->ssl);   /* free the SSL object and its BIO's */
  free(p->write_buf);
  free(p->encrypt_buf);
}


int ssl_client_want_write(struct ssl_client *cp) {
  return (cp->write_len>0);
}



/* Handle request to send unencrypted data to the SSL.  All we do here is just
 * queue the data into the encrypt_buf for later processing by the SSL
 * object. */
void send_unencrypted_bytes(const char *buf, size_t len)
{
  client.encrypt_buf = (char*)realloc(client.encrypt_buf, client.encrypt_len + len);
  memcpy(client.encrypt_buf+client.encrypt_len, buf, len);
  client.encrypt_len += len;
}


/* Queue encrypted bytes. Should only be used when the SSL object has requested a
 * write operation. */
void queue_encrypted_bytes(const char *buf, size_t len)
{
  client.write_buf = (char*)realloc(client.write_buf, client.write_len + len);
  memcpy(client.write_buf+client.write_len, buf, len);
  client.write_len += len;
}



void print_ssl_state()
{
  const char * current_state = SSL_state_string_long(client.ssl);
  if (current_state != client.last_state) {
    if (current_state)
      printf("SSL-STATE: %s\n", current_state);
    client.last_state = current_state;
  }
}


static enum sslstatus get_sslstatus(SSL* ssl, int n)
{
  auto x = SSL_get_error(ssl, n);
  switch (x)
  {
    case SSL_ERROR_NONE:
      return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      return SSLSTATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
      LOG_INFO(x);
      return SSLSTATUS_FAIL;
  }
}




void print_ssl_error()
{
  BIO *bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char *buf;
  size_t len = BIO_get_mem_data(bio, &buf);
  if (len > 0)
    printf("SSL-ERROR: %s", buf);
  BIO_free(bio);
}


/* Process outbound unencrypted data that is waiting to be encrypted.  The
 * waiting data resides in encrypt_buf.  It needs to be passed into the SSL
 * object for encryption, which in turn generates the encrypted bytes that then
 * will be queued for later socket write. */
int do_encrypt()
{
  char buf[DEFAULT_BUF_SIZE];
  enum sslstatus status;

  if (!SSL_is_init_finished(client.ssl))
    return 0;

  while (client.encrypt_len>0) {
    int n = SSL_write(client.ssl, client.encrypt_buf, client.encrypt_len);
    status = get_sslstatus(client.ssl, n);

    if (n>0) {
      /* consume the waiting bytes that have been used by SSL */
      if ((size_t)n<client.encrypt_len)
        memmove(client.encrypt_buf, client.encrypt_buf+n, client.encrypt_len-n);
      client.encrypt_len -= n;
      client.encrypt_buf = (char*)realloc(client.encrypt_buf, client.encrypt_len);

      /* take the output of the SSL object and queue it for socket write */
      do {
        n = BIO_read(client.wbio, buf, sizeof(buf));
        if (n > 0)
          queue_encrypted_bytes(buf, n);
        else if (!BIO_should_retry(client.wbio))
          return -1;
      } while (n>0);
    }

    if (status == SSLSTATUS_FAIL)
      return -1;

    if (n==0)
      break;
  }
  return 0;
}


/* Read bytes from stdin and queue for later encryption. */
void do_stdin_read()
{
  char buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
  if (n>0)
    send_unencrypted_bytes(buf, (size_t)n);
}

/* Process SSL bytes received from the peer. The data needs to be fed into the
   SSL object to be unencrypted.  On success, returns 0, on SSL error -1. */
int on_read_cb(char* src, size_t len)
{
  char buf[DEFAULT_BUF_SIZE];
  enum sslstatus status;
  int n;

  while (len > 0) {
    n = BIO_write(client.rbio, src, len);

    if (n == 10) {
      LOG_INFO("BIO_WRITE = " << n);
    }

    if (n<=0)
      return -1; /* assume bio write failure is unrecoverable */

    src += n;
    len -= n;

    if (!SSL_is_init_finished(client.ssl)) {
      if (do_ssl_handshake() == SSLSTATUS_FAIL) {
        LOG_INFO("do_ssl_handshake fail");
        return -1;
      }
      if (!SSL_is_init_finished(client.ssl))
        return 0;
    }

    /* The encrypted data is now in the input bio so now we can perform actual
     * read of unencrypted data. */

    do {
      n = SSL_read(client.ssl, buf, sizeof(buf));
      if (n > 0)
        client.io_on_read(buf, (size_t)n);
    } while (n > 0);

    LOG_INFO("CALLINGget_sslstatus N=" << n);
    status = get_sslstatus(client.ssl, n);

    /* Did SSL request to write bytes? This can happen if peer has requested SSL
     * renegotiation. */
    if (status == SSLSTATUS_WANT_IO)
      do {
        n = BIO_read(client.wbio, buf, sizeof(buf));
        if (n > 0)
          queue_encrypted_bytes(buf, n);
        else if (!BIO_should_retry(client.wbio)) {
          LOG_INFO("BIO_should_retry fail");
          return -1;
        }
      } while (n>0);

    if (status == SSLSTATUS_FAIL) {
      LOG_INFO("status fail");
      return -1;
    }
  }

  return 0;
}

/* Read encrypted bytes from socket. */
int do_sock_read()
{
  char buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(client.fd, buf, sizeof(buf));

  LOG_INFO("n=" << n);
  if (n>0)
    return on_read_cb(buf, (size_t)n);
  else
    return -1;
}


/* Write encrypted bytes to the socket. */
int do_sock_write()
{
  ssize_t n = write(client.fd, client.write_buf, client.write_len);
  if (n>0) {
    if ((size_t)n<client.write_len)
      memmove(client.write_buf, client.write_buf+n, client.write_len-n);
    client.write_len -= n;
    client.write_buf = (char*)realloc(client.write_buf, client.write_len);
    return 0;
  }
  else
    return -1;
}



enum sslstatus do_ssl_handshake()
{
  char buf[DEFAULT_BUF_SIZE];
  enum sslstatus status;

  print_ssl_state();
  int n = SSL_do_handshake(client.ssl);
  print_ssl_state();
  status = get_sslstatus(client.ssl, n);

  /* Did SSL request to write bytes? */
  if (status == SSLSTATUS_WANT_IO)
    do {
      n = BIO_read(client.wbio, buf, sizeof(buf));
      if (n > 0)
        queue_encrypted_bytes(buf, n);
      else if (!BIO_should_retry(client.wbio))
        return SSLSTATUS_FAIL;
    } while (n>0);

  return status;
}

auto FIX_SOH = char(1);

// std::string encode_fix_field(int tag, const char* value) {
//   std::ostringstream oss;
//   oss << tag << "=" << value << FIX_SOH;
//   return oss.str();
// }

template<typename T>
std::string encode_fix_field(int tag, T value) {
  std::ostringstream oss;
  oss << tag << "=" << value << FIX_SOH;
  return oss.str();
}

class FixMsg {
public:
  std::string tag8;
  std::string tag9;

  std::vector<std::string> headers;
  std::vector<std::string> body;


  size_t calc_body_length() const {
    size_t sum = 0;
    for (auto & item: headers)
      sum += item.size();
    for (auto & item: body)
      sum += item.size();
    return sum;
  }

  std::string encode() {
    std::ostringstream oss;

    oss << tag8;
    oss << tag9;
    for (auto & item: headers)
      oss << item;
    for (auto & item: body)
      oss << item;

    // checksum
    int checksum = 0;
    for (char c: oss.str()) {
      checksum += c;
    }
    checksum %= 256;
    char buf[4];
    sprintf(buf, "%03d", checksum);
    oss << encode_fix_field(10, buf);

    return oss.str();
  }



};


class FixSession {
public:

  FixSession()
  {
  }

  ~FixSession()
  {
    if (_io_thread)
      _io_thread->join();
  }

  void start() {
    _io_thread.reset(new std::thread(&FixSession::_start, this));
  }


  void _start() {
    // port name, optionally take from args
    int port = 55555;

    // host IP address. Attention! This must be a numeric address, not a server
    // host name, because this example code does not perform address lookup.
    char* host_ip = "127.0.0.1";

    // provide the hostname if this SSL client needs to use SNI to tell the server
    // what certificate to use
    const char * host_name = nullptr;

    // socket family, AF_INET (ipv4) or AF_INET6 (ipv6), must match host_ip above
    int ip_family = AF_INET;

    int sockfd = socket(ip_family, SOCK_STREAM, 0);

    if (ip_family == AF_INET) {
      struct sockaddr_in addr;
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = ip_family;
      addr.sin_port = htons(port);

      if (inet_pton(ip_family, host_ip, &(addr.sin_addr)) <= 0)
        die("inet_pton()");

      if (connect(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
        die("connect()");
    }


    LOG_INFO("socket connected");

    _efd = eventfd(0, 0);
    if (_efd == -1)
      die("eventfd");

    struct pollfd fdset[2];
    memset(&fdset, 0, sizeof(fdset));

    fdset[0].fd = _efd;
    fdset[0].events = POLLIN;

    ssl_init(0,0);
    ssl_client_init(&client, sockfd, SSLMODE_CLIENT);

    if (host_name)
      SSL_set_tlsext_host_name(client.ssl, host_name); // TLS SNI

    fdset[1].fd = sockfd;
    fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
#ifdef POLLRDHUP
    fdset[1].events |= POLLRDHUP;
#endif

    /* event loop */

    do_ssl_handshake();

    while (1) {
      fdset[1].events &= ~POLLOUT;
      fdset[1].events |= ssl_client_want_write(&client)? POLLOUT:0;

      LOG_INFO("GOING INTO POLL");
      int nready = poll(&fdset[0], 2, 60000);
      LOG_INFO("WAITING");

      if (nready == 0)
        continue; /* no fd ready */

      int revents = fdset[1].revents;
      if (revents & POLLIN)
        if (do_sock_read() == -1) {
          LOG_INFO("do_sock_read failed");
          break;
        }
      if (revents & POLLOUT)
        if (do_sock_write() == -1) {
          LOG_INFO("do_sock_write failed");
          break;
        }
      if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
        LOG_INFO("POLLERR|POLLHUP|POLLNVAL failed");
        break;
      }
#ifdef POLLRDHUP
      if (revents & POLLRDHUP) {
        LOG_INFO("POLLRDHUP failed");
        break;
      }
#endif

      if (fdset[0].revents & POLLIN) {

        uint64_t event_value = 1; // You can set the value as needed
        auto ss = read(_efd, &event_value, sizeof(event_value));
        // do_stdin_read();
        {
          std::unique_lock<std::mutex> lock(_mtx);
          for (auto & item : _pending_out) {
            LOG_INFO("GOT ITEM: LEN " << item.size());
            send_unencrypted_bytes(item.data(), item.size());
            send_unencrypted_bytes("\n", 1);
          }
          _pending_out.clear();
        }
      }
      if (client.encrypt_len>0)

        LOG_INFO("client.encrypt_len: " << client.encrypt_len);
        if (do_encrypt() < 0) {
          LOG_INFO("do_encrypt failed");
          break;
        }
    }
    LOG_INFO("OUT OF LOOP");

    close(fdset[1].fd);
    close(_efd);
    print_ssl_state();
    print_ssl_error();
    ssl_client_cleanup(&client);


  }


  void write(const std::string& buf) {

    vector<char> pending{buf.c_str(), buf.c_str()+buf.size()};

    LOG_INFO("pending" << pending.data());

    {
      std::unique_lock<std::mutex> lock(_mtx);
      _pending_out.push_back(std::move(pending));
      uint64_t event_value = 1; // You can set the value as needed
      ssize_t ret = ::write(_efd, &event_value, sizeof(event_value));
    }

  }


  void write(char* buf) {

    // push bytes onto queue
    auto len = strlen(buf);

    vector<char> pending{buf, buf+len};

    LOG_INFO("pending" << pending.data());

    {
      std::unique_lock<std::mutex> lock(_mtx);
      _pending_out.push_back(std::move(pending));


      uint64_t event_value = 1; // You can set the value as needed
      ssize_t ret = ::write(_efd, &event_value, sizeof(event_value));
    }

  }


  int _efd;
  std::mutex _mtx;
  std::list<vector<char>> _pending_out;
  std::unique_ptr<thread> _io_thread;
};

int main() {
  LOG_INFO("starting");

  FixMsg msg;
  msg.tag8 = encode_fix_field(8, "FIX.4.4");


  msg.headers.push_back(encode_fix_field(35, "A"));
  msg.headers.push_back(encode_fix_field(49, "SENDERCOMP"));
  msg.headers.push_back(encode_fix_field(56, "TARGETCOMP"));
  msg.headers.push_back(encode_fix_field(34, "0")); // msg seq num
  msg.headers.push_back(encode_fix_field(52, "20220101-23:23:59")); // msg seq num

  msg.body.push_back(encode_fix_field(98, "0"));
  msg.body.push_back(encode_fix_field(108, "60"));
  msg.body.push_back(encode_fix_field(141, "Y"));
  msg.body.push_back(encode_fix_field(554, "PASS"));

  // calc body length
  auto body_length = msg.calc_body_length();
  LOG_INFO("body_length " << body_length);
  msg.tag9 = encode_fix_field(9, body_length);

  auto fullmsg = msg.encode();
  LOG_INFO("FULL: " << fullmsg);


  FixSession fix_session;


  fix_session.start();

  sleep(2);
  fix_session.write(fullmsg);

  while (1) {
    sleep(2);
    fix_session.write("hello");

  }

  return 0;
}
