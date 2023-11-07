#include "kyber512_kem.hpp"
#include <thread>
#include <ctime>
#include <signal.h>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cryptopp/dh.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 62000
#define KEYPORT 61000
#define MAXLINE 1500
#define TAG_SIZE 16

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/sha3.h"
#include "cryptopp/cryptlib.h"
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::BufferedTransformation;
using CryptoPP::byte;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDH;
using CryptoPP::ECP;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/filters.h"
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;
using CryptoPP::SecByteBlock;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "assert.h"

string convertToString(char *a)
{
    string s = a;
    return s;
}

// Virtual interface access
int tun_open()
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) == -1)
    {
        perror("open /dev/net/tun");
        exit(1);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) == -1)
    {
        perror("ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }

    return fd;
}

// Encrypted data recieve
string data_recieve(int sockfd, struct sockaddr_in servaddr)
{

    socklen_t len;
    char buffer[MAXLINE] = {0};
    int n;

    n = recvfrom(sockfd, (char *)buffer, MAXLINE,
                 MSG_WAITALL, (struct sockaddr *)&servaddr,
                 &len);

    if (n == -1)
    {
        return "";
    }

    string recieved(buffer, n);

    return recieved;
}

// Virtual interface data read
string read_tun(int tundesc)
{

    char buf[MAXLINE - 60];
    int nbytes = read(tundesc, buf, sizeof(buf));
    if (nbytes == -1)
    {
        return "";
    }
    string data(buf, nbytes);

    return data;
}

/* Virtual interface data write.
   Data will appear as if it arrived at
   virtual interface and can be routed further */

void write_tun(int tundesc, string message)
{
    char buf[MAXLINE - 60];
    memcpy(buf, message.data(), message.length());
    int nbytes = write(tundesc, buf, message.length());
}

// Send encrypted data
void send_encrypted(int sockfd, struct sockaddr_in servaddr, string cipher, socklen_t len)
{

    char *cp = &cipher[0];
    sendto(sockfd, cp, cipher.length(), MSG_CONFIRM, (const struct sockaddr *)&servaddr, len);
}

// Data encryption
string encrypt_data(SecByteBlock *key, string message, AutoSeededRandomPool *prng, GCM<AES, CryptoPP::GCM_64K_Tables>::Encryption *e)
{
    string cipher;
    byte iv[AES::BLOCKSIZE];
    (*e).GetNextIV(*prng, iv);
    (*e).SetKeyWithIV(*key, (*key).size(), iv, sizeof(iv));

    try
    {

        StringSource ss1(message, true,
                         new AuthenticatedEncryptionFilter(*e,
                                                           new StringSink(cipher), false, TAG_SIZE));
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    string encrypted((char *)iv, sizeof(iv));

    encrypted += cipher;

    return encrypted;
}

// Data decryption + integrity check
string decrypt_data(SecByteBlock *key, string cipher)
{

    string rpdata;
    byte iv[AES::BLOCKSIZE];
    memcpy(iv, cipher.data(), sizeof(iv));

    GCM<AES, CryptoPP::GCM_64K_Tables>::Decryption d;
    d.SetKeyWithIV(*key, sizeof(*key), iv, sizeof(iv));

    AuthenticatedDecryptionFilter df(d,
                                     new StringSink(rpdata),
                                     AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                                     TAG_SIZE);

    StringSource ss2(cipher.substr(sizeof(iv)), true,
                     new Redirector(df));

    bool b = df.GetLastResult();
    assert(true == b);

    return rpdata;
}

/*
   Aggregation of functions needed for data recieve:
   1) Receive incoming encrypted data
   2) Decrypt data and check integrity
   3) Write decrypted data to virtual interface

   Returns false if there are no more data available on socket.
*/

bool D_E_C_R(int sockfd, struct sockaddr_in servaddr, SecByteBlock *key, int tundesc)
{
    string data;
    string encrypted_data = data_recieve(sockfd, servaddr);
    if (encrypted_data.length() == 0)
    {
        return false;
    }
    try
    {
        data = decrypt_data(key, encrypted_data);
    }
    catch (...)
    {
        return true;
    }

    write_tun(tundesc, data);
    return true;
}

/*
   Aggregation of functions needed for encryption and data send:
   1) Read data from virtual interface
   2) Encrypt data
   3) Send encrypted data

   Returns false if there are no more data available on virtual interface.
*/

bool E_N_C_R(int sockfd, struct sockaddr_in servaddr, SecByteBlock *key, int tundesc, socklen_t len, AutoSeededRandomPool *prng, GCM<AES, CryptoPP::GCM_64K_Tables>::Encryption e)
{
    string data = read_tun(tundesc);

    if (data.length() == 0)
    {
        return false;
    }
    string encrypted_data = encrypt_data(key, data, prng, &e);
    send_encrypted(sockfd, servaddr, encrypted_data, len);
    return true;
}

// Thread function for both encryption and decryption
void thread_encrypt(int sockfd, struct sockaddr_in servaddr, struct sockaddr_in cliaddr, SecByteBlock *key, int tundesc, socklen_t len, std::atomic<int> *threads, AutoSeededRandomPool *prng, GCM<AES, CryptoPP::GCM_64K_Tables>::Encryption e)
{
    for (int i = 0; i < 100; i++)
    {
        while (E_N_C_R(sockfd, cliaddr, key, tundesc, len, prng, e))
        {
        }
        while (D_E_C_R(sockfd, servaddr, key, tundesc))
        {
        }
    }
    *threads += 1;
}

/*
   Rekeying - client mode

   Client get new key from QKD server, combine it with PQC key
   and than send its ID to gateway in server mode.
*/

SecByteBlock rekey_srv(string pqc_key)
{

    CryptoPP::SHA3_256 hash;
    byte digest[CryptoPP::SHA3_256::DIGESTSIZE];

    SecByteBlock key(AES::MAX_KEYLENGTH);
    std::ifstream t("key");
    std::stringstream buffer;
    buffer << t.rdbuf();

    std::string message = buffer.str() + pqc_key;

    hash.CalculateDigest(digest, (byte *)message.c_str(), message.length());

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    int x = 0;
    for (unsigned int i = 0; i < output.length(); i += 2)
    {
        std::string bytestring = output.substr(i, 2);
        key[x] = (char)strtol(bytestring.c_str(), NULL, 16);
        x++;
    }
    return key;
}

// TCP socket creation and "Hello" messages exchange
int tcp_connection(int *pt_server_fd)
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[MAXLINE] = {0};
    const char *helloTCP = "Hello from server";

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(KEYPORT);

    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    cout << "Server waiting for TCP connection \n";

    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                             (socklen_t *)&addrlen)) < 0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    read(new_socket, buffer, MAXLINE);
    cout << "Recieved: " << buffer << "\n";
    send(new_socket, helloTCP, strlen(helloTCP), 0);
    cout << "TCP connection established \n";
    *pt_server_fd = server_fd;
    return new_socket;
}

// UDP socket creation and "Hello" messages exchange
int udp_connection(struct sockaddr_in *pt_servaddr, struct sockaddr_in *pt_cliaddr, socklen_t *pt_len)
{
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    char buffer[MAXLINE] = {0};

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr,
             sizeof(servaddr)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    cout << "Server waiting for UDP connection \n";

    socklen_t len;
    int n;

    len = sizeof(cliaddr);
    const char *hello = "Hello from server";
    n = recvfrom(sockfd, (char *)buffer, MAXLINE,
                 MSG_WAITALL, (struct sockaddr *)&cliaddr,
                 &len);
    buffer[n] = '\0';
    cout << "UDP connection established \n";
    sendto(sockfd, (const char *)hello, strlen(hello),
           MSG_CONFIRM, (const struct sockaddr *)&cliaddr,
           len);

    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    *pt_servaddr = servaddr;
    *pt_cliaddr = cliaddr;
    *pt_len = len;
    return sockfd;
}

string get_pqckey(int new_socket)
{
    constexpr size_t KEY_LEN = 32;
    std::vector<uint8_t> _cipher(kyber512_kem::CIPHER_LEN, 0);
    std::vector<uint8_t> _shrd_key(KEY_LEN, 0);
    std::vector<uint8_t> _m(KEY_LEN, 0);
    auto m = std::span<uint8_t, KEY_LEN>(_m);
    auto cipher = std::span<uint8_t, kyber512_kem::CIPHER_LEN>(_cipher);
    auto shrd_key = std::span<uint8_t, KEY_LEN>(_shrd_key);
    prng::prng_t prng_pqc;
    prng_pqc.read(m);

    /*
       PQC key establishment:

       1) Server recieves client public key
       2) Server generate PQC key
       3) Server encapsulates PQC key with client's public key and sends to client
    */
    std::vector<unsigned char> pqc_buffer(MAXLINE);
    read(new_socket, &pqc_buffer[0], MAXLINE);

    std::vector<uint8_t> _pkey(kyber512_kem::PKEY_LEN, 0);
    _pkey = pqc_buffer;

    auto pkey = std::span<uint8_t, kyber512_kem::PKEY_LEN>(_pkey);
    auto skdf = kyber512_kem::encapsulate(m, pkey, cipher);
    skdf.squeeze(shrd_key);

    string pqc_key = kyber_utils::to_hex(shrd_key);
    send(new_socket, cipher.data(), cipher.size(), 0);
    return pqc_key;
}

void get_qkdkey(string qkd_ip, char bufferTCP[MAXLINE])
{

    std::ofstream myfile;
    myfile.open("keyID");
    myfile << bufferTCP;
    myfile.close();

    // Obtain QKD key with keyID
    system(("./sym-ExpQKD 'server' " + qkd_ip).c_str());
}

// Program usage help
void help()
{
    cout << endl
         << "   Usage:" << endl
         << endl;
    cout << "   ./encryptor_server [QKD IP]" << endl;
    cout << "   QKD IP - Local QKD system IP address {x.x.x.x} (optional)" << endl
         << endl;
}

// ECDH key exchange
void PerformECDHKeyExchange()
{
    CryptoPP::AutoSeededRandomPool rng;

    // Create TCP connection for ECDH key exchange
    int ecdh_fd;

    int client_fd = tcp_connection(&ecdh_fd);
    // TCP error propagation
    if (client_fd == -1)
    {
        perror("TCP connection error");
        exit(EXIT_FAILURE);
    }

    // Set up the NIST P-521 curve domain
    CryptoPP::ECDH<CryptoPP::ECP>::Domain dh(CryptoPP::ASN1::secp521r1());

    // Generate ECDH keys
    CryptoPP::SecByteBlock privateKey(dh.PrivateKeyLength());
    CryptoPP::SecByteBlock publicKey(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, privateKey, publicKey);

    // Receive the server's public key
    CryptoPP::SecByteBlock receivedKey(dh.PublicKeyLength());
    read(client_fd, receivedKey.BytePtr(), receivedKey.SizeInBytes());
    // Send public key to the server
    send(client_fd, publicKey.BytePtr(), publicKey.SizeInBytes(), 0);

    // Derive shared secret
    CryptoPP::SecByteBlock sharedSecret(dh.AgreedValueLength());
    dh.Agree(sharedSecret, privateKey, receivedKey);

    string hex;
    CryptoPP::HexEncoder hexEncoder(new CryptoPP::StringSink(hex), false);
    hexEncoder.Put(sharedSecret, sharedSecret.size());
    hexEncoder.MessageEnd();

    std::cout << "Hexadecimal representation: " << hex << std::endl;

    // Close the socket
    close(client_fd);
    
}

int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        help();
        return 0;
    }

    // First argument - QKD server IP address
    string qkd_ip = argv[1];

    //******** SERVER MODE: ********//

    // Virtual interface access
    int tundesc;
    tundesc = tun_open();

    // TCP connection status variable
    int status = -1;

    // Message for keeping dynamic NAT translation
    const char *keepalive = "Keep Alive";

    // Reference time for dynamic NAT translation
    time_t ref = time(NULL);

    // AES key variable creation
    SecByteBlock key(AES::MAX_KEYLENGTH);

    // Variables for UDP/TCP connections
    int server_fd;
    socklen_t len;
    struct sockaddr_in servaddr, cliaddr;

    // Get count of runnable threads (excluding main thread)
    int threads_max = std::thread::hardware_concurrency() - 1;
    std::atomic<int> threads_available = threads_max;

    GCM<AES, CryptoPP::GCM_64K_Tables>::Encryption e;
    AutoSeededRandomPool prng;

    while (1)
    {

        // Perform ECDH key exchange
        PerformECDHKeyExchange();

        shutdown(server_fd, SHUT_RDWR);

        // TCP connection create
        int new_socket = tcp_connection(&server_fd);

        // Establish PQC key
        string pqc_key = get_pqckey(new_socket);

        // UDP connection create
        int sockfd = udp_connection(&servaddr, &cliaddr, &len);

        // QKD keyID receive
        char bufferTCP[MAXLINE] = {0};
        read(new_socket, bufferTCP, MAXLINE);
        get_qkdkey(qkd_ip, bufferTCP);

        //******** KEY ESTABLISHMENT: ********//
        // Send the public key to the other party
        // Server connection details

        // Combine PQC a QKD key into hybrid key for AES
        key = rekey_srv(pqc_key);

        // Set TCP socket to NON-blocking mode
        fcntl(new_socket, F_SETFL, O_NONBLOCK);
        status = -1;

        // Return to "waiting on TCP connection" state if TCP connection seems dead
        while (status != 0)
        {

            /*
               Rekeying is initialized when keyID is recieved on TCP socket

               Parent process tasks:
               1) Terminate child (forked) process
               2) Get new AES key
               3) Create new child process

               Termination and creation of new child process is needed for key synchronization
            */

            // Get TCP connection status
            status = read(new_socket, bufferTCP, MAXLINE);
            // Establish new hybrid key, if key_ID is recieved
            if (status > 0)
            {
                get_qkdkey(qkd_ip, bufferTCP);
                key = rekey_srv(pqc_key);
            }

            // Create runnable thread if there are data available either on tun interface or UDP socket
            if (E_N_C_R(sockfd, cliaddr, &key, tundesc, len, &prng, e) || D_E_C_R(sockfd, servaddr, &key, tundesc))
            {
                if (threads_available > 0)
                {
                    threads_available -= 1;
                    std::thread(thread_encrypt, sockfd, servaddr, cliaddr, &key, tundesc, len, &threads_available, &prng, e).detach();
                }
            }

            // Sleep if no data are available
            if (threads_available == threads_max)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            // Help with encryption/decryption if all runnable threads are created
            if (threads_available == 0)
            {
                while (E_N_C_R(sockfd, cliaddr, &key, tundesc, len, &prng, e))
                {
                }

                while (D_E_C_R(sockfd, servaddr, &key, tundesc))
                {
                }
            }

            // Send "KeepAlive" message via UDP every 60s to keep dynamic NAT translation - no need to encrypt
            if (time(NULL) - ref >= 60)
            {
                sendto(sockfd, keepalive, strlen(keepalive), MSG_CONFIRM, (const struct sockaddr *)&cliaddr, len);
                ref = time(NULL);
            }
        }
        // Clean sockets termination
        close(sockfd);
        close(new_socket);
        shutdown(server_fd, SHUT_RDWR);
    }
}
