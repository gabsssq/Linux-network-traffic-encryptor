#include <kyber512_kem.hpp>
#include <thread>
#include <ctime>
#include <chrono>
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

string xy_str;
string cipher_data_str;

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
    catch (CryptoPP::Exception &ex)
    {
        cerr << ex.what() << endl;
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
void thread_encrypt(int sockfd, struct sockaddr_in servaddr, SecByteBlock *key, int tundesc, socklen_t len, std::atomic<int> *threads, AutoSeededRandomPool *prng, GCM<AES, CryptoPP::GCM_64K_Tables>::Encryption e)
{
    for (int i = 0; i < 100; i++)
    {
        while (E_N_C_R(sockfd, servaddr, key, tundesc, len, prng, e))
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
SecByteBlock rekey_cli(int client_fd, string pqc_key, string qkd_ip, string ecdh_key)
{

    CryptoPP::SHA3_256 hash;
    byte digest[CryptoPP::SHA3_256::DIGESTSIZE];

    SecByteBlock key(AES::MAX_KEYLENGTH);

    system(("./sym-ExpQKD 'client' " + qkd_ip).c_str());

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

    std::ifstream s("keyID");
    std::stringstream bufferTCP;
    bufferTCP << s.rdbuf();

    send(client_fd, bufferTCP.str().c_str(), bufferTCP.str().length(), 0);

    return key;
}

// TCP socket creation and "Hello" messages exchange
int tcp_connection(const char *srv_ip)
{
    int status, client_fd;
    struct sockaddr_in serv_addr;
    const char *helloTCP = "Hello from client";
    char buffer[MAXLINE] = {0};

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(KEYPORT);

    if (inet_pton(AF_INET, srv_ip, &serv_addr.sin_addr) <= 0)
    {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }
    cout << "Atempting connection to server \n";

    for (int i = 1; i < 4; i++)
    {
        sleep(3);

        if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                              sizeof(serv_addr))) < 0)
        {

            cout << "\nConnection Failed ... Retrying " << i << "/3\n";
        }
        else
        {
            break;
        }

        if (i == 3)
        {
            cout << "Can't connect to server... exiting \n";
            return -1;
        }
    }

    send(client_fd, helloTCP, strlen(helloTCP), 0);
    read(client_fd, buffer, MAXLINE);
    cout << "Connected to server \n";
    return client_fd;
}

// UDP socket creation and "Hello" messages exchange
int udp_connection(struct sockaddr_in *pt_servaddr, socklen_t *pt_len, const char *srv_ip)
{
    int sockfd;
    struct sockaddr_in servaddr;
    char buffer[MAXLINE] = {0};

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(srv_ip);
    servaddr.sin_port = htons(PORT);

    socklen_t len;
    int n;
    const char *hello = "Hello from client";

    sendto(sockfd, (const char *)hello, strlen(hello),
           MSG_CONFIRM, (const struct sockaddr *)&servaddr,
           sizeof(servaddr));
    std::cout << "Hello message sent." << std::endl;

    memset(&buffer, 0, sizeof(buffer));
    n = recvfrom(sockfd, (char *)buffer, MAXLINE,
                 MSG_WAITALL, (struct sockaddr *)&servaddr,
                 &len);
    buffer[n] = '\0';
    std::cout << "Server: " << buffer << std::endl;

    // Set socket to NON-blocking mode
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    *pt_servaddr = servaddr;
    *pt_len = len;
    return sockfd;
}

// PQC key establishment
string get_pqckey(int client_fd)
{
    constexpr size_t SEED_LEN = 32;
    constexpr size_t KEY_LEN = 32;

    // Seeds required for keypair generation
    std::vector<uint8_t> _d(SEED_LEN, 0);
    std::vector<uint8_t> _z(SEED_LEN, 0);

    auto d = std::span<uint8_t, SEED_LEN>(_d);
    auto z = std::span<uint8_t, SEED_LEN>(_z);

    // Public/private keypair
    std::vector<uint8_t> _pkey(kyber512_kem::PKEY_LEN, 0);
    std::vector<uint8_t> _skey(kyber512_kem::SKEY_LEN, 0);

    auto pkey = std::span<uint8_t, kyber512_kem::PKEY_LEN>(_pkey);
    auto skey = std::span<uint8_t, kyber512_kem::SKEY_LEN>(_skey);

    // Seed required for key encapsulation
    std::vector<uint8_t> _m(SEED_LEN, 0);
    auto m = std::span<uint8_t, SEED_LEN>(_m);

    // Shared secret that sender/receiver arrives at
    std::vector<uint8_t> _shrd_key(KEY_LEN, 0);

    auto shrd_key = std::span<uint8_t, KEY_LEN>(_shrd_key);
    // Pseudo-randomness source
    prng::prng_t prng_pqc;

    // Fill up seeds using PRNG
    prng_pqc.read(d);
    prng_pqc.read(z);

    // Generate a keypair
    kyber512_kem::keygen(d, z, pkey, skey);

    // Fill up seed required for key encapsulation, using PRNG
    prng_pqc.read(m);

    /*
       PQC key establishment:
       Client sends public key to server, from which then receive
       encapsulated PQC key
    */
    std::vector<unsigned char> pqc_buffer(MAXLINE);
    send(client_fd, pkey.data(), pkey.size(), 0);
    read(client_fd, &pqc_buffer[0], MAXLINE);
    std::vector<uint8_t> _cipher(kyber512_kem::CIPHER_LEN, 0);
    _cipher = pqc_buffer;

    // take the first 216 bytes of the cipher text and put it in the new variable called cipher_data
    std::vector<uint8_t> cipher_data(_cipher.begin(), _cipher.begin() + 216);
    cipher_data_str = kyber_utils::to_hex(cipher_data);

    // Decapsulate cipher text and obtain KDF
    auto cipher = std::span<uint8_t, kyber512_kem::CIPHER_LEN>(_cipher);
    auto rkdf = kyber512_kem::decapsulate(skey, cipher);
    rkdf.squeeze(shrd_key);
    string pqc_key = kyber_utils::to_hex(shrd_key);

    return pqc_key;
}

// Program usage help
void help()
{
    cout << endl
         << "   Usage:" << endl
         << endl;
    cout << "   ./encryptor_client  [Server IP] [QKD IP]" << endl;
    cout << "   Server IP - IP address of server gateway {x.x.x.x}" << endl;
    cout << "   QKD IP - Local QKD system IP address {x.x.x.x} (optional)" << endl
         << endl;
}

string PerformECDHKeyExchange(int client_fd)
{
    /*close(client_fd);

    // Create TCP connection
    int custom_connection = tcp_connection(srv_ip);
    // TCP error propagation
    if (custom_connection == -1)
    {
        perror("TCP connection error");
        exit(EXIT_FAILURE);
    }*/

    CryptoPP::AutoSeededRandomPool rng;

    // Set up the NIST P-521 curve domain
    CryptoPP::ECDH<CryptoPP::ECP>::Domain dh(CryptoPP::ASN1::secp521r1());

    CryptoPP::Integer x = dh.GetGroupParameters().GetSubgroupGenerator().x;
    CryptoPP::Integer y = dh.GetGroupParameters().GetSubgroupGenerator().y;
    // take first 216 bytes of the x and y coordinates
    string x_str = CryptoPP::IntToString(x);
    string y_str = CryptoPP::IntToString(y);
    string xy_str = x_str.substr(0, 108) + y_str.substr(0, 108);

    // Generate ECDH keys
    CryptoPP::SecByteBlock privateKey(dh.PrivateKeyLength());
    CryptoPP::SecByteBlock publicKey(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, privateKey, publicKey);

    // Send public key to the server
    send(client_fd, publicKey.BytePtr(), publicKey.SizeInBytes(), 0);

    // Receive the server's public key
    CryptoPP::SecByteBlock receivedKey(dh.PublicKeyLength());
    read(client_fd, receivedKey.BytePtr(), receivedKey.SizeInBytes());

    // Derive shared secret
    CryptoPP::SecByteBlock sharedSecret(dh.AgreedValueLength());
    std::cout << dh.Agree(sharedSecret, privateKey, receivedKey) << std::endl;

    string hex;
    CryptoPP::HexEncoder hexEncoder(new CryptoPP::StringSink(hex), false);
    hexEncoder.Put(sharedSecret, sharedSecret.size());
    hexEncoder.MessageEnd();

    std::cout << "Hexadecimal representation: " << hex << std::endl;

    /*
    // Close the socket
    close(custom_connection);
    client_fd = tcp_connection(srv_ip);
    */

    return hex;
}

int main(int argc, char *argv[])
{

    if (argc < 3)
    {
        help();
        return 0;
    }

    // First argument - IP of gateway in server mode
    const char *srv_ip = argv[1];

    // Second argument - QKD server IP address (optional)
    string qkd_ip = argv[2];

    //******** CLIENT MODE: ********//

    // Virtual interface access
    int tundesc;
    tundesc = tun_open();

    // Variables for UDP connection
    socklen_t len;
    struct sockaddr_in servaddr;

    // AES key variable creation
    SecByteBlock key(AES::MAX_KEYLENGTH);

    // Get count of runnable threads (excluding main thread)
    int threads_max = std::thread::hardware_concurrency() - 1;
    std::atomic<int> threads_available = threads_max;

    GCM<AES, CryptoPP::GCM_64K_Tables>::Encryption e;
    AutoSeededRandomPool prng;

    // Create empty TCP buffer for getting status on TCP connection
    char bufferTCP[MAXLINE] = {0};

    // Time reference variable for rekey purposes
    time_t ref = time(NULL);

    while (1)
    {
        int status = -1;

        // Create TCP connection
        int client_fd = tcp_connection(srv_ip);

        // TCP error propagation
        if (client_fd == -1)
        {
            return -1;
        }

        // ECDH key exchange
        // Perform ECDH key exchange
        string ecdh_key = PerformECDHKeyExchange(client_fd);
        // Establish PQC key
        string pqc_key = get_pqckey(client_fd);

        cout << "PQC key: " << pqc_key << endl;

        
        // Create UDP connection
        int sockfd = udp_connection(&servaddr, &len, srv_ip);

        cout << "UDP connection established" << endl;
        
        // Set TCP socket to non-blocking state
        fcntl(client_fd, F_SETFL, O_NONBLOCK);


        while (status != 0)
        {
            // Establish new hybrid key
            key = rekey_cli(client_fd, pqc_key, qkd_ip, ecdh_key);
            ref = time(NULL);

            cout << "New key established" << endl;

            // Trigger Rekey after some period of time (10 min)
            while (time(NULL) - ref <= 600)
            {

                // Get TCP connection status
                status = read(client_fd, bufferTCP, MAXLINE);

                // If TCP connection is dead, return to TCP connection creation
                if (status == 0)
                {
                    break;
                }

                // Create runnable thread if there are data available either on tun interface or UDP socket
                if (E_N_C_R(sockfd, servaddr, &key, tundesc, len, &prng, e) || D_E_C_R(sockfd, servaddr, &key, tundesc))
                {
                    if (threads_available > 0)
                    {
                        threads_available -= 1;
                        std::thread(thread_encrypt, sockfd, servaddr, &key, tundesc, len, &threads_available, &prng, e).detach();
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
                    while (E_N_C_R(sockfd, servaddr, &key, tundesc, len, &prng, e))
                    {
                    }

                    while (D_E_C_R(sockfd, servaddr, &key, tundesc))
                    {
                    }
                }
            }
        }
        // Clean sockets termination
        close(client_fd);
        close(sockfd);
    }
}
