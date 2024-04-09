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
#include <mutex>

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
#include "cryptopp/shake.h"
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

string xy_str;
string kyber_cipher_data_str;
string qkd_parameter;
int counter = 0;

string convertToString(char *a)
{
    string s = a;
    return s;
}

std::atomic<int> enc_read_order = 0;
std::atomic<int> dec_read_order = 0;
std::atomic<int> enc_send_order = 1;
std::atomic<int> dec_send_order = 1;
std::mutex m1;
std::mutex m2;

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
   Get encryption order after reading from tun interface
*/

int enc_get_order()
{
    m1.lock();
    enc_read_order = (enc_read_order % 100000) + 1;
    int order = enc_read_order;
    m1.unlock();
    return order;
}

/*
   Get decription order after reading from socket
*/

int dec_get_order()
{
    m2.lock();
    dec_read_order = (dec_read_order % 100000) + 1;
    int order = enc_read_order;
    m2.unlock();
    return order;
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

    int order = enc_get_order();
//    cout << "\n dec order: " << order << endl;

    try
    {
        data = decrypt_data(key, encrypted_data);
    }
    catch (...)
    {
        while (order != enc_send_order)
        {
//            std::this_thread::sleep_for(std::chrono::nanoseconds(1));
        }
        enc_send_order = (enc_send_order % 100000) +1;
        return true;
    }
    while (order != enc_send_order)
    {
//        std::this_thread::sleep_for(std::chrono::nanoseconds(1));
    }

    write_tun(tundesc, data);
//    cout << "\n dec send order: " << enc_send_order << endl;
    enc_send_order = (enc_send_order % 100000) +1;
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

    int order = enc_get_order();
//    cout << "\n enc order: " << order << endl;
    string encrypted_data = encrypt_data(key, data, prng, &e);

    while (order != enc_send_order)
    {
//        std::this_thread::sleep_for(std::chrono::nanoseconds(1));
    }

    send_encrypted(sockfd, servaddr, encrypted_data, len);
//    cout << "\n enc send order: " << enc_send_order << endl;
    enc_send_order = (enc_send_order % 100000) +1;
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

// TCP socket creation and "Hello" messages exchange
int tcp_connection(int *pt_server_fd)
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[MAXLINE] = {0};
    const char *helloTCP = "Hello from server TCP";

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
    const char *hello = "Hello from server UDP";
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
    // read pqc buffer as string
    string pqc_string = convertToString((char *)&pqc_buffer[0]);

    std::vector<uint8_t> _pkey(kyber512_kem::PKEY_LEN, 0);
    _pkey = pqc_buffer;

    auto pkey = std::span<uint8_t, kyber512_kem::PKEY_LEN>(_pkey);
    auto skdf = kyber512_kem::encapsulate(m, pkey, cipher);
    skdf.squeeze(shrd_key);

    string pqc_key = kyber_utils::to_hex(shrd_key);
    send(new_socket, cipher.data(), cipher.size(), 0);
    // take the first 216 bytes of the cipher text and put it in the new variable called cipher_data
    std::vector<uint8_t> cipher_data(_cipher.begin(), _cipher.begin() + 216);
    kyber_cipher_data_str = kyber_utils::to_hex(cipher_data);
    return pqc_key;
}

void get_qkdkey(string qkd_ip, char bufferTCP[MAXLINE])
{

    CryptoPP::SHA3_256 hash;
    CryptoPP::SHAKE128 shake128_hash;

    std::ofstream myfile;
    myfile.open("keyID");
    myfile << bufferTCP;
    myfile.close();

    // Obtain QKD key with keyID
    system(("./sym-ExpQKD 'server' " + qkd_ip).c_str());

    // convert bufferTCP to string
    std::stringstream bufferTCP_string;
    bufferTCP_string << bufferTCP;
    cout << "QKD keyID recieved: " << bufferTCP_string.str() << endl;
    // hash content of bufferTCP with SHAKE128
    shake128_hash.Update((const byte *)bufferTCP_string.str().c_str(), bufferTCP_string.str().length());
    string pom_param;
    shake128_hash.TruncatedFinal((byte *)pom_param.c_str(), 216);
    qkd_parameter = pom_param + bufferTCP_string.str().substr(0, 216);
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
string PerformECDHKeyExchange(int socket)
{
    CryptoPP::AutoSeededRandomPool rng;

    // Set up the NIST P-521 curve domain
    CryptoPP::ECDH<CryptoPP::ECP>::Domain dh(CryptoPP::ASN1::secp521r1());

    // Generate ECDH keys
    CryptoPP::SecByteBlock privateKey(dh.PrivateKeyLength());
    CryptoPP::SecByteBlock publicKey(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, privateKey, publicKey);
    // print private and public key in hex format
    listen(socket, 1);
    string privKey;
    CryptoPP::HexEncoder privEncoder(new CryptoPP::StringSink(privKey), false);
    privEncoder.Put(privateKey, privateKey.size());
    privEncoder.MessageEnd();
    cout << "Private key: " << privKey << std::endl;

    string pubKey;
    CryptoPP::HexEncoder pubEncoder(new CryptoPP::StringSink(pubKey), false);
    pubEncoder.Put(publicKey, publicKey.size());
    pubEncoder.MessageEnd();
    cout << "Public key: " << pubKey << std::endl;

    // Receive the server's public key
    CryptoPP::SecByteBlock receivedKey(dh.PublicKeyLength());
    read(socket, receivedKey.BytePtr(), receivedKey.SizeInBytes());
    // print received key in hex format
    string recKey;
    CryptoPP::HexEncoder recEncoder(new CryptoPP::StringSink(recKey), false);
    recEncoder.Put(receivedKey, receivedKey.size());
    recEncoder.MessageEnd();
    cout << "Received key: " << recKey << std::endl;
    // Send public key to the server
    send(socket, publicKey.BytePtr(), publicKey.SizeInBytes(), 0);
    // print sent key in hex format
    string sentKey;
    CryptoPP::HexEncoder sentEncoder(new CryptoPP::StringSink(sentKey), false);
    sentEncoder.Put(publicKey, publicKey.size());
    sentEncoder.MessageEnd();
    cout << "Sent key: " << sentKey << std::endl;

    // Derive shared secret
    CryptoPP::SecByteBlock sharedSecret(dh.AgreedValueLength());
    dh.Agree(sharedSecret, privateKey, receivedKey);

    string hex;
    CryptoPP::HexEncoder hexEncoder(new CryptoPP::StringSink(hex), false);
    hexEncoder.Put(sharedSecret, sharedSecret.size());
    hexEncoder.MessageEnd();

    std::cout << "Hexadecimal representation: " << hex << std::endl;
    CryptoPP::Integer x = dh.GetGroupParameters().GetSubgroupGenerator().x;
    CryptoPP::Integer y = dh.GetGroupParameters().GetSubgroupGenerator().y;
    // take first 216 bytes of the x and y coordinates
    string x_str = CryptoPP::IntToString(x);
    string y_str = CryptoPP::IntToString(y);
    xy_str = x_str.substr(0, 216) + y_str.substr(0, 216);

    /*
    // Close the socket
    close(custom_connection);
    client_fd = tcp_connection(srv_ip);
    */

    return hex;
}

string hmac_hashing(string &salt, string &key)
{
    /*
        CryptoPP::HMAC<CryptoPP::SHA3_256> hmac((const byte *)salt.c_str(), salt.length());

        hmac.Update((const byte *)key.c_str(), key.length());
        byte hmac_digest[CryptoPP::SHA3_256::DIGESTSIZE];
        hmac.Final(hmac_digest);

        // write hmac_digest to string
        CryptoPP::HexEncoder encoder;
        string hmac_output;
        encoder.Attach(new CryptoPP::StringSink(hmac_output));
        encoder.Put(hmac_digest, sizeof(hmac_digest));
        encoder.MessageEnd();

        return hmac_output;
        */
    const size_t desired_length = 216;

    string padded_key(salt);
    string padded_message(key);

    // Pad the key and message with zeros if needed
    if (padded_key.size() < desired_length)
    {
        padded_key.resize(desired_length, '\0');
    }

    if (padded_message.size() < desired_length)
    {
        padded_message.resize(desired_length, '\0');
    }

    CryptoPP::HMAC<CryptoPP::SHA3_256> hmac((const byte *)padded_key.data(), padded_key.size());
    string result;

    CryptoPP::StringSource(padded_message, true, new CryptoPP::HashFilter(hmac, new CryptoPP::HexEncoder(new CryptoPP::StringSink(result))));

    return result;
}

string sha3_hashing(string key, string *public_value)
{

    CryptoPP::SHA3_256 hash;

    byte digest[CryptoPP::SHA3_256::DIGESTSIZE];
    string concat = *public_value + key;
    hash.CalculateDigest(digest, (byte *)concat.c_str(), concat.length());

    // write digest to string
    CryptoPP::HexEncoder encoder;
    string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
    *public_value = output;

    return output;
}

string xorStrings(const string &str1, const string &str2)
{
    // Ensure the strings have the same length
    if (str1.length() != str2.length())
    {
        throw std::runtime_error("Strings must have the same length for XOR operation");
    }

    // Result string
    string result;

    // XOR each pair of characters
    for (std::size_t i = 0; i < str1.length(); ++i)
    {
        result += static_cast<char>(str1[i] ^ str2[i]);
    }

    return result;
}

/*
   Rekeying - client mode

   Client get new key from QKD server, combine it with PQC key
   and than send its ID to gateway in server mode.
*/

SecByteBlock rekey_srv(int new_socket, string qkd_ip)
{
    CryptoPP::SHA3_256 hash;
    CryptoPP::SHAKE128 shake128_hash;
    byte digest[CryptoPP::SHA3_256::DIGESTSIZE];
    SecByteBlock sec_key(AES::MAX_KEYLENGTH);
    counter++;
    // get system time and convert it to string
    time_t now = time(0);
    tm *ltm = localtime(&now);
    string time = std::to_string(ltm->tm_hour) + std::to_string(ltm->tm_min) + std::to_string(ltm->tm_sec);
    string salt = time + std::to_string(counter);
    salt = "wBvFh#7QjH8tLpNkRsYx1z3uA2s4Xc6WvBnMlKjIgFhDdSfGhJkLpOeQrTbUyVtXyZaCxwVuNmLkIjHgFdDsAaSdFgHjKlQwErTyUiOpAsDfGhJkLpOeRtYuIwQeRtYuI";

    string pqc_key = get_pqckey(new_socket);
    cout << "PQC key established:" << pqc_key << "\n";
    listen(new_socket, 3);
    string ecdh_key = PerformECDHKeyExchange(new_socket);

    if (qkd_ip.empty())
    {

        // all parameters set, starting to creating hybrid key
        string key_one = hmac_hashing(salt, pqc_key);
        cout << "Key one: " << key_one << endl;
        string key_two = hmac_hashing(salt, ecdh_key);
        cout << "Key two: " << key_two << endl;

        string param_one = sha3_hashing(pqc_key, &kyber_cipher_data_str);
        cout << "Param one: " << param_one << endl;
        string param_two = sha3_hashing(ecdh_key, &xy_str);
        cout << "Param two: " << param_two << endl;

        string second_round_param_one = param_one + param_two;
        string second_round_key_one = hmac_hashing(key_one, second_round_param_one);
        cout << "Second round key one: " << second_round_key_one << endl;
        string second_round_key_two = hmac_hashing(key_two, second_round_param_one);
        cout << "Second round key two: " << second_round_key_two << endl;

        string key = xorStrings(second_round_key_one, second_round_key_two);
        cout << "Key: " << key << endl;

        // hash final key with SHA3_256
        hash.CalculateDigest(digest, (byte *)key.c_str(), key.length());
        CryptoPP::HexEncoder encode_key;
        string output_key;
        encode_key.Attach(new CryptoPP::StringSink(output_key));
        encode_key.Put(digest, sizeof(digest));
        encode_key.MessageEnd();

        cout << "Key established: " << output_key << endl;

        int x = 0;
        for (unsigned int i = 0; i < output_key.length(); i += 2)
        {
            string bytestring = output_key.substr(i, 2);
            sec_key[x] = (char)strtol(bytestring.c_str(), NULL, 16);
            x++;
        }

        // output kyber cipher data, xy coordinates and qkd parameter
        cout << "Kyber cipher data: " << kyber_cipher_data_str << endl;
        cout << "XY coordinates: " << xy_str << endl;

        return sec_key;
    }
    else
    {

        std::ifstream t("key");
        std::stringstream buffer;
        buffer << t.rdbuf();
        string buffer_str = buffer.str();
        cout << "Buffer: " << buffer_str << endl;

        // all parameters set, starting to creating hybrid key
        string key_one = hmac_hashing(salt, pqc_key);
        string key_two = hmac_hashing(salt, ecdh_key);
        string key_three = hmac_hashing(salt, buffer_str);

        string param_one = sha3_hashing(pqc_key, &kyber_cipher_data_str);
        string param_two = sha3_hashing(ecdh_key, &xy_str);
        string param_three = sha3_hashing(buffer_str, &qkd_parameter);

        string second_round_param_one = param_two + param_three;
        string second_round_param_two = param_one + param_three;
        string second_round_param_three = param_one + param_two;
        string second_round_key_one = hmac_hashing(key_one, second_round_param_one);
        string second_round_key_two = hmac_hashing(key_two, second_round_param_two);
        string second_round_key_three = hmac_hashing(key_three, second_round_param_three);

        string third_round_key_one = xorStrings(second_round_key_one, second_round_key_two);
        string fourth_round_key_one = xorStrings(third_round_key_one, second_round_key_three);

        string key = xorStrings(third_round_key_one, fourth_round_key_one);

        // hash final key with SHA3_256
        hash.CalculateDigest(digest, (byte *)key.c_str(), key.length());
        CryptoPP::HexEncoder encode_key;
        string output_key;
        encode_key.Attach(new CryptoPP::StringSink(output_key));
        encode_key.Put(digest, sizeof(digest));
        encode_key.MessageEnd();

        int x = 0;
        for (unsigned int i = 0; i < output_key.length(); i += 2)
        {
            string bytestring = output_key.substr(i, 2);
            sec_key[x] = (char)strtol(bytestring.c_str(), NULL, 16);
            x++;
        }

        cout << "Key established:" << output_key << "\n";

        return sec_key;
    }
}

int main(int argc, char *argv[])
{

    /*if (argc < 2)
    {
        help();
        return 0;
    }*/
    string qkd_ip = "";
    // First argument - QKD server IP address
    if (argv[1] != NULL)
    {
        qkd_ip = argv[1];
        ;
    }

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

        // TCP connection create
        int new_socket = tcp_connection(&server_fd);

        // Perform ECDH key exchange
        // string ecdh_key = PerformECDHKeyExchange(new_socket);
        // Establish PQC key
        // string pqc_key = get_pqckey(new_socket);

        // UDP connection create
        int sockfd = udp_connection(&servaddr, &cliaddr, &len);

        char bufferTCP[MAXLINE] = {0};
        
        read(new_socket, bufferTCP, MAXLINE);

        if (argv[1] != NULL)
        {
            // QKD keyID receive
            get_qkdkey(qkd_ip, bufferTCP);
        }

        //******** KEY ESTABLISHMENT: ********//
        // Send the public key to the other party
        // Server connection details
        // get_qkdkey(qkd_ip, bufferTCP);
        // Combine PQC a QKD key into hybrid key for AES
        key = rekey_srv(new_socket, qkd_ip);
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
                fcntl(new_socket, F_SETFL, fcntl(new_socket, F_GETFL, 0) & ~O_NONBLOCK);

                if (argv[1] != NULL)
                {
                    // QKD keyID receive
                    get_qkdkey(qkd_ip, bufferTCP);
                }
                key = rekey_srv(new_socket, qkd_ip);
                // set socket to non-blocking mode
                // Set TCP socket to NON-blocking mode
            }
            fcntl(new_socket, F_SETFL, O_NONBLOCK);
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
