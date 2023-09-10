#include "kyber512_kem.hpp"
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
#define PORT 62000
#define KEYPORT 61000
#define MAXLINE 1500
#define TAG_SIZE 16

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::byte;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::SecByteBlock;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "assert.h"


string convertToString(char* a)
{
    string s = a;
    return s;
}

// Virtual interface access
int tun_open()
{
  struct ifreq ifr;
  int fd, err;

  if ( (fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) == -1 ) {
       perror("open /dev/net/tun");exit(1);
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

  if ( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) == -1 ) {
    perror("ioctl TUNSETIFF");close(fd);exit(1);
  }

  return fd;
}


// Encrypted data recieve
string data_recieve(int sockfd, struct sockaddr_in servaddr){

socklen_t len;
    char buffer[MAXLINE] = { 0 };
    int n;

    n = recvfrom(sockfd, (char *)buffer, MAXLINE, 
                MSG_WAITALL, (struct sockaddr *) &servaddr,
                &len);

if (n == -1){
return "";
}

string recieved(buffer, n);

return recieved;
}

// Virtual interface data read
string read_tun(int tundesc){

char buf[MAXLINE-60];
int nbytes = read(tundesc, buf, sizeof(buf));
if (nbytes==-1){
return "";
}
string data(buf, nbytes);

return data;
}


/* Virtual interface data write.
   Data will appear as if it arrived at
   virtual interface and can be routed further */

void write_tun(int tundesc, string message){
char buf[MAXLINE-60];
memcpy(buf, message.data(), message.length());
int nbytes = write(tundesc, buf, message.length());
}


// Send encrypted data
void send_encrypted(int sockfd, struct sockaddr_in servaddr, string cipher, socklen_t len){

    char *cp = &cipher[0];
    sendto(sockfd, cp, cipher.length(), MSG_CONFIRM, (const struct sockaddr *) &servaddr, len);

}


// Data encryption
string encrypt_data(SecByteBlock key, string message){
string cipher;
AutoSeededRandomPool prng;
byte iv[ AES::BLOCKSIZE ];
prng.GenerateBlock( iv, sizeof(iv));

    GCM< AES, CryptoPP::GCM_64K_Tables >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv, sizeof(iv) );


try
{

    StringSource ss1( message, true,
        new AuthenticatedEncryptionFilter( e,
            new StringSink( cipher ), false, TAG_SIZE
        )
    );

}
catch( CryptoPP::Exception& e )
{
    cerr << e.what() << endl;
   exit(1);
}

string encrypted((char *)iv, sizeof(iv));

encrypted += cipher;

return encrypted;
}


// Data decryption + integrity check
string decrypt_data(SecByteBlock key, string cipher){

string rpdata;
byte iv[ AES::BLOCKSIZE ];
memcpy(iv, cipher.data(), sizeof(iv));


        GCM< AES, CryptoPP::GCM_64K_Tables >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv));

        AuthenticatedDecryptionFilter df( d,
            new StringSink( rpdata ),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
            TAG_SIZE
        );

        StringSource ss2( cipher.substr(sizeof(iv)), true,
            new Redirector( df)
        );

        bool b = df.GetLastResult();
        assert( true == b );

return rpdata;
}

/*
   Aggregation of functions needed for data recieve:
   1) Receive incoming encrypted data
   2) Decrypt data and check integrity
   3) Write decrypted data to virtual interface

   Returns false if there are no more data available on socket.
*/

bool D_E_C_R (int sockfd, struct sockaddr_in servaddr, SecByteBlock key, int tundesc){
string data;
string encrypted_data = data_recieve(sockfd, servaddr);
if (encrypted_data.length() == 0){
return false;
}
try{
data = decrypt_data(key, encrypted_data);
}
    catch(...)
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

bool E_N_C_R (int sockfd, struct sockaddr_in servaddr, SecByteBlock key, int tundesc, socklen_t len){
string data = read_tun(tundesc);

if (data.length()==0){
return false;
}
string encrypted_data = encrypt_data(key, data);
send_encrypted (sockfd, servaddr, encrypted_data, len);
return true;
}

// Thread function for both encryption and decryption
void thread_encrypt (int sockfd, struct sockaddr_in servaddr, SecByteBlock* key_ref, int tundesc, socklen_t len, std::atomic<int>* ctr, std::atomic<int>* threads){
for (int i = 0; i < 100; i++){
SecByteBlock key = *key_ref;
while(E_N_C_R (sockfd, servaddr, key, tundesc, len)){
*ctr += 1;
}

while(D_E_C_R (sockfd, servaddr, key, tundesc)){
*ctr += 1;
}
}
*threads += 1;
}

/*
   Rekeying - client mode

   Client get new key from QKD server, combine it with PQC key
   and than send its ID to gateway in server mode.
*/
SecByteBlock rekey_cli(int client_fd, string pqc_key, string qkd_ip){

CryptoPP::SHA256 hash;
byte digest[ CryptoPP::SHA256::DIGESTSIZE ];

SecByteBlock key( AES::MAX_KEYLENGTH );

system(("./sym-ExpQKD 'client' " + qkd_ip).c_str());

std::ifstream t("key");
std::stringstream buffer;
buffer << t.rdbuf();

std::string message = buffer.str() + pqc_key;
hash.CalculateDigest( digest, (byte*) message.c_str(), message.length() );
CryptoPP::HexEncoder encoder;
std::string output;
encoder.Attach( new CryptoPP::StringSink( output ) );
encoder.Put( digest, sizeof(digest) );
encoder.MessageEnd();

int x = 0;
for (unsigned int i = 0; i < output.length(); i += 2) {
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

// Program usage help
void help(){
cout << endl << "   Usage:" << endl << endl;
cout << "   ./encryptor_client [QKD IP] [Server IP]" << endl;
cout << "   QKD IP - Local QKD system IP address {x.x.x.x}" << endl;
cout << "   Server IP - IP address of server gateway {x.x.x.x}" << endl << endl;
}

int main(int argc, char* argv[])
{

if (argc < 3){
help();
return 0;
}

// First argument - QKD server IP address
string qkd_ip = argv[1];

// Second argument - IP of gateway in server mode
const char* srv_ip = argv[2];


//******** CLIENT MODE: ********//


// PQC key establishment parameters and variables
 constexpr size_t SEED_LEN = 32;
 constexpr size_t KEY_LEN = 32;
// Seeds required for keypair generation
 std::vector<uint8_t> d(SEED_LEN, 0);
 std::vector<uint8_t> z(SEED_LEN, 0);

 // Public/private keypair
 std::vector<uint8_t> pkey(kyber512_kem::PKEY_LEN, 0);
 std::vector<uint8_t> skey(kyber512_kem::SKEY_LEN, 0);

 // Seed required for key encapsulation
 std::vector<uint8_t> m(SEED_LEN, 0);
 std::vector<uint8_t> cipher(kyber512_kem::CIPHER_LEN, 0);

 // Shared secret that sender/receiver arrives at
 std::vector<uint8_t> shrd_key(KEY_LEN, 0);

 // Pseudo-randomness source
 prng::prng_t prng;

 // Fill up seeds using PRNG
 prng.read(d.data(), d.size());
 prng.read(z.data(), z.size());

 // Generate a keypair
 kyber512_kem::keygen(d.data(), z.data(), pkey.data(), skey.data());

 // Fill up seed required for key encapsulation, using PRNG
 prng.read(m.data(), m.size());


// AES key variable creation
SecByteBlock key( AES::MAX_KEYLENGTH );

// Virtual interface access
int tundesc;
tundesc = tun_open();

// TCP socket creation and "Hello" messages exchange
int status, client_fd;
    struct sockaddr_in serv_addr;
    const char* helloTCP = "Hello from client";
    char buffer[MAXLINE] = { 0 };

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
  
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(KEYPORT);
  
    if (inet_pton(AF_INET, srv_ip, &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }
  
    if ((status
         = connect(client_fd, (struct sockaddr*)&serv_addr,
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    send(client_fd, helloTCP, strlen(helloTCP), 0);
    printf("Hello message sent\n");
    read(client_fd, buffer, MAXLINE);
    printf("%s\n", buffer);

/*
   PQC key establishment:
   Client sends public key to server, from which then receive
   encapsulated PQC key
*/

    send(client_fd, pkey.data(), pkey.size(), 0);
    read(client_fd, buffer, MAXLINE);

// Decapsulate cipher text and obtain KDF
    auto rkdf = kyber512_kem::decapsulate(skey.data(),(const uint8_t*) buffer);
    rkdf.squeeze(shrd_key.data(), KEY_LEN);
    string pqc_key = kyber_utils::to_hex(shrd_key.data(), KEY_LEN);

// UDP socket creation and "Hello" messages exchange
int sockfd;
    struct sockaddr_in servaddr;

    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family    = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(srv_ip);
    servaddr.sin_port = htons(PORT);

    socklen_t len;
  int n;
const char *hello = "Hello from client";

    sendto(sockfd, (const char *)hello, strlen(hello),
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));
    std::cout<<"Hello message sent."<<std::endl;

  memset(&buffer, 0, sizeof(buffer));
    n = recvfrom(sockfd, (char *)buffer, MAXLINE,
                MSG_WAITALL, (struct sockaddr *) &servaddr,
                &len);
    buffer[n] = '\0';
    std::cout<<"Server :"<<buffer<<std::endl;


// Set socket to NON-blocking mode

fcntl(sockfd, F_SETFL, O_NONBLOCK);

// AES key set
key = rekey_cli(client_fd, pqc_key, qkd_ip);

// Process fork for more CPUs utilization
string encoded;

// Get count of runnable threads (- main thread)
int threads_max = std::thread::hardware_concurrency()-1;
std::atomic<int> threads_available = threads_max;

// Counter for rekeying purposes
std::atomic<int> counter = 0;

while (1){

// Counter value for rekeying signalization
while (counter<200000){


// Create runnable thread if there are data available either on tun interface or UDP socket
if (E_N_C_R (sockfd, servaddr, key, tundesc, len) || D_E_C_R (sockfd, servaddr, key, tundesc)) {
counter ++;
if (threads_available > 0){
threads_available -=1;
std::thread (thread_encrypt, sockfd, servaddr, &key, tundesc, len, &counter, &threads_available).detach();
}
}

// Sleep if no data are available
if (threads_available == threads_max) {
std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

// Help with encryption/decryption if all runnable threads are created
if (threads_available == 0){
while(E_N_C_R (sockfd, servaddr, key, tundesc, len)){
counter++;
}

while(D_E_C_R (sockfd, servaddr, key, tundesc)){
counter++;
}
}


}
// Rekey after counter hits predefined value
key = rekey_cli(client_fd, pqc_key, qkd_ip);
counter = 0;
}
// Clean program termination
close(client_fd);
close(sockfd);
close(tundesc);
return 0;
}
