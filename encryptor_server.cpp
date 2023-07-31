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
#define PORT 62000
#define KEYPORT 61000
#define MAXLINE 1500
#define TAG_SIZE 16

//While cycle break
volatile bool stop = false;

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

// Threads termination after CTRL+C
void inthand(int signum) {
stop = true;
}

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
return true;
}
try{
data = decrypt_data(key, encrypted_data);
}
    catch(...)
    {
	return false;
    }

write_tun(tundesc, data);
return false;
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
return true;
}
string encrypted_data = encrypt_data(key, data);
send_encrypted (sockfd, servaddr, encrypted_data, len);
return false;
}


/*
   Rekeying - client mode

   Client get new key from QKD server, combine it with PQC key
   and than send its ID to gateway in server mode.
*/

SecByteBlock rekey_srv(string pqc_key){

CryptoPP::SHA256 hash;
byte digest[ CryptoPP::SHA256::DIGESTSIZE ];

SecByteBlock key( AES::MAX_KEYLENGTH );
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
return key;
}

// Program usage help
void help(){
cout << endl << "   Usage:" << endl << endl;
cout << "   ./encryptor_server [QKD IP]" << endl;
cout << "   QKD IP - Local QKD system IP address {x.x.x.x}" << endl;
}

int main(int argc, char* argv[])
{


if (argc < 2){
help();
return 0;
}

// First argument - QKD server IP address
string qkd_ip = argv[1];


//******** SERVER MODE: ********//


// PQC key establishment parameters and variables
constexpr size_t KEY_LEN = 32;
std::vector<uint8_t> cipher(kyber512_kem::CIPHER_LEN, 0);
std::vector<uint8_t> shrd_key(KEY_LEN, 0);
std::vector<uint8_t> m(KEY_LEN, 0);
prng::prng_t prng;
prng.read(m.data(), m.size());

SecByteBlock key( AES::MAX_KEYLENGTH );

// Virtual interface access
int tundesc;
tundesc = tun_open();


// TCP socket creation and "Hello" messages exchange
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[MAXLINE] = { 0 };
    const char* helloTCP = "Hello from server";

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(KEYPORT);

    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address))
        < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket
         = accept(server_fd, (struct sockaddr*)&address,
                  (socklen_t*)&addrlen))
        < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    read(new_socket, buffer, MAXLINE);
    printf("%s\n", buffer);
    send(new_socket, helloTCP, strlen(helloTCP), 0);
    printf("Hello message sent\n");

/*
   PQC key establishment:

   1) Server recieves client public key
   2) Server generate PQC key
   3) Server encapsulates PQC key with client's public key and
      sends to client
*/

    read(new_socket, buffer, MAXLINE);
    auto skdf = kyber512_kem::encapsulate(m.data(), (const uint8_t*)buffer, cipher.data());
    skdf.squeeze(shrd_key.data(), KEY_LEN);

    string pqc_key=kyber_utils::to_hex(shrd_key.data(), 32);
    send(new_socket, cipher.data(), cipher.size(), 0);

// UDP socket creation and "Hello" messages exchange
int sockfd;
    struct sockaddr_in servaddr, cliaddr;

    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family    = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    if ( bind(sockfd, (const struct sockaddr *)&servaddr,
            sizeof(servaddr)) < 0 )
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    socklen_t len;
  int n;

    len = sizeof(cliaddr);
const char *hello = "Hello from server";
 n = recvfrom(sockfd, (char *)buffer, MAXLINE,
                MSG_WAITALL, ( struct sockaddr *) &cliaddr,
                &len);
    buffer[n] = '\0';
    printf("Client : %s\n", buffer);
    sendto(sockfd, (const char *)hello, strlen(hello),
        MSG_CONFIRM, (const struct sockaddr *) &cliaddr,
            len);
    std::cout<<"Hello message sent."<<std::endl;

    fcntl(sockfd, F_SETFL, O_NONBLOCK);
	
	
char bufferTCP[MAXLINE] = { 0 };
std::ofstream myfile;


// QKD keyID receive
read(new_socket, bufferTCP, MAXLINE);

myfile.open ("keyID");
myfile<< bufferTCP;
myfile.close();

// Obtain QKD key with keyID
system(("./sym-ExpQKD 'server' " + qkd_ip).c_str());

// Combine PQC a QKD key into hybrid key for AES
key = rekey_srv(pqc_key);

// Set socket to NON-blocking mode
fcntl(new_socket, F_SETFL, O_NONBLOCK);

// Process fork for more CPUs utilization
pid_t frk = fork();

// CTRL + C listener for clean program termination
signal(SIGINT, inthand);

// TCP connection status variable
int status;
// Message for keeping dynamic NAT translation
const char* keepalive = "Keep Alive";
// Reference time for dynamic NAT translation
time_t ref = time(NULL);
while (!stop){

/*
   Rekeying is initialized when keyID is recieved on TCP socket

   Parent process tasks:
   1) Terminate child (forked) process
   2) Get new AES key
   3) Create new child process

   Termination and creation of new child process is needed for key synchronization
*/

if (frk > 0){
status = read(new_socket, bufferTCP, MAXLINE);
if (status == 0){
stop = true;
}
else if(status > 0){
kill(frk, SIGTERM);
myfile.open ("keyID");
myfile<< bufferTCP;
myfile.close();

system(("./sym-ExpQKD 'server' " + qkd_ip).c_str());

key = rekey_srv(pqc_key);
frk = fork();
}
}

// Data encryption from virtual interface
while(! E_N_C_R (sockfd, cliaddr, key, tundesc, len)){
}

// Data decryption from UDP socket
while(! D_E_C_R (sockfd, servaddr, key, tundesc)){
}

usleep(100);
if (time(NULL)-ref>=1){
// Send "KeepAlive" message for dynamic NAT purposes
send(new_socket, keepalive, strlen(keepalive), 0);
sendto(sockfd, keepalive, strlen(keepalive), MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);
ref = time(NULL);
}
}
// Clean program termination
kill(frk, SIGTERM);
close(sockfd);
close(new_socket);
shutdown(server_fd, SHUT_RDWR);
close(tundesc);
return 0;
}
