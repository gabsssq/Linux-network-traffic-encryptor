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

//Globalni promenna pro preruseni while cyklu
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

// Funkce pro ukonceni programu pri kombinaci CTRL+C
void inthand(int signum) {
stop = true;
}

string convertToString(char* a)
{
    string s = a;
    return s;
}

// Ziskani file descriptoru pro cteni a zapis do virtualniho rozhrani
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


// Funkce pro prijem sifrovanych dat poslanych pres UDP
string Prijem(int sockfd, struct sockaddr_in servaddr){

socklen_t len;
    char buffer[MAXLINE] = { 0 };
    int n;

    n = recvfrom(sockfd, (char *)buffer, MAXLINE, 
                MSG_WAITALL, (struct sockaddr *) &servaddr,
                &len);

if (n == -1){
return "";
}

string prijmuto(buffer, n);

return prijmuto;
}

// Funkce pro cteni z virtualniho rozhrani
string CtenizTUN(int tundesc){

char buf[MAXLINE-60];
int nbytes = read(tundesc, buf, sizeof(buf));
if (nbytes==-1){
return "";
}
string retez(buf, nbytes);

return retez;
}


/* Funkce pro zapis do virtualniho rozhrani.
   Data se budou jevit, jako by prisla na
   virt. rozhrani a budou dale smerovana  */
void ZapisdoTUN(int tundesc, string zprava){
char buf[MAXLINE-60];
memcpy(buf, zprava.data(), zprava.length());
int nbytes = write(tundesc, buf, zprava.length());
string retez(buf, nbytes);
}


// Posilani sifrovanych dat na druhou branu pres UDP
void Posilani(int sockfd, struct sockaddr_in servaddr, string poslani, socklen_t len){

    char *hello = &poslani[0];
    sendto(sockfd, hello, poslani.length(), MSG_CONFIRM, (const struct sockaddr *) &servaddr, len);

}


// Sifrovani dat, pridani TAG a IV
string Sifrovani(SecByteBlock key, string zprava){
string cipher;
AutoSeededRandomPool prng;
byte iv[ AES::BLOCKSIZE ];
prng.GenerateBlock( iv, sizeof(iv));

    GCM< AES, CryptoPP::GCM_64K_Tables >::Encryption e;
    e.SetKeyWithIV( key, key.size(), iv, sizeof(iv) );


try
{

    StringSource ss1( zprava, true,
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

string poslani((char *)iv, sizeof(iv));

poslani += cipher;

return poslani;
}


// Funkce pro desifrovni a kontrolu integrity
string Desifrovani(SecByteBlock key, string cipher){

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
   Agregace funkci pro desifrovani:
   1) Prijem sifrovanych dat pres UDP
   2) Desifrovani a kontrola integrity
   3) Zapis do virtualniho rozhrani

   Funkce vraci true nebo false, podle toho, zda
   jsou dostupna dalsi data na UDP socketu

*/
bool D_E_C_R (int sockfd, struct sockaddr_in servaddr, SecByteBlock key, int tundesc){
string text;
string sifrtext = Prijem(sockfd, servaddr);
if (sifrtext.length() == 0){
return true;
}
try{
text = Desifrovani(key, sifrtext);
}
    catch(...)
    {
	return false;
    }

ZapisdoTUN(tundesc, text);
return false;
}

/*
   Agregace funkci pro sifrovani:
   1) Cteni dat z virtualniho rozhrani
   2) Sifrovani dat
   3) Poslani pres UDP

   Funkce vraci true nebo false, podle toho, zda
   jsou dostupna dalsi data na virtualnim rozhrani

*/

bool E_N_C_R (int sockfd, struct sockaddr_in servaddr, SecByteBlock key, int tundesc, socklen_t len){
string text = CtenizTUN(tundesc);

if (text.length()==0){
return true;
}
string sifrtext = Sifrovani(key, text);
Posilani (sockfd, servaddr, sifrtext, len);
return false;
}


/*
   Vymena klice v rezimu serveru

   Funkce zkombinuje vyjednany PQC klic a klic
   ziskany z QKD serveru pomoci SHA-256
*/
SecByteBlock VymenaKlice_srv(string pqc_key){

CryptoPP::SHA256 hash;
byte digest[ CryptoPP::SHA256::DIGESTSIZE ];

SecByteBlock key( AES::MAX_KEYLENGTH );
std::ifstream t("klic");
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

// Vypis pouziti programu
void help(){
cout << endl << "   Pouziti:" << endl << endl;
cout << "   ./sifrator_server.exe [QKD IP]" << endl;
cout << "   QKD IP - IP adresa dosazitelneho QKD serveru" << endl;
}

int main(int argc, char* argv[])
{


if (argc < 2){
help();
return 0;
}

// Prvni argument je IP QKD serveru
string qkd_ip = argv[1];


//******** MOD SERVERU: ********//


uint8_t cipher[kyber512_kem::cipher_text_len()];
prng::prng_t prng;


SecByteBlock key( AES::MAX_KEYLENGTH );

// Deskriptor pro pristup k virtualnimu rozhrani
int tundesc;
tundesc = tun_open();


// Vytvoreni TCP socketu a zkouska spojeni vymenou Hello zprav
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
   Ustanoveni PQC klice:

   1) Server obdrzi verejny klic klienta
   2) Server vygeneruje PQC klic
   3) Server zabali PQC klic pomoci verejneho
      klice klienta a posle klientovi

*/
    read(new_socket, buffer, MAXLINE);
    auto skdf = kyber512_kem::encapsulate(prng, (const unsigned char*)buffer, cipher);
    uint8_t* shrd_key = static_cast<uint8_t*>(std::malloc(32));
    skdf.read(shrd_key, 32);

    string pqc_key=kyber_utils::to_hex(shrd_key, 32);
    send(new_socket, cipher, sizeof(cipher), 0);

// Vytvoreni UDP socketu a zkouska spojeni vymenou Hello zprav
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


// Prijem keyID na TCP socketu
read(new_socket, bufferTCP, MAXLINE);

myfile.open ("keyID");
myfile<< bufferTCP;
myfile.close();

// Ziskani QKD klice pomoci keyID
system(("./sym-ExpQKD 'server' " + qkd_ip).c_str());

// Kombinace PQC a QKD klicu
key = VymenaKlice_srv(pqc_key);

/*
   Nastaveni socketu do NON-blocking rezimu
   
   V blocking rezimu by program vzdy cekal
   ve funkci read()/recv() na data 
*/
fcntl(new_socket, F_SETFL, O_NONBLOCK);

// Vytvoreni shodneho procesu pro vyuziti vice CPU
pid_t frk = fork();

// Odchyceni CTRL + C pro ukonceni nekonecne smycky
signal(SIGINT, inthand);

// Promenna pro kontrolu stavu TCP spoje
int status;
// Zprava pro udrzeni dynamickeho NAT prekladu
const char* keepalive = "Keep Alive";
// Referencni cas pro udrzeni dynamickeho NATU
time_t ref = time(NULL);
while (!stop){

/*
   Vymena klice probiha pri prijmu keyID na TCP socket

   Rodicovsky proces vykona nasledujici:

   1) ukonceni kopie procesu
   2) vymena klice
   3) vytvoreni kopie procesu

   ukonceni a nove vytvoreni kopie procesu
   je potreba, aby oba procesy pracovaly se
   stejnymi klici

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

key = VymenaKlice_srv(pqc_key);
frk = fork();
}
}

// Sifrovani dat z virtualniho rozhrani, dokud se nevyprazdni
while(! E_N_C_R (sockfd, cliaddr, key, tundesc, len)){
}
// Desifrovani dat z UDP socketu, dokud se nevyprazdni
while(! D_E_C_R (sockfd, servaddr, key, tundesc)){
}

usleep(100);
if (time(NULL)-ref>=1){
// Obnoveni dynamickeho prekladu provozem ze serveru
send(new_socket, keepalive, strlen(keepalive), 0);
sendto(sockfd, keepalive, strlen(keepalive), MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);
ref = time(NULL);
}
}
// Cisteni po ukonceni while smycky
kill(frk, SIGTERM);
close(sockfd);
close(new_socket);
shutdown(server_fd, SHUT_RDWR);
close(tundesc);
return 0;
}
