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
int tun_open(char *devname)
{
  struct ifreq ifr;
  int fd, err;

  if ( (fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) == -1 ) {
       perror("open /dev/net/tun");exit(1);
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, devname, IFNAMSIZ);

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
   Vymena klice v rezimu klient

   Klient zazada QKD server o novy klic, ktery
   zkombinuje s PQC klicem pomoci SHA-256, a pak
   posle jeho ID serveru
*/
SecByteBlock VymenaKlice_cli(int client_fd, string pqc_key, string qkd_ip){

CryptoPP::SHA256 hash;
byte digest[ CryptoPP::SHA256::DIGESTSIZE ];

SecByteBlock key( AES::MAX_KEYLENGTH );

system(("./sym-ExpQKD 'client' " + qkd_ip).c_str());

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

std::ifstream s("keyID");
std::stringstream bufferTCP;
bufferTCP << s.rdbuf();

send(client_fd, bufferTCP.str().c_str(), bufferTCP.str().length(), 0);

return key;
}

// Vypis pouziti programu
void help(){
cout << endl << "   Pouziti:" << endl << endl;
cout << "   ./sifrator_client.exe [QKD IP] [Server IP]" << endl;
cout << "   QKD IP - IP adresa dosazitelneho QKD serveru" << endl;
cout << "   Server IP - IP adresa sifratoru v rezimu server" << endl << endl;
}

int main(int argc, char* argv[])
{

if (argc < 3){
help();
return 0;
}

// Prvni argument je IP QKD serveru
string qkd_ip = argv[1];

// Druhy argument je IP serveru
const char* srv_ip = argv[2];


//******** MOD KLIENTA: ********//


// Vytvoreni klicu pro KEM
    uint8_t pkey[kyber512_kem::pub_key_len()];
    uint8_t skey[kyber512_kem::sec_key_len()];
    prng::prng_t prng;

    kyber512_kem::keygen(prng, pkey, skey);

// Klic pro AES
SecByteBlock key( AES::MAX_KEYLENGTH );

// Deskriptor pro pristup k virtualnimu rozhrani
int tundesc;
tundesc = tun_open();

// Vytvoreni TCP socketu a zkouska spojeni vymenou Hello zprav
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
   Ustanoveni PQC klice:
   Klient posle svuj verejny klic serveru, od ktereho pak obdrzi
   "zabaleny" PQC klic, ktery ziska pomoci sveho soukromeho klice
*/

    send(client_fd, pkey, sizeof(pkey), 0);
    read(client_fd, buffer, MAXLINE);
    auto rkdf = kyber512_kem::decapsulate(skey, (const unsigned char*)buffer);
    uint8_t* shrd_key = static_cast<uint8_t*>(std::malloc(32));
    rkdf.read(shrd_key, 32);
    string pqc_key = kyber_utils::to_hex(shrd_key, 32);

// Vytvoreni UDP socketu a zkouska spojeni vymenou Hello zprav
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

/*
   Nastaveni socketu do NON-blocking rezimu
   
   V blocking rezimu by program vzdy cekal
   ve funkci read()/recv() na data 
*/
fcntl(sockfd, F_SETFL, O_NONBLOCK);

// Nastaveni klice pro AES
key = VymenaKlice_cli(client_fd, pqc_key, qkd_ip);

// Vytvoreni shodneho procesu pro vyuziti vice CPU
pid_t frk = fork();


string encoded;

// Citac slouzici pro re-keying po 200 000 zpravach
int counter = 0;

// Odchyt kombinace CTRL + C pro ukonceni nekonecneho cyklu
signal(SIGINT, inthand);

while (!stop){

while (counter<200000 && !stop){

// Sifrovani dat z virtualniho rozhrani, dokud se nevyprazdni
while(!E_N_C_R (sockfd, servaddr, key, tundesc, len)){
counter++;
}

// Desifrovani dat z UDP socketu, dokud se nevyprazdni
while(!D_E_C_R (sockfd, servaddr, key, tundesc)){
counter++;
}


usleep(100);

}

/*
   re-keying po 200 000 zpravach

   Rodicovsky proces vykona nasledujici:

   1) vynulovani citace
   2) ukonceni kopie procesu
   3) vymena klice
   4) vytvoreni kopie procesu

   ukonceni a nove vytvoreni kopie procesu
   je potreba, aby oba procesy pracovaly se
   stejnymi klici
*/
if (frk > 0){
counter = 0;
kill(frk, SIGTERM);
key = VymenaKlice_cli(client_fd, pqc_key, qkd_ip);
frk = fork();
}

}
// Cisteni po ukonceni while smycky
kill(frk, SIGTERM);
close(client_fd);
close(sockfd);
close(tundesc);
return 0;
}
