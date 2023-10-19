#include <iostream>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>

using namespace CryptoPP;

void GenerateECDHKeys()
{
    AutoSeededRandomPool prng;

    // Vyberte 512-bitovou køivku
    ECDH <ECP>::Domain dh;
    dh.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp521r1());

    // Generování privátního klíèe
    DH_PrivateKey<ECP> privateKey;
    privateKey.Initialize(prng, dh);

    // Extrahování veøejného klíèe
    DH_PublicKey<ECP> publicKey;
    privateKey.MakePublicKey(publicKey);

    // Výstup veøejného a soukromého klíèe
    std::cout << "Veøejný klíè: " << std::hex << publicKey.GetPublicElement() << std::dec << std::endl;
    std::cout << "Soukromý klíè: " << std::hex << privateKey.GetPrivateExponent() << std::dec << std::endl;
}

int main()
{
  
    // Generování klíèù
    GenerateECDHKeys();

    return 0;
}
