#ifndef _Schnorr
#define _Schnorr

#include <string>
#include <iostream>
using namespace std;

#include "cryptopp/osrng.h"      // Random Number Generator
#include "cryptopp/eccrypto.h"   // Elliptic Curve
#include "cryptopp/ecp.h"        // F(p) EC
#include "cryptopp/integer.h"    // Integer Operations
#include "cryptopp/ecp.h"        // Curve Operations
using namespace CryptoPP;

NAMESPACE_BEGIN(SchnorrCPP)

// A class encapsulating the secp256r1 curve
// and Schnorr signing functions
class CCurve {
private:
	static const size_t SCHNORR_SECRET_KEY_SIZE = 32;
	static const size_t SCHNORR_SIG_SIZE = 32;
	static const size_t SCHNORR_PUBLIC_KEY_COMPRESSED_SIZE = 33;
	static const size_t SCHNORR_PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;

	bool secretKeySet;
	bool publicKeySet;

	ECP ec;
    ECPPoint G;
    Integer q;
    AutoSeededRandomPool rng;

    Integer secretKey;
    ECPPoint Q; // public key

    Integer HashPointMessage(const ECPPoint& R, const byte* message, int mlen);
    
    void PrintInteger(Integer i);

public:
	CCurve();

	~CCurve();

    bool HasPrivateKey();
    bool HasPublicKey();

	bool GenerateSecretKey();
	bool GeneratePublicKey();
	bool GenerateKeys();

	bool SetVchPublicKey(std::vector<unsigned char> vchPubKey);
	bool GetVchPublicKey(std::vector<unsigned char>& vchPubKey);
    
	bool SetVchSecretKey(std::vector<unsigned char> vchSecret);
	bool GetVchSecretKey(std::vector<unsigned char>& vchSecret);

	bool GetSignatureFromVch(std::vector<unsigned char> vchSig, Integer& sigE, Integer& sigS);
	bool GetVchFromSignature(std::vector<unsigned char>& vchSig, Integer sigE, Integer sigS);

	Integer GetPublicKeyX();
	Integer GetPublicKeyY();
	Integer GetSecretKey();

    void ModuloAddToHex(Integer k, Integer iL, std::vector<unsigned char>& dataBytes);
    void GetVchPointMultiplyAdd(Integer iL, std::vector<unsigned char>& dataBytes);
    
    bool Sign(std::vector<unsigned char> vchHash, std::vector<unsigned char>& vchSig);
    bool Verify(std::vector<unsigned char> vchHash, std::vector<unsigned char> vchSig);
};

NAMESPACE_END

#endif
