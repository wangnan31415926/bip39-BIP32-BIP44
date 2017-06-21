#include "includeAll.h"







/** Characters for the base 58 representation of numbers. */
const char base58_char_list[58] = {
'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L',
'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r',
's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};




///** Test vector for BIP32 key derivation. */
//struct BIP32TestVector
//{
//	/** Master seed. */
//	unsigned char master[256];
//	/** Length of master seed, in bytes. */
//	unsigned int master_length;
//	/** Key derivation path. */
//	unsigned long path[16];
//	/** Number of steps in derivation path. */
//	unsigned int path_length;
//	/** Expected private key, as a base58-encoded serialised extended private key
//	  * as described in the BIP32 specification. */
//	char base58_private[256];
//};


/** Test vectors from BIP 32 specification. */
const struct BIP32TestVector test_vectors[] =
{

{
// Test vector 1, chain m
	{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // master seed
16, // length of master seed
{0}, // derivation path
0, // steps in derivation path
"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi" // extended private key
},

{
// Test vector 1, chain m/0H
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // master seed
16, // length of master seed
{0x80000000}, // derivation path
1, // steps in derivation path
"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7" // extended private key
},

{
// Test vector 1, chain m/0H/1
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // master seed
16, // length of master seed
{0x80000000, 1}, // derivation path
2, // steps in derivation path
"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs" // extended private key
},

{
// Test vector 1, chain m/0H/1/2H
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // master seed
16, // length of master seed
{0x80000000, 1, 0x80000002}, // derivation path
3, // steps in derivation path
"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM" // extended private key
},

{
// Test vector 1, chain m/0H/1/2H/2
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // master seed
16, // length of master seed
{0x80000000, 1, 0x80000002, 2}, // derivation path
4, // steps in derivation path
"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334" // extended private key
},

{
// Test vector 1, chain m/0H/1/2H/2/1000000000
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // master seed
16, // length of master seed
{0x80000000, 1, 0x80000002, 2, 1000000000}, // derivation path
5, // steps in derivation path
"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76" // extended private key
},

{
// Test vector 2, chain m
{
0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea,
0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a,
0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a,
0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42}, // master seed
64, // length of master seed
{0}, // derivation path
0, // steps in derivation path
"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U" // extended private key
},

{
// Test vector 2, chain m/0
{
0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea,
0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a,
0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a,
0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42}, // master seed
64, // length of master seed
{0}, // derivation path
1, // steps in derivation path
"xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt" // extended private key
},

{
// Test vector 2, chain m/0/2147483647H
{
0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea,
0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a,
0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a,
0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42}, // master seed
64, // length of master seed
{0, 0xffffffff}, // derivation path
2, // steps in derivation path
"xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9" // extended private key
},

{
// Test vector 2, chain m/0/2147483647H/1
{
0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea,
0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a,
0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a,
0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42}, // master seed
64, // length of master seed
{0, 0xffffffff, 1}, // derivation path
3, // steps in derivation path
"xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef" // extended private key
},

{
// Test vector 2, chain m/0/2147483647H/1/2147483646H
{
0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea,
0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a,
0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a,
0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42}, // master seed
64, // length of master seed
{0, 0xffffffff, 1, 0xfffffffe}, // derivation path
4, // steps in derivation path
"xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc" // extended private key
},

{
// Test vector 2, chain m/0/2147483647H/1/2147483646H/2
{
0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea,
0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a,
0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a,
0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42}, // master seed
64, // length of master seed
{0, 0xffffffff, 1, 0xfffffffe, 2}, // derivation path
5, // steps in derivation path
"xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j" // extended private key
}

};


/** Convert a master seed into a master node (an extended private key), as
  * described by the BIP32 specification.
  * \param master_node The master node will be written here. This must be a
  *                    byte array with space for #NODE_LENGTH bytes.
  * \param seed Input seed, which is an arbitrary array of bytes.
  * \param seed_length Length of input seed in number of bytes.
  */
void bip32SeedToNode(unsigned char *master_node, const unsigned char *seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char *)"Bitcoin seed", 12, seed, seed_length);
}
/** Deterministically derive private key from a BIP32 node (a.k.a. extended
  * private key), as described by the BIP32 specification.
  * \param out The derived private key will be written here upon success. The
  *            private key will be written as a little-endian 256 bit
  *            multi-precision integer, suitable for input into a function
  *            such as ecdsaSign().
  * \param master_node The master node (a.k.a. extended private key) to derive
  *                    the private key from.
  * \param path Path through the derivation tree. See BIP32 specification for
  *             more details.
  * \param path_length Number of steps through derivation tree. This may be 0.
  * \return false on success, true on error.
  */
bool bip32DerivePrivate(BigNum256 out, const uint8_t *master_node, const uint32_t *path, const unsigned int path_length)
{
	uint8_t current_node[NODE_LENGTH];
	uint8_t temp[NODE_LENGTH];
	uint8_t hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_t serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_t serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			// Hardened derivation.
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			// Non-hardened derivation.
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp); // big-endian -> little-endian
			pointMultiply(&p, temp);
			// TODO: cache point multiply results so that repeated key derivation is faster
			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				// Compressed public keys should always be 33 bytes; this should never
				// happen.
//				fatalError();
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		// Need to write to temp here (instead of current_node) because part of
		// current_node is used as the key.
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		// First 32 bytes of temp = I_L, last 32 bytes = I_R = derived chain code
		// I_L must be interpreted as a big-endian 256 bit integer. However,
		// bignum256.c works with little-endian integers.
		swapEndian256(current_node); // big-endian -> little-endian
		swapEndian256(temp); // big-endian -> little-endian
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true; // I_L >= n
		}
		setFieldToN();
		bigAdd(temp, temp, current_node); // add k_par to I_L (mod n)
		if (bigIsZero(temp))
		{
			return true; // k_i == 0
		}
		swapEndian256(temp); // little-endian -> big-endian (for next step)
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out); // big-endian -> little-endian for result
	return false; // success
}

