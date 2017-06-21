#include "includeall.h"

	unsigned char master_node[NODE_LENGTH];
///** The maximum size of a transaction (in bytes) which parseTransaction()
//  * is prepared to handle. */
//#define MAX_TRANSACTION_SIZE	2000000
///** The maximum number of inputs that the transaction parser is prepared
//  * to handle. This should be small enough that a transaction with the
//  * maximum number of inputs is still less than #MAX_TRANSACTION_SIZE bytes in
//  * size.
//  * \warning This must be < 65536, otherwise an integer overflow may occur.
//  */
//#define MAX_INPUTS				5000
///** The maximum number of outputs that the transaction parser is prepared
//  * to handle. This should be small enough that a transaction with the
//  * maximum number of outputs is still less than #MAX_TRANSACTION_SIZE bytes
//  * in size.
//  * \warning This must be < 65536, otherwise an integer overflow may occur.
//  */
//#define MAX_OUTPUTS				2000
//
///** The maximum amount that can appear in an output, stored as a little-endian
//  * multi-precision integer. This represents 21 million BTC. */
//static const uint8_t max_money[] = {
//0x00, 0x40, 0x07, 0x5A, 0xF0, 0x75, 0x07, 0x00};


/**
 * \defgroup DEROffsets Offsets for DER signature encapsulation.
 *
 * @{
 */
/** Initial offset of r in signature. It's 4 because 4 bytes are needed for
  * the SEQUENCE/length and INTEGER/length bytes. */
#define R_OFFSET	4
/** Initial offset of s in signature. It's 39 because: r is initially 33
  * bytes long, and 2 bytes are needed for INTEGER/length. 4 + 33 + 2 = 39. */
#define S_OFFSET	39
/**@}*/
/** Encapsulate an ECDSA signature in the DER format which OpenSSL uses.
  * This function does not fail.
  * \param signature This must be a byte array with space for at
  *                  least #MAX_SIGNATURE_LENGTH bytes. On exit, the
  *                  encapsulated signature will be written here.
  * \param r The r value of the ECDSA signature. This should be a 32 byte
  *          little-endian multi-precision integer.
  * \param s The s value of the ECDSA signature. This should be a 32 byte
  *          little-endian multi-precision integer.
  * \return The length of the signature, in number of bytes.
  */
static uint8_t encapsulateSignature(uint8_t *signature, BigNum256 r, BigNum256 s)
{
	uint8_t sequence_length;
	uint8_t i;

	memcpy(&(signature[R_OFFSET + 1]), r, 32);
	memcpy(&(signature[S_OFFSET + 1]), s, 32);
	// Place an extra leading zero in front of r and s, just in case their
	// most significant bit is 1.
	// Integers in DER are always 2s-complement signed, but r and s are
	// non-negative. Thus if the most significant bit of r or s is 1,
	// a leading zero must be placed in front of the integer to signify that
	// it is non-negative.
	// If the most significant bit is not 1, the extraneous leading zero will
	// be removed in a check below.
	signature[R_OFFSET] = 0x00;
	signature[S_OFFSET] = 0x00;

	// Integers in DER are big-endian.
	swapEndian256(&(signature[R_OFFSET + 1]));
	swapEndian256(&(signature[S_OFFSET + 1]));

	sequence_length = 0x46; // 2 + 33 + 2 + 33
	signature[R_OFFSET - 2] = 0x02; // INTEGER
	signature[R_OFFSET - 1] = 0x21; // length of INTEGER
	signature[S_OFFSET - 2] = 0x02; // INTEGER
	signature[S_OFFSET - 1] = 0x21; // length of INTEGER
	signature[S_OFFSET + 33] = 0x01; // hashtype
	// According to DER, integers should be represented using the shortest
	// possible representation. This implies that leading zeroes should
	// always be removed. The exception to this is that if removing the
	// leading zero would cause the value of the integer to change (eg.
	// positive to negative), the leading zero should remain.

	// Remove unncecessary leading zeroes from s. s is pruned first
	// because pruning r will modify the offset where s begins.
	while ((signature[S_OFFSET] == 0) && ((signature[S_OFFSET + 1] & 0x80) == 0))
	{
		for (i = S_OFFSET; i < 72; i++)
		{
			signature[i] = signature[i + 1];
		}
		sequence_length--;
		signature[S_OFFSET - 1]--;
		if (signature[S_OFFSET - 1] == 1)
		{
			break;
		}
	}

	// Remove unnecessary leading zeroes from r.
	while ((signature[R_OFFSET] == 0) && ((signature[R_OFFSET + 1] & 0x80) == 0))
	{
		for (i = R_OFFSET; i < 72; i++)
		{
			signature[i] = signature[i + 1];
		}
		sequence_length--;
		signature[R_OFFSET - 1]--;
		if (signature[R_OFFSET - 1] == 1)
		{
			break;
		}
	}

	signature[0] = 0x30; // SEQUENCE
	signature[1] = sequence_length; // length of SEQUENCE
	// 3 extra bytes: SEQUENCE/length and hashtype
	return (uint8_t)(sequence_length + 3);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////



/** Sign a transaction. This should be called after the transaction is parsed
  * and a signature hash has been computed. The primary purpose of this
  * function is to call ecdsaSign() and encapsulate the ECDSA signature in
  * the DER format which OpenSSL uses.
  * \param signature The encapsulated signature will be written here. This
  *                  must be a byte array with space for
  *                  at least #MAX_SIGNATURE_LENGTH bytes.
  * \param out_length The length of the signature, in number of bytes, will be
  *                   written here (on success). This length includes the hash
  *                   type byte.
  * \param sig_hash The signature hash of the transaction (see
  *                 parseTransaction()).
  * \param private_key The private key to sign the transaction with. This must
  *                    be a 32 byte little-endian multi-precision integer.
  * \return false on success, or true if an error occurred while trying to
  *         obtain a random number.
  */
void signTransaction(uint8_t *signature, uint8_t *out_length, BigNum256 sig_hash, BigNum256 private_key)
{
	uint8_t r[32];
	uint8_t s[32];

	*out_length = 0;
	 ecdsaSign(r, s, sig_hash, private_key);
	*out_length = encapsulateSignature(signature, r, s);
}




















/////////////////////////////////////////////////////////
bool b58enc(unsigned char *b58, unsigned short *b58sz, unsigned char *data, unsigned short binsz)
{
	unsigned char *bin = data;
	int carry=0;
	unsigned short i, j, high, zcount = 0;
	unsigned short size=0;
	
    i=0;
	j=0;
	high=0;

	while (zcount < binsz && !bin[zcount])
		++zcount;
	
	size = (binsz - zcount) * 138 / 100 + 1;
	uint8_t buf[200];
	memset(buf, 0, size);
	
	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
		}
	}
	
	for (j = 0; j < size && !buf[j]; ++j);
	
//	if (*b58sz <= zcount + size - j)
//	{
//		*b58sz = zcount + size - j + 1;
//		return false;
//	}
	
	if (zcount)
	{memset(b58, '1', zcount);}
	for (i = zcount; j < size; ++i, ++j)
	{b58[i] =base58_char_list[buf[j]];}
	b58[i] = '\0';
	*b58sz = i + 1;
	
	return true;
}

void base58Decode(uint8_t *out, const char *in, const unsigned int len)
{
	unsigned int i;
	unsigned int j;
	unsigned int digit;
	unsigned int carry;
	unsigned int result;

	memset(out, 0, SERIALISED_BIP32_KEY_LENGTH);
	for (i = 0; i < len; i++)
	{
		digit = 0;
		for (j = 0; j < 58; j++)
		{
			if (in[i] == base58_char_list[j])
			{
				digit = j;
				break;
			}
		}
		// multiply by 58
		carry = 0;
		for (j = 0; j < SERIALISED_BIP32_KEY_LENGTH; j++)
		{
			result = (unsigned int)out[j] * 58 + carry;
			out[j] = (uint8_t)result;
			carry = result >> 8;
		}
		// add digit
		carry = 0;
		for (j = 0; j < SERIALISED_BIP32_KEY_LENGTH; j++)
		{
			result = (unsigned int)out[j] + carry;
			if (j == 0)
			{
				result += digit;
			}
			out[j] = (uint8_t)result;
			carry = result >> 8;
		}
	}
}

/**************************************
函数名称：将解析出的公钥地址进行base58chaeck转换
入参：    buf 公钥存储首地址（20字节）,out base58check数据存储地址，outlength 输出数据长度
**************************************/
void HextoBase58check(unsigned char* buf,unsigned char* base58check,unsigned short* outlength)
{
	unsigned char p[25]={0};                //数据组织缓冲区

    memcpy(&p[1],buf,20);

	sha256_double(p,21);

    memcpy(&p[21],(unsigned char*)sha256_h,4);     //取hash结果前4字节

    b58enc(base58check,outlength,p,25);     //base58转换

}


///********************************************
//函数名称：双hash，sha256^2
//入参：bufIN 数据首地址，length 数据长度
//hash结果保存在h中
//********************************************/
//void sha256_double(unsigned char* bufIN,unsigned short length)
//{ 
//	unsigned char i;
//
//	sha256(bufIN,length);
//    for(i=0;i<8;i++)                        //对结果进行从小端->大端转换
//	{
//      BigendChang((unsigned char*)(&sha256_h[i]),4); 
//	}
//	sha256((unsigned char*)sha256_h,32);           //再次做hash sha256
//	for(i=0;i<8;i++)                        //对结果进行从小端->大端转换
//	{
//      BigendChang((unsigned char*)(&sha256_h[i]),4); 
//	}
//
//}
