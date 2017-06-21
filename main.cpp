#include "includeAll.h"



///////////////////////////////////wangnan获取随机数////////////////////////
/** Fill array with pseudo-random testing data.
  * \param out Byte array to fill.
  * \param len Number of bytes to write.
  */
void fillWithRandom(uint8_t *out, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
	{
		out[i] = 0;//(uint8_t)rand();wangnandebug
	}
}



/////////////////////////////////////printf/////////////////////////////////////
/** Display a multi-precision integer of arbitrary size as a hex string.
  * \param number The byte array containing the integer.
  * \param size The size, in number of bytes, of the byte array.
  * \param is_big_endian This should be true if the integer is stored in
  *                      big-endian format and should be false if the number
  *                      is stored in little-endian format.
  */
void bigPrintVariableSize(const uint8_t *number, const unsigned int size, const bool is_big_endian)
{
	unsigned int i;
	if (is_big_endian)
	{
		for (i = 0; i < size; i++)
		{
			printf("%02x", number[i]);
		}
	}
	else
	{
		for (i = (uint8_t)(size - 1); i < size; i--)
		{
			printf("%02x", number[i]);
		}
	}
}
void printLittleEndian32(const BigNum256 buffer)
{
	bigPrintVariableSize(buffer, 32, false);
}
/////////////////////////////////////printfend/////////////////////////////////////

/***********************************************
函数名称：测试函数
功能实现：通过16字节随机数->助记符；
          通过助记符->64字节种子；
          通过种子->master node；
          通过master node->parent public key和chain code;
          通过master node和path->child private key
          实现签名函数。
**********************************************/
void test1(void)
{
  	uint8_t seed[64];                       //用来生成parent key的种子
//	unsigned char master_node[NODE_LENGTH];
    PointAffine Mpublickey[1];              //定义masterpublickey存储位置
    unsigned char chaincode[CANARY_LENGTH]; //chaincode存储路径
    unsigned char out[32 + CANARY_LENGTH];  //
unsigned char j;
unsigned char wn[]={0xaa,0x47,0x07,0x8a,0x81,0xc6,0x87,0x82,0x24,0xb0,0xcf,0xc9,0xba,0xf1,0x6b,0x6b};//128位随机数;

    printf("entropy:\r\n");  
	for(j=0;j<16;j++)
	{
       printf("%02x",wn[j]);
	}
	printf("\r\n");
    printf("\r\n");
   /////////////////////////////////////////////////////////////////
    mnemonic_from_data(wn,sizeof(wn),0);//通过随机数转换为助记符
   /////////////////////////////////////////////////////////////////
    j=0;
	printf("entropy to mnemonic:\r\n");
    while(mnemo[j]!=0)
	{
		printf("%c",mnemo[j]);
		j++;
	}
    printf("\r\n");
    printf("\r\n");

	/////////////////////////////////////////////////////////////
    mnemonic_to_seed(mnemo, 0, seed, 0);//通过助记符转化为种子
	////////////////////////////////////////////////////////////
    printf("mnemonic to seed:");
	for(j=0;j<64;j++)
	{
	printf("%02x",seed[j]);
	}
	printf("\r\n");
    printf("\r\n");


    bip32SeedToNode(master_node,seed, 64);//通过seed生成master node
    getMasterPublicKey(Mpublickey,chaincode,master_node);//获取masterpublickey
	printf("Mpublic_x:");
	bigPrintVariableSize(Mpublickey->x, 32, true);
	printf("\r\n");
	printf("Mpublic_y:");
	bigPrintVariableSize(Mpublickey->y, 32, true);
	printf("\r\n");
	printf("Mpublic_point:%x\r\n",Mpublickey->is_point_at_infinity);
	printf("chaincode:");
	bigPrintVariableSize(chaincode, 32, true);
    printf("\r\n");
	printf("\r\n");

	
      bip32DerivePrivate(out, master_node,TxPathData,5);//通过master node和path生成child private key
	printf("child private:");
	bigPrintVariableSize(out, 32, false);
	    printf("\r\n");
		printf("\r\n");

		unsigned char data[32];
		memset(data,0x01,32);
        unsigned char out_[MAX_SIGNATURE_LENGTH];//签名结果
	signTransaction(out_,seed,data,data);//签名
    printf("signresult %d:",seed[0]);
	for(j=0;j<seed[0];j++)
	{
       printf("%02x",out_[j]);
	}
    printf("\r\n");
}

/***********************************************
函数名称：测试函数
功能实现：实现16进制转base58check编码  用于地址显示
          双sha256 hash。              用于对交易进行hash
**********************************************/
void test2(void)
{
    unsigned char C[25]={0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33
		              ,0x01,0x65,0x62,0xfc};

	unsigned char D[25]={0x09,0x92,0xca,0xc2,0xf8,0x6e,0x7b,0xcd,0x01,0x54,0xc2,0x3f,0xb4,0xd3,0x1d,0xd2,0x02,0x80,0x36,0xce};
	unsigned char E[25]={0x65,0x35,0xa4,0x39,0x38,0xda,0x2a,0x86,0xad,0xe7,0x96,0xd0,0x51,0x37,0x16,0x2e,0xda,0xbb,0x12,0x45};
	unsigned char A[200]; //存储base58check数据
	unsigned short B[1];  //存储base58check长度
	unsigned char j;

   printf("Hexdata:\r\n");
	for(j=0;j<25;j++)
	{
       printf("%02x",D[j]);
	}
   printf("\r\n");   
   HextoBase58check(D,A,B);//base58check转换
   printf("HextoBase58check:\r\n");
	for(j=0;j<B[0];j++)
	{
       printf("%c",A[j]);
	}
    printf("\r\n");
    printf("\r\n");
//////////////////////////////////////////////////////////
	printf("Hexdata:\r\n");
	for(j=0;j<25;j++)
	{
       printf("%02x",E[j]);
	}
    printf("\r\n"); 
	HextoBase58check(E,A,B);//base58check转换
    printf("HextoBase58check:\r\n");
	for(j=0;j<B[0];j++)
	{
       printf("%c",A[j]);
	}
    printf("\r\n");
	printf("\r\n");
/////////////////////////////////////////////////////////////////////
unsigned char bufw1[]={0x01 ,0x00 ,0x00 ,0x00 ,0x03 ,0xc1 ,0xe7 ,0x41 ,0xf3 ,0x23 ,0x02 ,0x88 ,0x13 ,0xa3 ,0xa8 ,0x31 ,0x5a ,0xa3 ,0x8b ,0xa1 ,0x69 ,0x4d ,0x74 ,0x99 ,0x10 ,0x92 ,0x4a ,0x6d ,0xa1 ,0xbb ,0x5d ,0x0c ,0xf3 ,0xd1 ,0x2b ,0x6f ,0x9e ,0x00 ,0x00 ,0x00 ,0x00 ,0x19 ,0x76 ,0xa9 ,0x14 ,0x6f ,0x14 ,0xd2 ,0x8e ,0xac ,0x23 ,0xa1 ,0xd7 ,0x0c ,0x17 ,0x57 ,0xa3 ,0x6f ,0x1f ,0x7b ,0x68 ,0x83 ,0x62 ,0x98 ,0x18 ,0x88 ,0xac ,0xff ,0xff ,0xff ,0xff ,0x09 ,0xfd ,0xd6 ,0x59 ,0x78 ,0x27 ,0x17 ,0x2a ,0x71 ,0x90 ,0xf3 ,0xb7 ,0xc4 ,0x4f ,0x58 ,0x7b ,0x91 ,0x20 ,0xa9 ,0x32 ,0x79 ,0xa8 ,0x5c ,0xab ,0xa2 ,0xee ,0x1e ,0xe7 ,0x29 ,0x35 ,0xd3 ,0x7c ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0xff ,0xff ,0xff ,0xff ,0x46 ,0x65 ,0x62 ,0xf7 ,0xf8 ,0xe8 ,0x62 ,0x5a ,0xb3 ,0xb1 ,0x55 ,0x11 ,0x43 ,0x90 ,0xdc ,0x03 ,0x80 ,0xd1 ,0x37 ,0xd5 ,0xad ,0x18 ,0x67 ,0x08 ,0xc8 ,0x90 ,0x57 ,0x8e ,0x31 ,0x68 ,0x3f ,0x92 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0xff ,0xff ,0xff ,0xff ,0x02 ,0x80 ,0x96 ,0x98 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x19 ,0x76 ,0xa9 ,0x14 ,0x8d ,0x67 ,0x12 ,0x79 ,0x97 ,0x50 ,0xe3 ,0xc9 ,0x4a ,0xb5 ,0x69 ,0x14 ,0x2e ,0x4d ,0xf6 ,0x41 ,0x7d ,0xfb ,0x84 ,0xbe ,0x88 ,0xac ,0x30 ,0xe6 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x19 ,0x76 ,0xa9 ,0x14 ,0x2e ,0x7f ,0x41 ,0x16 ,0xfd ,0x4e ,0x7d ,0x19 ,0xe4 ,0x84 ,0xec ,0x3a ,0x4e ,0xc1 ,0xd1 ,0x94 ,0x8e ,0x64 ,0x5e ,0xb4 ,0x88 ,0xac ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00};
unsigned char* p1=(unsigned char*)sha256_h;
sha256_double(bufw1,230);
printf("Hexdata:\r\n");
	for(j=0;j<230;j++)
	{
       printf("%02x",bufw1[j]);
	}
    printf("\r\n"); 
printf("sha256_double:\r\n");
	for(j=0;j<32;j++)
	{
       printf("%02x",p1[j]);
	}
    printf("\r\n");

}


/***********************************************
函数名称：测试函数
功能实现：实现交易解析
**********************************************/
void test3(void)
{
	unsigned short i,j;
	unsigned char bufw1[276]={0x01 ,0x00 ,0x00 ,0x00 ,0x03 ,0xc1 ,0xe7 ,0x41 ,0xf3 ,0x23 ,0x02 ,0x88 ,0x13 ,0xa3 ,0xa8 ,0x31 ,0x5a ,0xa3 ,0x8b ,0xa1 ,0x69 ,0x4d ,0x74 ,0x99 ,0x10 ,0x92 ,0x4a ,0x6d ,0xa1 ,0xbb ,0x5d ,0x0c ,0xf3 ,0xd1 ,0x2b ,0x6f ,0x9e ,0x00 ,0x00 ,0x00 ,0x00 ,0x19 ,0x76 ,0xa9 ,0x14 ,0x6f ,0x14 ,0xd2 ,0x8e ,0xac ,0x23 ,0xa1 ,0xd7 ,0x0c ,0x17 ,0x57 ,0xa3 ,0x6f ,0x1f ,0x7b ,0x68 ,0x83 ,0x62 ,0x98 ,0x18 ,0x88 ,0xac ,0xff ,0xff ,0xff ,0xff ,0x09 ,0xfd ,0xd6 ,0x59 ,0x78 ,0x27 ,0x17 ,0x2a ,0x71 ,0x90 ,0xf3 ,0xb7 ,0xc4 ,0x4f ,0x58 ,0x7b ,0x91 ,0x20 ,0xa9 ,0x32 ,0x79 ,0xa8 ,0x5c ,0xab ,0xa2 ,0xee ,0x1e ,0xe7 ,0x29 ,0x35 ,0xd3 ,0x7c ,0x01 ,0x00 ,0x00 ,0x00 ,0x19 ,0x76 ,0xa9 ,0x14 ,0xed ,0xba ,0x0b ,0xee ,0x5d ,0xb2 ,0x1c ,0x9f ,0xb2 ,0x7b ,0x9e ,0x31 ,0x5b ,0x21 ,0x96 ,0x1f ,0xb8 ,0x69 ,0x73 ,0x81 ,0x88 ,0xac ,0xff ,0xff ,0xff ,0xff ,0x46 ,0x65 ,0x62 ,0xf7 ,0xf8 ,0xe8 ,0x62 ,0x5a ,0xb3 ,0xb1 ,0x55 ,0x11 ,0x43 ,0x90 ,0xdc ,0x03 ,0x80 ,0xd1 ,0x37 ,0xd5 ,0xad ,0x18 ,0x67 ,0x08 ,0xc8 ,0x90 ,0x57 ,0x8e ,0x31 ,0x68 ,0x3f ,0x92 ,0x00 ,0x00 ,0x00 ,0x00 ,0x19 ,0x76 ,0xa9 ,0x14 ,0xae ,0xb1 ,0x75 ,0xcf ,0xa0 ,0xcb ,0x7a ,0x8f ,0x20 ,0x70 ,0x0a ,0xaf ,0x1b ,0x79 ,0x8f ,0x65 ,0x80 ,0xa4 ,0x95 ,0x73 ,0x88 ,0xac ,0xff ,0xff ,0xff ,0xff ,0x02 ,0x80 ,0x96 ,0x98 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x19 ,0x76 ,0xa9 ,0x14 ,0x8d ,0x67 ,0x12 ,0x79 ,0x97 ,0x50 ,0xe3 ,0xc9 ,0x4a ,0xb5 ,0x69 ,0x14 ,0x2e ,0x4d ,0xf6 ,0x41 ,0x7d ,0xfb ,0x84 ,0xbe ,0x88 ,0xac ,0x30 ,0xe6 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x19 ,0x76 ,0xa9 ,0x14 ,0x2e ,0x7f ,0x41 ,0x16 ,0xfd ,0x4e ,0x7d ,0x19 ,0xe4 ,0x84 ,0xec ,0x3a ,0x4e ,0xc1 ,0xd1 ,0x94 ,0x8e ,0x64 ,0x5e ,0xb4 ,0x88 ,0xac ,0x00 ,0x00 ,0x00 ,0x00};
static   unsigned char w=0;
//	unsigned char* p1=(unsigned char*)sha256_h;
//    sha256_double(bufw1,148);
//    printf("Hexdata:\r\n");
//	for(j=0;j<148;j++)
//	{
//       printf("%02x",bufw1[j]);
//	}
//    printf("\r\n"); 
//    printf("sha256_double:\r\n");
//	for(j=0;j<32;j++)
//	{
//       printf("%02x",p1[j]);
//	}
//    printf("\r\n");
//    printf("\r\n");


      parse_transaction_Byte(bufw1,276);
   
	  if(w==0)
	  {
       for(j=0;j<ParseData.Transa_txout_num;j++)
	   {
         printf("Address %d:\r\n",j);
         for(i=0;i<ParseData.Transa_coincountdata[j].addresslenght[0];i++)
		 {
            printf("%c",ParseData.Transa_coincountdata[j].address[i]);
		 }
		 printf("\r\n");
	   }
	   w=1;
	  }
	 	
	
   	

}

void main(void)
{
//	unsigned char expected_bytes[SERIALISED_BIP32_KEY_LENGTH];
//	unsigned char master_node[NODE_LENGTH];
//    unsigned char canary[CANARY_LENGTH];
//	unsigned char out[32 + CANARY_LENGTH];
//	unsigned int i;
//	unsigned int j;//wangnan debug
//	char publickey_wangnan[]="xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
//    PointAffine Mpublickey[1];//定义masterpublickey存储位置
//    unsigned char chaincode[CANARY_LENGTH];
//	uint8_t seed[64];
//种子生成parent private key
//
//	for (i = 0; i < (sizeof(test_vectors) / sizeof(struct BIP32TestVector)); i++)
//	{
//		bip32SeedToNode(master_node, test_vectors[i].master, test_vectors[i].master_length);//通过seed生成master node
//	
//		printf("masternode:");
//				for(j=0;j<64;j++)
//				{
//				printf("%x",master_node[j]);
//				}
//		printf("\r\n");
//
//getMasterPublicKey(Mpublickey,chaincode,master_node);//获取masterpublickey
//
//printf("Mpublic_x:");
//bigPrintVariableSize(Mpublickey->x, 32, false);
//printf("\r\n");
//printf("Mpublic_y:");
//bigPrintVariableSize(Mpublickey->y, 32, false);
//printf("\r\n");
//printf("Mpublic_point:%x\r\n",Mpublickey->is_point_at_infinity);
//printf("chaincode:");
////bigPrintVariableSize(chaincode, 32, false);
//				for(j=0;j<32;j++)
//				{
//				printf("%x",chaincode[j]);
//				}
//printf("\r\n");
//
//		if (bip32DerivePrivate(out, master_node, test_vectors[i].path, test_vectors[i].path_length))//通过master node和path生成child private key
//		{
//			printf("Test vector %u failed to derive\n", i);
//		}
//		else
//		{
//
//
//			base58Decode(expected_bytes, test_vectors[i].base58_private, strlen(test_vectors[i].base58_private));
//
//			if (memcmp(&(out[0]), &(expected_bytes[4]), 32) != 0)
//			{
//				printf("Test vector %u derivation mismatch\n", i);
//				printf("Derived: ");
//				printLittleEndian32(&(out[0]));
//				printf("\n");
//				printf("Vector : ");
//				printLittleEndian32(&(expected_bytes[4]));
//				printf("\n");
//
//				printf("fail\r\n");
//			}
//			else if (memcmp(&(out[32]), canary, sizeof(canary)) != 0)
//			{
//				printf("Test vector %u caused write to canary\n", i);
//				printf("fail\r\n");
//			}
//			else
//			{
//				printf("test_vectors %d:",i);
//				for(j=0;j<32;j++)
//				{
//				printf("%x",out[j]);
//				}
//				printf("\r\n");
//
//				printf("success\r\n");
//			}
//		}
//	}
////种子生成parent private key END
//base58Decode(expected_bytes, publickey_wangnan, strlen(publickey_wangnan));
//printf("publickey %d:",i);
//printLittleEndian32(&(expected_bytes[4]));
//printf("\r\n");



//	test1();
//  test2();

	test3();
	while(1)
	{
	test3();
	}
}