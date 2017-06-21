#ifndef _PARSETRANSACTION_H_
#define _PARSETRANSACTION_H_

//BIPs 标准协议相关定义
#define TransaVersionsize 4        //版本字节大小
#define TransapreviousHashsize  32 //Utxo的hash大小
#define Transaindexsize         4  //被花费的UTXO的索引号大小
#define Transacoinsize          8  //金额大小
#define TransaInOutlengthsize   1   //输入输出长度大小占用1字节
#define TransaNull              4  //无定义字节

//BIPs end

#define signSuccess 1     //签名成功
#define signFail    2     //签名失败
#define Nosign      0     //没有签名

#define Transa_address_MAX 256 //支持做多地址输出
#define addresssize_MAX    40 //地址最大空间
#define pathlengh 5//path长度

extern unsigned char TxRecivecompleteflag;
extern unsigned char Saveaddresscoinokflag;
extern unsigned char SignResaltState;
extern unsigned long TxPathData[20];


typedef struct
{
    unsigned char coin[Transacoinsize];     //金额
    unsigned char address[addresssize_MAX]; //地址
    unsigned char addresslenght[TransaInOutlengthsize];            //地址长度
}
CoinAddressStruct;

typedef struct
{
    unsigned long path[pathlengh];     //交易路径path[]={0x8000002C,0x80000000,0x80000000,0,0};
}
TxPath;

typedef struct
{
	unsigned char Transa_txin_num;                             //交易输入的数量
    unsigned char Transa_verion_data[TransaVersionsize];                       //交易版本数据
    TxPath Transa_path[256];                                   //交易路径                    
    unsigned char Transa_txout_num;                            //交易输出的数量
    CoinAddressStruct Transa_coincountdata[Transa_address_MAX];    //金额地址存储
}
TransactiondataStruct;

extern TransactiondataStruct ParseData;

unsigned char parse_transaction_Byte(unsigned char *datatransaction,unsigned short length_tx);

#endif
