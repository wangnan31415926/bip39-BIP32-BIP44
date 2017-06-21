#include "includeAll.h"

unsigned char TxRecivecompleteflag=1;               //数据接收完成标志位 0，未接收；1 接收完成
unsigned char SignResaltState=0;                    //签名结果 0 没有签名操作，1 签名成功，2签名失败
unsigned char Saveaddresscoinokflag=0;              //金额，地址存储完成标志位 0 没完成；1 完成

unsigned char         Txsignedcount=0;          //交易签名计数器。记录已经签名过几次数据
TransactiondataStruct ParseData;                //分析中所有相关数据缓存
unsigned short        TxOut_startaddress=0;     //交易输出数据的起始地址

unsigned char         UtxoHashCount=0;          //以hash utxo个数计数器

unsigned char SignResaultSavebuf[73];           //存储签名结果
unsigned char SignResaultSavelength[1];         //存储签名结果长度
unsigned long TxPathData[20]={0x8000002C,0x80000000,0x80000000,0,0};
/*******************************************
函数名称：签名
入参：datatransaction 输入的交易数据首地址
**************************************************/

void Tx_signed(unsigned char* datatransaction,unsigned short length_tx)
{
	unsigned short i; 
	unsigned short hash_size;
    HashState hs;
	unsigned char* p=datatransaction;
	unsigned char lenscrip;
	unsigned short        Data_p=0;                 //数据指针

	unsigned char out[64];//存储子私钥 前32字节为子私钥
	unsigned char HASHbuf[32];//存储hash结果

	sha256Begin(&hs); //sha256初始化

	for(i=0;i<(TransaVersionsize+TransaInOutlengthsize);i++)  //对前5字节进行hash，4字节版本；1字节输入长度
	{
		sha256WriteByte(&hs,datatransaction[i]);
	}
	Data_p=Data_p+TransaVersionsize+TransaInOutlengthsize; //数据指针+5
	p=&p[Data_p];

	while(UtxoHashCount<ParseData.Transa_txin_num)//判断以hash utxo个数计数器<交易输入数量
	{
		if(Txsignedcount!=UtxoHashCount)//判断当前，utxo是否需要变化后hash
		{//需要变化后hash,脚本区清零
			hash_size=TransapreviousHashsize+Transaindexsize;//先hash 32+4
			for(i=0;i<hash_size;i++)  
			{
				sha256WriteByte(&hs,p[i]);
			}
           
            sha256WriteByte(&hs,0);
			Data_p=hash_size;
            lenscrip=p[Data_p];//存储报文长度
            p=&p[hash_size+TransaInOutlengthsize+lenscrip];//数据指针指向下一数据首地址
 			for(i=0;i<TransaNull;i++)  
			{
				sha256WriteByte(&hs,p[i]);
			} 
			p=p+TransaNull;

		}
		else
		{//无需变化直接hash
			hash_size=TransapreviousHashsize+Transaindexsize+TransaInOutlengthsize+TransaNull+p[TransapreviousHashsize+Transaindexsize];//大小=32+4+1+p[32+4]+4
			for(i=0;i<hash_size;i++)  
			{
				sha256WriteByte(&hs,p[i]);
			}

			Data_p=hash_size; //数据指针=数据指针+大小
			p=&p[Data_p];//数据指针指向下一个数据
		}

		UtxoHashCount++;
	}

	UtxoHashCount=0; //清以hash utxo个数计数器

	hash_size=length_tx-TxOut_startaddress;//对输出进行整体hash
	p=&datatransaction[TxOut_startaddress];
	for(i=0;i<hash_size;i++)  
	{
		sha256WriteByte(&hs,p[i]);
	}

sha256WriteByte(&hs,0x01);
sha256WriteByte(&hs,0);
sha256WriteByte(&hs,0);
sha256WriteByte(&hs,0);

	sha256Finish(&hs);//结束第一次hash
	memcpy(sha256_h, hs.h, 32);
	for(i=0;i<8;i++)                        //对结果进行从小端->大端转换
	{
      BigendChang((unsigned char*)(&sha256_h[i]),4); 
	}

	sha256((unsigned char*)sha256_h,32);    //再次做hash sha256
	for(i=0;i<8;i++)                        //对结果进行从小端->大端转换
	{
      BigendChang((unsigned char*)(&sha256_h[i]),4); 
	}


	//进行签名，存储签名结果
//	//获取TxPathData
//	for(i=0;i<pathlengh;i++)
//	{
//       TxPathData=ParseData.Transa_path[i];
//	}
    //获取TxPathData end


    bip32DerivePrivate(out, master_node,TxPathData,5);//通过master node和path生成child private key//查找私钥

	memcpy(HASHbuf,(unsigned char*)sha256_h,32);
	BigendChang(HASHbuf,32); //HASH结果big-end->little-end


	signTransaction(SignResaultSavebuf,SignResaultSavelength,HASHbuf,out);//签名

}

/*************************************************
函数名称：查找输出起始地址
入参：datatransaction 输入的交易数据首地址
**************************************************/
void TxOut_startaddress_f(unsigned char *datatransaction)
{
	unsigned char j;
    
	TxOut_startaddress=5;
	for(j=0;j<ParseData.Transa_txin_num;j++)
	{
      TxOut_startaddress=TxOut_startaddress+TransapreviousHashsize+Transaindexsize+TransaInOutlengthsize;
      TxOut_startaddress=TxOut_startaddress+datatransaction[TxOut_startaddress-1]+4;
	}

	ParseData.Transa_txout_num=datatransaction[TxOut_startaddress]; //存储交易输出计数器

}

/**************************************************
函数名称：准备地址金额输出显示
入参：datatransaction 输入的交易数据首地址
**************************************************/
void TxAddressCoinSave(unsigned char *datatransaction)
{
	unsigned short num=0;
	unsigned char* p;

	unsigned char  TxoutAdd=0;//以存储输出累加器
	unsigned char  scriplength=0;//报文长度记录
	unsigned char  buf[40];
	unsigned char  buf2[40];
	unsigned short i,wn[1];

	if(Saveaddresscoinokflag==0)
	{
       p=&datatransaction[TxOut_startaddress+1];//将数据指针指向第一个输出数据
	   while(TxoutAdd<ParseData.Transa_txout_num)//判断交易存储是否全部完成
	   {
		memcpy(ParseData.Transa_coincountdata[TxoutAdd].coin,p,Transacoinsize);//存储金额
        p=p+8;//数据指针+8，指向下一位置
		
        scriplength=p[0];//记录报文长度
		p++;
		num=0;
        while(p[0]>0x4b)
		{
			p++;
			num++;
		}
        ParseData.Transa_coincountdata[TxoutAdd].addresslenght[0]=p[0];//记录地址长度
        p++;
		num++;
        memcpy(ParseData.Transa_coincountdata[TxoutAdd].address,p,ParseData.Transa_coincountdata[TxoutAdd].addresslenght[0]);//存储地址
		p=p+ParseData.Transa_coincountdata[TxoutAdd].addresslenght[0];
		num=num+ParseData.Transa_coincountdata[TxoutAdd].addresslenght[0];
		while(num<scriplength)
		{
			num++;
			p++;
		}
  

		for(i=0;i<ParseData.Transa_coincountdata[TxoutAdd].addresslenght[0];i++)
		{
           buf[i]=ParseData.Transa_coincountdata[TxoutAdd].address[i];
		}
		HextoBase58check(buf,ParseData.Transa_coincountdata[TxoutAdd].address,(unsigned short*)&(ParseData.Transa_coincountdata[TxoutAdd].addresslenght[0]));//base58check转换//base58转换

	    TxoutAdd++;//以存储输出累加器+1
	  }

       Saveaddresscoinokflag=1;//地址存储完成置位
	}

}

/**********************************
函数名称：发送签名结果
**********************************/
void Send_sigresault(unsigned char* buf,unsigned char length)
{
	//debug
	unsigned char i;

		printf("TX_sign:\r\n");
	  for(i=0;i<length;i++)
	  {
        printf("%02x",buf[i]);
	  }
      printf("\r\n");
      printf("\r\n");
}

unsigned char Buttonkey=0;
//
void AccordingKey(unsigned char *datatransaction,unsigned short length_tx)
{
	switch(Buttonkey)
	{
	case 0://确认键
		   Tx_signed(datatransaction,length_tx);     //对当前需要签名的交易进行签名
		   Txsignedcount++;//签名计数器累加
		   Send_sigresault(SignResaultSavebuf,SignResaultSavelength[0]);//发送签名结果



		   if(Txsignedcount<ParseData.Transa_txin_num) {}//判断所有输入是否签名完成
		   else
		   {   //成功 签名完成
			   SignResaltState=signSuccess;
			   Txsignedcount=0;//清签名计数器
               TxRecivecompleteflag=0;//清交易数据接收完成标志
			   Saveaddresscoinokflag=0;  ///金额，地址存储完成标志位清零
		   }
	break;
	case 1://取消键
			SignResaltState=signFail; //失败标志位赋值
			TxRecivecompleteflag=0;   //交易数据接收标志位清零
			Saveaddresscoinokflag=0;  ///金额，地址存储完成标志位清零
		break;


	}

}


/*************************************************
函数名称：分析交易数据
入参：datatransaction 输入的交易数据首地址,length_tx 交易长度
出参：分析结果返回值 1 失败，0 成功
**************************************************/

unsigned char parse_transaction_Byte(unsigned char *datatransaction,unsigned short length_tx)
{

	if(TxRecivecompleteflag==1)//交易数据接收完成
	{
		memcpy(ParseData.Transa_verion_data,datatransaction,4);         //版本存入
		ParseData.Transa_txin_num=datatransaction[4];                      //交易输入数量存储处理
		TxOut_startaddress_f(datatransaction);                             //查找长度输出位置
		if((ParseData.Transa_txin_num!=0)&&(ParseData.Transa_txout_num!=0))//判断交易是否合法
		{
		     TxAddressCoinSave(datatransaction);       //对金额，地址进行存储
		     AccordingKey(datatransaction,length_tx);  //根据键值进行操作
		   
		}
		else
		{
		//报错，无法签名
			SignResaltState=signFail; //失败标志位赋值
			TxRecivecompleteflag=0;   //交易数据接收标志位清零
			Saveaddresscoinokflag=0;  ///金额，地址存储完成标志位清零
		}
	}

    

	return 0;
}