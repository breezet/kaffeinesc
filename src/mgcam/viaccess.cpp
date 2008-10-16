#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qfile.h>
#include <qdir.h>
#include <qstring.h>
#include <qdatastream.h>

#include "viaccess.h"



cTPS::cTPS()
{
	mem = 0;
	st20Inited = false;
	memLen=cb1off=cb2off=cb3off=0;
}

cTPS::~cTPS()
{
	if ( mem )
		free(mem);
}

int cTPS::loadTpsAu( struct tpsrc6_key *k, int*naes )
{
	int ret=0;
	unsigned char line[100];

	QString  s = QDir::homeDirPath()+"/.kaffeine/tps.au";
	QFile f( s );
	if ( f.open(IO_ReadOnly) ) {
		QDataStream t( &f );
		if ( !f.at( 56*(*naes+1) ) || t.atEnd() ) {
			f.close();
			*naes = -1;
			return 0;
		}
		t.readRawBytes( (char*)line, 56 );
		f.close();
		memcpy( k->tpsKey[0], line+4, 16 );
		k->step[0] = line[52];
		memcpy( k->tpsKey[1], line+20, 16 );
		k->step[1] = line[53];
		memcpy( k->tpsKey[2], line+36, 16 );
		k->step[2] = line[54];
		ret = line[55];
		++*naes;
		return ret;
	}
	*naes = -1;
	return 0;
}

bool cTPS::loadAlgo3()
{
	QString  s = QDir::homeDirPath()+"/.kaffeine/tps.algo3";
	QFile f( s );
	if ( f.open(IO_ReadOnly) ) {
		QDataStream t( &f );
		t >> memLen;
		t >> cb1off;
		t >> cb2off;
		t >> cb3off;
		if ( mem ) { free(mem); mem=0; }
		if(!(mem=(unsigned char*)malloc(memLen))) return false;
		t.readRawBytes( (char*)mem, memLen );
		f.close();
		st20Inited=false;
		fprintf(stderr,"TPS : algo3 loaded, memLen=%d\n", memLen);
		return true;
	}
	return false;
}

bool cTPS::InitST20(void)
{
  if(!mem) return false;
  if(!st20Inited) {
    st20.SetFlash(mem,memLen);
    st20.SetRam(NULL,0x10000);
    st20Inited=true;
    }
  return true;
}

bool cTPS::RegisterAlgo3(const unsigned char *data, int cb1, int cb2, int cb3, int kd)
{
  if ( mem ) { free(mem); mem=0; }
  if(!(mem=(unsigned char*)malloc(kd))) return false;
  memcpy(mem,data,kd);
  memLen=kd; cb1off=cb1; cb2off=cb2; cb3off=cb3;
  st20Inited=false;
  fprintf(stderr,"TpsAu : registered callbacks for algo 3\n");
  return true;
}

bool cTPS::Handle80008003(const unsigned char *src, int len, unsigned char *dest)
{
  if(cb1off && InitST20()) {
    for(int i=0; i<len; i++) st20.WriteByte(RAMS+0x400+i,src[i]);
    st20.WriteShort(RAMS+0x0,0x8000);
    st20.WriteShort(RAMS+0x2,0x8003);
    st20.WriteWord(RAMS+0x8,RAMS+0x400);
    st20.Init(FLASHS+cb1off,RAMS+0xF000);
    st20.SetCallFrame(0,RAMS,0,0);
    int err=st20.Decode(1000);
    if(err<0) {
      fprintf(stderr,"TpsAu : ST20 processing failed in callback1 (%d)\n",err);
      return false;
      }
    for(int i=0; i<0x2D; i++) dest[i]=st20.ReadByte(RAMS+0x400+i);
    return true;
    }
  return false;
}

bool cTPS::DecryptAlgo3( unsigned char *data, const unsigned char *key )
{
  if(cb2off && cb3off && InitST20()) {
    for(int i=0; i<16; i++) st20.WriteByte(RAMS+0x400+i,key[i]);
    st20.Init(FLASHS+cb2off,RAMS+0xF000);
    st20.SetCallFrame(0,RAMS+0x400,RAMS+0x800,0);
    int err=st20.Decode(30000);
    if(err<0) {
      fprintf(stderr,"TPS : ST20 processing failed in callback2 (%d)\n",err);
      return false;
      }

    for(int i=0; i<16; i++) st20.WriteByte(RAMS+0x400+i,data[i]);
    st20.Init(FLASHS+cb3off,RAMS+0xF000);
    st20.SetCallFrame(0,RAMS+0x400,RAMS+0x1000,RAMS+0x800);
    err=st20.Decode(40000);
    if(err<0) {
      fprintf(stderr,"TPS : ST20 processing failed in callback3 (%d)\n",err);
      return false;
      }
    for(int i=0; i<16; i++) data[i]=st20.ReadByte(RAMS+0x1000+i);
    return true;
    }
  return false;
}

void cTPS::TpsDecrypt(unsigned char *data, short mode, unsigned char *key)
{
	if ( mode==0 ) {
		return;
	}
	else if ( mode==1 ) {
		fprintf(stderr, "TPS : doing AES\n");
		cAES aes;
		aes.SetKey( key );
		aes.Decrypt( data, 16 );
	}
	else if ( mode==2 ) {
		fprintf(stderr, "TPS : doing RC6\n");
		cRC6 rc6;
		rc6.SetKey( key );
		rc6.Decrypt( data );
	}
	else if ( mode==3 ) {
		fprintf(stderr, "TPS : doing Algo3\n");
		if ( !mem && !loadAlgo3() )
			return;
		if ( !DecryptAlgo3( data, key ) )
			fprintf(stderr, "TPS : decrypt failed in algo 3\n");
	}
	else {
		fprintf(stderr,"TPS : unknown TPS decryption algo %d\n",mode);
	}
}

cViaccess::cViaccess() : cDes()
{
  v2mode=false;
}

/* viaccess DES modification */

unsigned int cViaccess::Mod(unsigned int R, unsigned int key7) const
{
  if(key7!=0) {
    const unsigned int key5=(R>>24)&0xff;
    unsigned int al=key7*key5 + key7 + key5;
    al=(al&0xff)-((al>>8)&0xff);
    if(al&0x100) al++;
    R=(R&0x00ffffffL) + (al<<24);
    }
  return R;
}

/* viaccess2 modification. Extracted from "Russian wafer" card.
   A lot of thanks to it's author :) */

void cViaccess::Via2Mod(const unsigned char *key2, unsigned char *data)
{
  int kb, db;
  for(db=7; db>=0; db--) {
    for(kb=7; kb>3; kb--) {
      int a0=kb^db;
      int pos=7;
      if(a0&4) { a0^=7; pos^=7; }
      a0=(a0^(kb&3)) + (kb&3);
      if(!(a0&4)) data[db]^=(key2[kb] ^ ((data[kb^pos]*key2[kb^4]) & 0xFF));
      }
    }
  for(db=0; db<8; db++) {
    for(kb=0; kb<4; kb++) {
      int a0=kb^db;
      int pos=7;
      if(a0&4) { a0^=7; pos^=7; }
      a0=(a0^(kb&3)) + (kb&3);
      if(!(a0&4)) data[db]^=(key2[kb] ^ ((data[kb^pos]*key2[kb^4]) & 0xFF));
      }
    }
}

void cViaccess::Decode(unsigned char *data, const unsigned char *key)
{
  if(v2mode) Via2Mod(v2key,data);
  Des(data,key,VIA_DES);
  if(v2mode) Via2Mod(v2key,data);
}

void cViaccess::SetV2Mode(const unsigned char *key2)
{
  if(key2) {
    memcpy(v2key,key2,sizeof(v2key));
    v2mode=true;
    }
  else v2mode=false;
}

void cViaccess::SetPH(int val)
{
	pH = val;
}

void cViaccess::SetHashKey(const unsigned char *key)
{
  memcpy(hkey,key,sizeof(hkey));
}

void cViaccess::HashByte(unsigned char c)
{
  hbuff[pH++]^=c;
  if(pH==8) { pH=0; Hash(); }
}

void cViaccess::FillHbuf( int offset, unsigned char *data, int len )
{
	memcpy(hbuff+offset, data, len);
}

void cViaccess::HashClear(void)
{
  memset(hbuff,0,sizeof(hbuff));
  pH=0;
}

void cViaccess::Hash(void)
{
  if(v2mode) Via2Mod(v2key,hbuff);
  Des(hbuff,hkey,VIA_DES_HASH);
  if(v2mode) Via2Mod(v2key,hbuff);
}

int cViaccess::HashNanos(const unsigned char *data, int len)
{
  int i=0;
  pH=0;
  if(data[0]==0x9f) {
    HashByte(data[i++]);
    HashByte(data[i++]);
    for(int j=0; j<data[1]; j++) HashByte(data[i++]);
    while(pH!=0) HashByte(0);
    }
  for(; i<len; i++) HashByte(data[i]);
  return i;
}

bool cViaccess::Decrypt(const unsigned char *work_key,  unsigned char *data, int len, unsigned char *des_data1, unsigned char *des_data2,bool tps,int*naes)
{
	struct tpsrc6_key k;
	int flagEA=0, flagDF=0;
	int pos=0, encStart=0;
	unsigned char signatur[8];
	bool DF=false;
	while(pos<len) {
		switch(data[pos]) {
			case 0xEA:
				encStart = pos + 2;
				flagEA=pos;
				break;
			case 0xD2:
				break;
			case 0xDF:
				flagDF=pos;
				DF=true;
				break;
			case 0xf0:	/* checksum */
				memcpy(signatur,&data[pos+2],8);
				break;
			default:
				break;
		}
		pos += data[pos+1]+2;
	}

	int doPost=0, doPre=0, doTPS=0, stepbitmap=0;
	if ( DF ) {
		//fprintf(stderr,"TPS : naes=%d\n",*naes);
		stepbitmap=loadTpsAu(&k,naes);
		fprintf( stderr, "NAES = %d, stepbitmap = %d, k.step[0]=%d, k.step[1]=%d, k.step[2]=%d\n", *naes, stepbitmap, k.step[0], k.step[1], k.step[2] );
		if ( (stepbitmap&4)&&(tps) )
                	doTPS=1;
		if ( !(stepbitmap&4) )
			doTPS =(0x6996>>(((data[flagDF+2])&0xF)^((data[flagDF+2])>>4)))&1;
		if ( stepbitmap&8 )
			doPre =(0x6996>>(((data[flagDF+3])&0xF)^((data[flagDF+3])>>4)))&1;
		if ( stepbitmap&16 )
			doPost =(0x6996>>(((data[flagDF+4])&0xF)^((data[flagDF+4])>>4)))&1;

		if ( doPre ) {
			TpsDecrypt(data+flagEA+2,k.step[0],k.tpsKey[0]);
		}
		if ( doTPS ) {
			TpsDecrypt(data+flagEA+2,(DF)?k.step[2]:1,k.tpsKey[2]);
		}
	}
	else if ( tps ) {
		stepbitmap=loadTpsAu(&k,naes);
		TpsDecrypt(data+flagEA+2,1,k.tpsKey[2]);
	}
  memcpy(des_data1,&data[flagEA+2],8);
  memcpy(des_data2,&data[flagEA+2+8],8);
  HashClear();
  SetHashKey(work_key);
  // key preparation
  unsigned char prepared_key[8];
  if(work_key[7]==0) {
    // 8th key-byte = 0 then like Eurocrypt-M but with viaccess mods
    HashNanos(data,encStart+16);
    memcpy(prepared_key,work_key,sizeof(prepared_key));
    }
  else { // key8 not zero
    // rotate the key 2x left
    prepared_key[0]=work_key[2];
    prepared_key[1]=work_key[3];
    prepared_key[2]=work_key[4];
    prepared_key[3]=work_key[5];
    prepared_key[4]=work_key[6];
    prepared_key[5]=work_key[0];
    prepared_key[6]=work_key[1];
    prepared_key[7]=work_key[7];
    // test if key8 odd
    if(work_key[7]&1) {
      HashNanos(data,encStart);
      // test if low nibble zero
      unsigned char k = ((work_key[7] & 0xf0) == 0) ? 0x5a : 0xa5;
      for(int i=0; i<8; i++) {
        unsigned char tmp=des_data1[i];
        des_data1[i]=(k & hbuff[pH]) ^ tmp;
        HashByte(tmp);
        }
      for(int i=0; i<8; i++) {
        unsigned char tmp=des_data2[i];
        des_data2[i]=(k & hbuff[pH]) ^ tmp;
        HashByte(tmp);
        }
      }
    else {
      HashNanos(data,encStart+16);
      }
    }
  Decode(des_data1,prepared_key);
  Decode(des_data2,prepared_key);
	if(doPost)
	{
		unsigned char tmp[16]={0};
		memcpy(tmp,des_data1,8);
		memcpy(tmp+8,des_data2,8);
		TpsDecrypt(&tmp[0],k.step[1],k.tpsKey[1]);
		memcpy(des_data1,tmp,8);
		memcpy(des_data2,tmp+8,8);
	}

  Hash();
  return (memcmp(signatur,hbuff,8)==0);
}

