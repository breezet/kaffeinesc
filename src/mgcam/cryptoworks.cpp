#include "cryptoworks.h"
#include "misc.h"
// -- cCwDes -------------------------------------------------------------------
#include <byteswap.h>
// #include <asm/unaligned.h>
// ASM related
#define get_unaligned(ptr) (*(ptr))
#define put_unaligned(val, ptr) ((void)( *(ptr) = (val) ))

#include <string.h>

static const unsigned char cryptoPC1[] = {
	53,46,39,32,50,43,36,29,
	22,15, 8, 1,51,44,37,30,
	23,16, 9, 2,52,45,38,31,
	24,17,10, 3,53,46,39,32,
	25,18,11, 4,56,49,42,35,
	28,21,14, 7,55,48,41,34,
	27,20,13, 6,54,47,40,33,
	26,19,12, 5,25,18,11, 4
};

static const unsigned char cryptoPC2[] = {
	18,21,15,28, 5, 9,   7,32,19,10,25,14,
	27,23,16, 8,30,12,  20,11,31,24,17, 6,
	49,60,39,45,55,63,  38,48,59,53,41,56,
	52,57,47,64,42,61,  54,50,58,44,37,40,
};

#define shiftin(V,R,n) ((V<<1)+(((R)>>(n))&1))
#define rol28(V,n) (V<<(n) | ((V&0x0fffffffL)>>(28-(n))))
#define ror28(V,n) (V>>(n) | ((V&0xfffffff0L)<<(28-(n))))

#define DESROUND(C,D,T) { \
   unsigned int s=0; \
   for(int j=7, k=0; j>=0; j--) { \
     unsigned int v=0, K=0; \
     for(int t=5; t>=0; t--, k++) { \
       v=shiftin(v,T,E[k]); \
       if(PC2[k]<33) K=shiftin(K,C,32-PC2[k]); \
       else          K=shiftin(K,D,64-PC2[k]); \
       } \
     s=(s<<4) + S[7-j][v^K]; \
     } \
   T=0; \
   for(int j=31; j>=0; j--) T=shiftin(T,s,P[j]); \
   }

cCwDes::cCwDes(void)
:cDes(cryptoPC1,cryptoPC2)
{}

void cCwDes::PrepKey(unsigned char *out, const unsigned char *key) const
{
	if(key!=out) memcpy(out,key,8);
	Permute(out,PC1,64);
}

void cCwDes::PrepKey48(unsigned char *out, const unsigned char *key22, unsigned char algo) const
{
	memset(out,0,8);
	memcpy(out,&key22[16],6);
	int ctr=7-(algo&7);
	for(int i=8; i>=2 && i>ctr; i--) out[i-2]=key22[i];
}

void cCwDes::CwDes(unsigned char *data, const unsigned char *key22, int mode) const
{
	unsigned char mkey[8];
	PrepKey(mkey,key22+9);
	unsigned int C=bswap_32(get_unaligned((unsigned int *)(mkey  )));
	unsigned int D=bswap_32(get_unaligned((unsigned int *)(mkey+4)));
	unsigned int L=bswap_32(get_unaligned((unsigned int *)(data  )));
	unsigned int R=bswap_32(get_unaligned((unsigned int *)(data+4)));
	if(!(mode&DES_RIGHT)) {
		for(int i=15; i>=0; i--) {
			C=rol28(C,LS[15-i]); D=rol28(D,LS[15-i]);
			unsigned int T=R;
			DESROUND(C,D,T);
			T^=L; L=R; R=T;
		}
	}
	else {
		for(int i=15; i>=0; i--) {
			unsigned int T=R;
			DESROUND(C,D,T);
			T^=L; L=R; R=T;
			C=ror28(C,LS[i]); D=ror28(D,LS[i]);
		}
	}
	put_unaligned(bswap_32(L),(unsigned int *)(data  ));
	put_unaligned(bswap_32(R),(unsigned int *)(data+4));
}

void cCwDes::CwL2Des(unsigned char *data, const unsigned char *key22, unsigned char algo) const
{
	unsigned char mkey[8];
	PrepKey48(mkey,key22,algo);
	PrepKey(mkey,mkey);
	unsigned int C=bswap_32(get_unaligned((unsigned int *)(mkey  )));
	unsigned int D=bswap_32(get_unaligned((unsigned int *)(mkey+4)));
	unsigned int L=bswap_32(get_unaligned((unsigned int *)(data  )));
	unsigned int R=bswap_32(get_unaligned((unsigned int *)(data+4)));
	for(int i=1; i>=0; i--) {
		C=rol28(C,1); D=rol28(D,1);
		unsigned int T=R;
		DESROUND(C,D,T);
		T^=L; L=R; R=T;
	}
	put_unaligned(bswap_32(L),(unsigned int *)(data  ));
	put_unaligned(bswap_32(R),(unsigned int *)(data+4));
}

void cCwDes::CwR2Des(unsigned char *data, const unsigned char *key22, unsigned char algo) const
{
	unsigned char mkey[8];
	PrepKey48(mkey,key22,algo);
	PrepKey(mkey,mkey);
	unsigned int C=bswap_32(get_unaligned((unsigned int *)(mkey  )));
	unsigned int D=bswap_32(get_unaligned((unsigned int *)(mkey+4)));
	unsigned int L=bswap_32(get_unaligned((unsigned int *)(data  )));
	unsigned int R=bswap_32(get_unaligned((unsigned int *)(data+4)));
	for(int i=1; i>=0; i--) {
		C=rol28(C,15); D=rol28(D,15);
	}
	for(int i=1; i>=0; i--) {
		unsigned int T=R;
		DESROUND(C,D,T);
		T^=L; L=R; R=T;
		C=ror28(C,1); D=ror28(D,1);
	}
	put_unaligned(bswap_32(R),(unsigned int *)(data  ));
	put_unaligned(bswap_32(L),(unsigned int *)(data+4));
}

// -- cCryptoworks -------------------------------------------------------------

cCryptoworks::cCryptoworks(void)
{
	BN_set_word(exp,2);
}

void cCryptoworks::EncDec(unsigned char *data, const unsigned char *key22, unsigned char algo, int mode)
{
	des.CwL2Des(data,key22,algo);
	des.CwDes(data,key22,mode);
	des.CwR2Des(data,key22,algo);
}

void cCryptoworks::Signatura(const unsigned char *data, int len, const unsigned char *key22, unsigned char *sig)
{
	int algo=data[0]&7;
	if(algo==7) algo=6;
	memset(sig,0,8);
	int j=0;
	bool first=true;
	for(int i=0; i<len; i++) {
		sig[j]^=data[i];
		if(++j>7) {
			if(first) {
				des.CwL2Des(sig,key22,algo);
			}
			des.CwDes(sig,key22,DES_LEFT);
			j=0; first=false;
		}
	}
	if(j>0) {
		des.CwDes(sig,key22,DES_LEFT);
	}
	des.CwR2Des(sig,key22,algo);
}

void cCryptoworks::DecryptDES(unsigned char *data, unsigned char algo, const unsigned char *key22)
{
	algo&=7;
	if(algo<7) {
		EncDec(data,key22,algo,DES_RIGHT);
	}
	else {
		unsigned char k[22], t[8];
		memcpy(k,key22,22);
		for(int i=0; i<3; i++) {
			EncDec(data,k,algo,i&1);
			memcpy(t,k,8);
			memcpy(k,k+8,8); memcpy(k+8,t,8);
		}
	}
}

bool cCryptoworks::DecryptRSA(unsigned char *data, int len, unsigned char algo, const unsigned char *key22, BIGNUM *mod)
{
	unsigned char buf[64];
	unsigned char *mask = new unsigned char[len];
	if(!mask)
		return false;
	memcpy(buf,data+len,8);
	EncDec(buf,key22,algo,DES_LEFT);
	buf[0]|=0x80;
	if((algo&0x18)<0x18) buf[0]=0xFF;
	if(algo&8) buf[1]=0xFF;

	static const unsigned char t1[] = { 0xE,0x3,0x5,0x8,0x9,0x4,0x2,0xF,0x0,0xD,0xB,0x6,0x7,0xA,0xC,0x1 };
	for(int k=0; k<len; k+=32) {
		memcpy(buf+8,buf,8);
		for(int i=0; i<8; i++) {
			int n=i<<1;
			buf[n+1]=buf[i+8];
			buf[n  ]=(t1[buf[n+1]>>4]<<4) | t1[buf[i+8]&0xF];
		}
		for(int i=16; i<64; i+=16) memcpy(&buf[i],buf,16);
			buf[31]=((buf[15]<<4)&0xFF) | 6;
			buf[16]=buf[0]^1;
			buf[32]&=0x7F;
			buf[32]|=0x40;
		RotateBytes(buf,32);
		RotateBytes(buf+32,32);

		if(rsa.RSA(buf,buf,64,exp,mod,true)==0) {
			fprintf( stderr, "Cryptoworks: RSA failed\n");
			delete [] mask;
			return false;
		}
		RotateBytes(buf,8);
		RotateBytes(mask+k,buf+8,min(32,len-k));
	}
	xxor(data,len,data,mask);
	delete [] mask;
	return true;
}
