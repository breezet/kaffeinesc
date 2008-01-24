#ifndef VIACCESS_H
#define VIACCESS_H

#include "crypto.h"
#include "st20.h"

struct tpsrc6_key {
	unsigned char tpsKey[3][16];
	unsigned char step[3];
};

class cTPS
{
public:
	cTPS();
	~cTPS();
protected:
	void TpsDecrypt(unsigned char *data, short mode, unsigned char *key);
	bool Handle80008003(const unsigned char *src, int len, unsigned char *dest);
	bool RegisterAlgo3(const unsigned char *data, int cb1, int cb2, int cb3, int kd);
	bool DecryptAlgo3( unsigned char *data, const unsigned char *key );
	bool InitST20(void);
	bool loadAlgo3();
	int loadTpsAu( struct tpsrc6_key *k, int*naes );
	unsigned char *mem;
	int memLen, cb1off, cb2off, cb3off;
	cST20 st20;
	bool st20Inited;
};

class cViaccess : protected cDes, protected cTPS
{
private:
	unsigned char v2key[8];
	bool v2mode;
	int HashNanos(const unsigned char *data, int len);
	void Via2Mod(const unsigned char *key2, unsigned char *data);
public:
	unsigned char hbuff[8], hkey[8];
	int pH;
	void SetPH(int val);
	void SetHashKey(const unsigned char *key);
	void HashByte(unsigned char c);
	void HashClear(void);
	void Hash(void);
	void Decode(unsigned char *data, const unsigned char *key);
	virtual unsigned int Mod(unsigned int R, unsigned int key7) const;

	cViaccess();
	void SetV2Mode(const unsigned char *key2);
	bool Decrypt(const unsigned char *work_key,  unsigned char *data, int len, unsigned char *des_data1, unsigned char *des_data2,bool tps,int*naes);
	void FillHbuf( int offset, unsigned char *data, int len );
};
#endif
