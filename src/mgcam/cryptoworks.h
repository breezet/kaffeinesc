#ifndef ___CRYPTOWORKS_H
#define ___CRYPTOWORKS_H
#include "crypto.h"

class cCwDes : public cDes {
private:
	void PrepKey(unsigned char *out, const unsigned char *key) const;
	void PrepKey48(unsigned char *out, const unsigned char *key22, unsigned char algo) const;
public:
	cCwDes(void);
	void CwDes(unsigned char *data, const unsigned char *key22, int mode) const;
	void CwL2Des(unsigned char *data, const unsigned char *key22, unsigned char algo) const;
	void CwR2Des(unsigned char *data, const unsigned char *key22, unsigned char algo) const;
};

class cCryptoworks {
private:
	cCwDes des;
	cRSA rsa;
	cBN exp;
  //
	void EncDec(unsigned char *data, const unsigned char *key22, unsigned char algo, int mode);
public:
	cCryptoworks(void);
	void Signatura(const unsigned char *data, int len, const unsigned char *key22, unsigned char *sig);
	void DecryptDES(unsigned char *data, unsigned char algo, const unsigned char *key22);
	bool DecryptRSA(unsigned char *data, int len, unsigned char algo, const unsigned char *key22, BIGNUM *mod);
};
#endif
