#ifndef ___MGCAM_H
#define ___MGCAM_H

extern "C" {
	void decrypt_seca(unsigned char *k,unsigned char *d);
	void encrypt_seca(unsigned char *k,unsigned char *d);
	void sessionKeyCrypt(unsigned char *data,unsigned char *key,int date);
	int signatureCheck(unsigned char *data,int length,unsigned char *key,int date,unsigned char *signature,int keylen);
	void decryptIrd(unsigned char *data,unsigned char *key,int rounds,int offset);
}

#include "viaccess.h"
#include "nagra.h"
#include "cryptoworks.h"

#endif
