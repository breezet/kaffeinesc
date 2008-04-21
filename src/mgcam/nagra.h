#include <openssl/bn.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include "openssl-compat.h"

class cNagraDES {
private:
  cDes des;
public:
  void Decrypt(const unsigned char *data, const unsigned char *key, unsigned char *out, bool desmod=false);
  void Crypt(const unsigned char *data, const unsigned char *key, unsigned char *out);
  bool SigCheck(const unsigned char *block, const unsigned char *sig, const unsigned char *vkey, const int rounds);
};

class cNagra {
protected:
  cRSA rsa;
  //
  virtual void CreatePQ(const unsigned char *pk, BIGNUM *p, BIGNUM *q)=0;
  void ExpandPQ(BIGNUM *p, BIGNUM *q, const unsigned char *data, BIGNUM *e, BIGNUM *m);
public:
  cNagra(void);
  virtual ~cNagra() {};
  void CreateRSAPair(const unsigned char *key, const unsigned char *data, BIGNUM *e, BIGNUM *m);
  unsigned char mecmTable[256];
  void WriteTable(unsigned char *from, int off);
  cBN pubExp;
};

class cNagra1 : public cNagra, public cNagraDES {
protected:
  virtual void CreatePQ(const unsigned char *key, BIGNUM *p, BIGNUM *q);
public:
  bool DecryptECM(const unsigned char *in, unsigned char *out, const unsigned char *vkey, int len, BIGNUM *e1, BIGNUM *n1, BIGNUM *n2);
};

class cNagra2 : public cNagra {
private:
  static const unsigned char primes[];
  unsigned seed[5], cwkey[8];
  bool keyValid;
  //
  bool Signature(const unsigned char *vkey, const unsigned char *sig, const unsigned char *msg, int len);

protected:
  cIDEA idea;

  bool Algo(int algo, const unsigned char *hd, unsigned char *hw);
  void ExpandInput(unsigned char *hw);
  void DoMap(int f, unsigned char *data=0, int l=0);
  //
  virtual void CreatePQ(const unsigned char *key, BIGNUM *p, BIGNUM *q);
public:
  cNagra2(void);
  virtual ~cNagra2();
  bool DecryptECM(const unsigned char *in, unsigned char *out, const unsigned char *key, int len, const unsigned char *vkey, BIGNUM *m);
  bool DecryptEMM( const unsigned char *in, unsigned char *out, const unsigned char *key, int len, const unsigned char *vkey, BIGNUM *m );
  bool MECM(unsigned char in15, int algo, unsigned char *cws);
  void swapCW(unsigned char *cw);

};
