#include <openssl/bn.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include "openssl-compat.h"

// -- cMapCore -----------------------------------------------------------------

#define SETSIZE  0x02
#define IMPORT_J 0x03
#define IMPORT_A 0x04
#define IMPORT_B 0x05
#define IMPORT_C 0x06
#define IMPORT_D 0x07
#define EXPORT_A 0x0A
#define EXPORT_B 0x0B
#define EXPORT_C 0x0C
#define EXPORT_D 0x0D

class cMapCore {
private:
  cBN x, y, s, j;
  SHA_CTX sctx;
protected:
  cBN A, B, C, D, J;
  cBN H, R;
  cBNctx ctx;
  int wordsize;
  //
  void ImportReg(unsigned char reg, const unsigned char *data, int l=0);
  void ExportReg(unsigned char reg, unsigned char *data, int l=0, bool BE=false);
  void SetWordSize(int l) { wordsize=l; }
  void MakeJ(void);
  void MonMul(BIGNUM *o, BIGNUM *i1, BIGNUM *i2);
  bool DoMap(int f, unsigned char *data=0, int l=0);
public:
  cMapCore(void);
};

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

class cNagra2 : public cNagra, cMapCore {
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
