/*
 * Softcam plugin to VDR (C++)
 *
 * This code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * Or, point your browser to http://www.gnu.org/copyleft/gpl.html
 */

#ifndef ___MISC_H
#define ___MISC_H

#include "helper.h"
#include <openssl/bn.h>

#define SCT_LEN(sct) (3+(((sct)[1]&0x0f)<<8)+(sct)[2])

// ----------------------------------------------------------------

bool CheckNull(const unsigned char *data, int len);
bool CheckFF(const unsigned char *data, int len);
unsigned char XorSum(const unsigned char *mem, int len);
void RotateBytes(unsigned char *in, int n);
void RotateBytes(unsigned char *out, const unsigned char *in, int n);
unsigned int crc32_le(unsigned int crc, unsigned char const *p, int len);
//-----------------------------------------------------------------
inline int keynrset(int a,int b,int c)
{
  return ((((a)&0xFF)<<16)|(((b)&0xFF)<<8)|((c)&0xFF));
}
inline int sct_len(unsigned char *sct)
{
	return 3+((sct[1]&0x0f)<<8)+sct[2];
}
template<class T> inline T min(T a, T b) { return a <= b ? a : b; }
// ----------------------------------------------------------------


// -- cBN ----------------------------------------------------------------------

class cBN {
private:
  BIGNUM big;
public:
  cBN(void) { BN_init(&big); }
  ~cBN() { BN_free(&big); }
  operator BIGNUM* () { return &big; }
  bool Get(const unsigned char *in, int n);
  bool GetLE(const unsigned char *in, int n);
  int Put(unsigned char *out, int n) const;
  int PutLE(unsigned char *out, int n) const;
  };

class cBNctx {
private:
  BN_CTX *ctx;
public:
  cBNctx(void) { ctx=BN_CTX_new(); }
  ~cBNctx() { BN_CTX_free(ctx); }
  operator BN_CTX* () { return ctx; }
  };


// ----------------------------------------------------------------

class cSimpleListBase;

class cSimpleItem {
friend class cSimpleListBase;
private:
  cSimpleItem *next;
public:
  virtual ~cSimpleItem() {}
  cSimpleItem *Next(void) const { return next; }
  };

class cSimpleListBase {
protected:
  cSimpleItem *first, *last;
  int count;
public:
  cSimpleListBase(void);
  ~cSimpleListBase();
  void Add(cSimpleItem *Item, cSimpleItem *After=0);
  void Ins(cSimpleItem *Item);
  void Del(cSimpleItem *Item, bool Del=true);
  void Clear(void);
  int Count(void) const { return count; }
  };

template<class T> class cSimpleList : public cSimpleListBase {
public:
  T *First(void) const { return (T *)first; }
  T *Last(void) const { return (T *)last; }
  T *Next(const T *item) const { return (T *)item->cSimpleItem::Next(); }
  };

// --------------------------------------------------------------

class cAssSct : public cSimpleItem {
private:
  const unsigned char *data;
public:
  cAssSct(const unsigned char *Data);
  const unsigned char *Data(void) const { return data; }
  };

class cAssembleData : private cSimpleList<cAssSct> {
private:
  const unsigned char *data;
  cAssSct *curr;
public:
  cAssembleData(const unsigned char *Data);
  void SetAssembled(const unsigned char *Data);
  const unsigned char *Assembled(void);
  const unsigned char *Data(void) const { return data; }
  };

class cProvider : public cSimpleItem {
public:
  virtual bool MatchID(const unsigned char *data)=0;
  virtual bool MatchEMM(const unsigned char *data)=0;
  virtual unsigned long long ProvId(void)=0;
  virtual int UpdateType(const unsigned char *data) { return 2; }
  virtual int Assemble(cAssembleData *ad) { return 0; }
  };

class cProviderViaccess : public cProvider {
private:
  unsigned char *sharedEmm;
  int sharedLen, sharedToggle;
public:
  unsigned char ident[3];
  unsigned char sa[4];
  //
  cProviderViaccess(void);
  cProviderViaccess(const unsigned char *id, const unsigned char *s);
  virtual ~cProviderViaccess();
  virtual bool MatchID(const unsigned char *data);
  virtual bool MatchEMM(const unsigned char *data);
  virtual unsigned long long ProvId(void);
  virtual int UpdateType(const unsigned char *data);
  virtual int Assemble(cAssembleData *ad);
  };

class cParseViaccess {
public:
  static const unsigned char *NanoStart(const unsigned char *data);
  static const unsigned char *CheckNano90(const unsigned char *data);
  static const unsigned char *CheckNano90FromNano(const unsigned char *data);
  static int KeyNr(const unsigned char *data);
  static int KeyNrFromNano(const unsigned char *data);
  static const unsigned char *ProvIdPtr(const unsigned char *data);
  static int ProvId(const unsigned char *data);
  };


#endif //___MISC_H
