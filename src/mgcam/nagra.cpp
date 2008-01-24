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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "crypto.h"
#include "nagra.h"
#include "misc.h"
#include "helper.h"

// -- cMapCore -----------------------------------------------------------------

cMapCore::cMapCore(void)
{
  wordsize=4;
}

void cMapCore::ImportReg(unsigned char reg, const unsigned char *in, int l)
{
  l=(l?l:wordsize)<<3;
  switch(reg) {
    case IMPORT_J: J.GetLE(in,8); break;
    case IMPORT_A: A.GetLE(in,l); break;
    case IMPORT_B: B.GetLE(in,l); break;
    case IMPORT_C: C.GetLE(in,l); break;
    case IMPORT_D: D.GetLE(in,l); break;
    default: printf("internal: nagramap import register not supported\n"); return;
    }
}

void cMapCore::ExportReg(unsigned char reg, unsigned char *out, int l, bool BE)
{
  l=(l?l:wordsize)<<3;
  cBN *ptr;
  switch(reg) {
    case EXPORT_A: ptr=&A; break;
    case EXPORT_B: ptr=&B; break;
    case EXPORT_C: ptr=&C; break;
    case EXPORT_D: ptr=&D; break;
    default: printf("internal: nagramap export register not supported\n"); return;
    }
  if(!BE) ptr->PutLE(out,l);
  else ptr->Put(out,l);
}

void cMapCore::MakeJ(void)
{
#if OPENSSL_VERSION_NUMBER < 0x0090700fL
#error BN_mod_inverse is probably buggy in your openssl version
#endif
  BN_zero(x);
  BN_sub(J,x,D);
  BN_set_bit(J,0);
  BN_set_bit(x,64);
  BN_mod_inverse(J,J,x,ctx);
}

void cMapCore::MonMul(BIGNUM *o, BIGNUM *i1, BIGNUM *i2)
{
  int words=(BN_num_bytes(i1)+7)>>3;
  BN_zero(s);
  for(int i=0; i<words; i++) {	
    BN_rshift(x,i1,i<<6);
    BN_mask_bits(x,64);
    BN_mul(x,x,i2,ctx);
    BN_add(s,s,x);

    BN_copy(x,s);
    BN_mask_bits(x,64);
    BN_mul(x,x,J,ctx);
    if(i==(words-1)) {
      BN_lshift(y,x,64);
      BN_add(y,y,x);
      // Low
      BN_rshift(C,y,2);
      BN_add(C,C,s);
      BN_rshift(C,C,52);
      BN_mask_bits(C,12);
      }

    BN_mask_bits(x,64);
    BN_mul(x,x,D,ctx);
    BN_add(s,s,x);
    if(i==(words-1)) {
      // High
      BN_lshift(y,s,12);
      BN_add(C,C,y);
      BN_mask_bits(C,wordsize<<6);
      }

    BN_rshift(s,s,64);
    if(BN_cmp(s,D)==1) {
      BN_copy(x,s);
      BN_sub(s,x,D);
      }
    }
  BN_copy(o,s);
}

bool cMapCore::DoMap(int f, unsigned char *data, int l)
{
  switch(f) {
    case 0x43: // init SHA1
      SHA1_Init(&sctx);
      break;
    case 0x44: // add 64 bytes to SHA1 buffer
      RotateBytes(data,64);
      SHA1_Update(&sctx,data,64);
      BYTE4_LE(data   ,sctx.h4);
      BYTE4_LE(data+4 ,sctx.h3);
      BYTE4_LE(data+8 ,sctx.h2);
      BYTE4_LE(data+12,sctx.h1);
      BYTE4_LE(data+16,sctx.h0);
      break;
    case 0x45: // add wordsize bytes to SHA1 buffer and finalize SHA result
      if(wordsize) {
        if(wordsize>1) RotateBytes(data,wordsize);
        SHA1_Update(&sctx,data,wordsize);
        }
      memset(data,0,64);
      SHA1_Final(data+64,&sctx);
      break;
    default:
      return false;
    }
  return true;
}


// -- cNagraDES ----------------------------------------------------------------

void cNagraDES::Decrypt(const unsigned char *data, const unsigned char *key, unsigned char *out, bool desmod)
{
  unsigned char cardkey[8];
  memcpy(cardkey,key,8);
  RotateBytes(cardkey,8);
  memcpy(out,data,8);
  if(!desmod) RotateBytes(out,8);
  des.Des(out,cardkey,NAGRA_DES_DECR);
  if(!desmod) RotateBytes(out,8);
}

void cNagraDES::Crypt(const unsigned char *data, const unsigned char *key, unsigned char *out)
{
  unsigned char cardkey[8];
  memcpy(cardkey,key,8);
  RotateBytes(cardkey,8);
  memcpy(out,data,8);
  RotateBytes(out,8);
  des.Des(out,cardkey,NAGRA_DES_ENCR);
  RotateBytes(out,8);
}

bool cNagraDES::SigCheck(const unsigned char *block, const unsigned char *sig, const unsigned char *vkey, const int rounds)
{
  unsigned char hash[8];
  memcpy(hash,vkey,8);
  for(int j=0; j<rounds; j++) {
    unsigned char cr[8];
    Crypt(block+j*8,hash,cr);
    for(int i=0; i<8; i++) hash[i]=cr[i]^block[j*8+i];
    }
  return (0==memcmp(hash,sig,8));
}

// -- cNagra -------------------------------------------------------------------

cNagra::cNagra(void)
{
  BN_set_word(pubExp,3);
  memset(mecmTable,0,sizeof(mecmTable));
}

void cNagra::WriteTable(unsigned char *from, int off)
{
  off&=0xFF;
  if(off+16<256) memcpy(mecmTable+off,from,16);
  else {
    int l=256-off;
    memcpy(mecmTable+off,from,l);
    memcpy(mecmTable,from+l,16-l);
    }
}

void cNagra::CreateRSAPair(const unsigned char *key, const unsigned char *data, BIGNUM *e, BIGNUM *m)
{
  // Calculate P and Q from data
  cBN p,q;
  CreatePQ(key,p,q);
  ExpandPQ(p,q,data,e,m);
}

void cNagra::ExpandPQ(BIGNUM *p, BIGNUM *q, const unsigned char *data, BIGNUM *e, BIGNUM *m)
{
  // Calculate N=P*Q (modulus)
  cBNctx ctx;
  BN_mul(m,p,q,ctx);
  if(data) BN_bin2bn(data,64,e); // set provided data as E1
  else {                         // else calculate the 'official' one
    // E = ( ( ( (P-1) * (Q-1) * 2) + 1) / 3)
    BN_sub_word(p,1);
    BN_sub_word(q,1);
    BN_mul(e,p,q,ctx);
    BN_mul_word(e,2);
    BN_add_word(e,1);
    BN_div_word(e,3);
    }
}

// -- cNagra1 ------------------------------------------------------------------

#define dn(x) x;
#define d(x) x;
#define dl(x) x;

bool cNagra1::DecryptECM(const unsigned char *in, unsigned char *out, const unsigned char *vkey, int len, BIGNUM *e1, BIGNUM *n1, BIGNUM *n2)
{
  cBN result;
  if(rsa.RSA(result,&in[2],len,pubExp,n2)<=0) {
    dn(printf("nagra: error decrypting ECM (round 1)\n"))
    return false;;
    }
  cBN mod;
  BN_set_word(mod,in[0]>>4);
  BN_lshift(mod,mod,508);
  BN_add(result,result,mod);
  if(rsa.RSA(out,64,result,e1,n1,false)!=64) {
    dn(printf("nagra: error: result of ECM decryption is not 64 bytes\n"))
    return false;
    }
  if(vkey && !SigCheck(out,&out[56],vkey,7)) {
    dn(printf("nagra: ECM decryption failed\n"))
    return false;
    }
  return true;
}

void cNagra1::CreatePQ(const unsigned char *key, BIGNUM *p, BIGNUM *q)
{
  // Make des_key
  unsigned char des_data[32];
  unsigned char des_key[8], des_tmp[8];
  memcpy(des_data,key,8);
  RotateBytes(des_tmp,key,8);
  des_tmp[7]=0x00;
  Decrypt(des_data,des_tmp,des_key,true);
  RotateBytes(des_key,8);
  des_key[7]=0x00;

  // Calculate P
  for(int i=0; i<4; i++) {
    const int off=i*8;
    memcpy(&des_data[off],&key[4],8);
    des_data[off]^=i;
    Decrypt(&des_data[off],des_key,des_tmp,true);
    memcpy(&des_data[off],des_tmp,8);
    }
  BN_bin2bn(des_data,32,p);
  BN_add_word(p,(key[12]<<4)|((key[13]>>4)&0x0f));
  BN_set_bit(p,(BN_num_bytes(p)*8)-1);

  // Calculate Q
  for(int i=0; i<4; i++) {
    const int off=i*8;
    memcpy(&des_data[off],&key[4],8);
    des_data[off]^=(i+4);
    Decrypt(&des_data[off],des_key,des_tmp,true);
    memcpy(&des_data[off],des_tmp,8);
    }
  BN_bin2bn(des_data,32,q);
  BN_add_word(q,((key[13]&0x0f)<<8)|key[14]);
  BN_set_bit(q,(BN_num_bytes(q)*8)-1);
}

// -- cNagra2 ------------------------------------------------------------------

cNagra2::cNagra2(void)
{
  keyValid=false;
}

cNagra2::~cNagra2()
{
}

void cNagra2::CreatePQ(const unsigned char *key, BIGNUM *p, BIGNUM *q)
{
  // Calculate P and Q from PK
  IdeaKS ks;
  idea.SetEncKey(key,&ks);
  // expand IDEA-G key
  unsigned char idata[96];
  for(int i=11; i>=0; i--) {
    const int off=i*8;
    memcpy(&idata[off],&key[13],8);
    idata[off]^=i;
    idea.Decrypt(&idata[off],8,&ks,0);
    for(int j=7; j>=0; j--) idata[off+j] ^= key[13+j];
    idata[off]^=i;
    }
  // Calculate P
  idata[0] |= 0x80;
  idata[47] |= 1;
  BN_bin2bn(idata,48,p);
  BN_add_word(p,(key[21] << 5 ) | ((key[22] & 0xf0) >> 3));
  // Calculate Q
  idata[48] |= 0x80;
  idata[95] |= 1;
  BN_bin2bn(idata+48,48,q);
  BN_add_word(q,(key[22] &0xf << 9 ) | (key[23]<<1));
}

bool cNagra2::Signature(const unsigned char *vkey, const unsigned char *sig, const unsigned char *msg, int len)
{
  unsigned char buff[16];
  memcpy(buff,vkey,sizeof(buff));
  for(int i=0; i<len; i+=8) {
    IdeaKS ks;
    idea.SetEncKey(buff,&ks);
    memcpy(buff,buff+8,8);
    idea.Encrypt(msg+i,8,buff+8,&ks,0);
    for(int j=7; j>=0; j--) buff[j+8]^=msg[i+j];
    }
  buff[8]&=0x7F;
  return (memcmp(sig,buff+8,8)==0);
}

bool cNagra2::DecryptECM(const unsigned char *in, unsigned char *out, const unsigned char *key, int len, const unsigned char *vkey, BIGNUM *m)
{
  int sign=in[0] & 0x80;
  if(rsa.RSA(out,in+1,64,pubExp,m)<=0) {
    d(printf("nagra2: first RSA failed (ECM)\n"))
    return false;
    }
  out[63]|=sign; // sign adjustment
  if(len>64) memcpy(out+64,in+65,len-64);

  if(in[0]&0x04) {
    unsigned char tmp[8];
    DES_key_schedule ks1, ks2;
    RotateBytes(tmp,&key[0],8);
    DES_KEY_SCHED((DES_cblock *)tmp,ks1);
    RotateBytes(tmp,&key[8],8);
    DES_KEY_SCHED((DES_cblock *)tmp,ks2);
    memset(tmp,0,sizeof(tmp));
    for(int i=7; i>=0; i--) RotateBytes(out+8*i,8);
    DES_EDE2_CBC_ENCRYPT(out,out,len,ks1,ks2,(DES_cblock *)tmp,DES_DECRYPT);
    for(int i=7; i>=0; i--) RotateBytes(out+8*i,8);
    }
  else idea.Decrypt(out,len,key,0);

  RotateBytes(out,64);
  if(rsa.RSA(out,out,64,pubExp,m,false)<=0) {
    d(printf("nagra2: second RSA failed (ECM)\n"))
    return false;
    }
  if(vkey && !Signature(vkey,out,out+8,len-8)) {
    d(printf("nagra2: signature failed (ECM)\n"))
    return false;
    }
  return true;
}

bool cNagra2::DecryptEMM(const unsigned char *in, unsigned char *out, const unsigned char *key, int len, const unsigned char *vkey, BIGNUM *m)
{
  int sign=in[0]&0x80;
  if(rsa.RSA(out,in+1,96,pubExp,m)<=0) {
    dl(printf("nagra2: first RSA failed (EMM)\n"))
    return false;
    }
  out[95]|=sign; // sign adjustment
  cBN exp;
  if(in[0]&0x08) {
    // standard IDEA decrypt
    if(len>96) memcpy(out+96,in+97,len-96);
    idea.Decrypt(out,len,key,0);
    BN_set_word(exp,3);
    }
  else {
    // private RSA key expansion
    CreateRSAPair(key,0,exp,m);
    }
  RotateBytes(out,96);
  if(rsa.RSA(out,out,96,exp,m,false)<=0) {
    dl(printf("nagra2: second RSA failed (EMM)\n"))
    return false;
    }
  if(vkey && !Signature(vkey,out,out+8,len-8)) {
    dl(printf("nagra2: signature failed (EMM)\n"))
    return false;
    }
  return true;
}

void cNagra2::DoMap(int f, unsigned char *data, int l)
{
  printf("nagra2: calling MECM function %02X\n",f);
  switch(f) {
    case 0x37:
      l=(l?l:wordsize)<<3;
      H.GetLE(data,l);
      MonMul(B,H,A);
      break;
    case 0x3a:
      MakeJ();
      BN_zero(R);
      BN_set_bit(R,68*wordsize);
      BN_mod(H,R,D,ctx);
      for(int i=0; i<4; i++) MonMul(H,H,H);
      MonMul(B,A,H);
      MonMul(B,A,B);
      break;
    default:
      if(!cMapCore::DoMap(f,data,l))
        printf("nagra2: unsupported MECM call %02x\n",f);
      break;
    }
}

bool cNagra2::Algo(int algo, const unsigned char *hd, unsigned char *hw)
{
  if(algo==0x60) {
    hw[0]=hd[0];
    hw[1]=hd[1];
    hw[2]=hd[2]&0xF8;
    ExpandInput(hw);
    hw[63]|=0x80;
    hw[95]=hw[127]=hw[95]&0x7F;
    //default value - SetWordSize(4);
    ImportReg(IMPORT_J,hw+0x18);
    ImportReg(IMPORT_D,hw+0x20);
    ImportReg(IMPORT_A,hw+0x60);
    DoMap(0x37,hw+0x40);
    ExportReg(EXPORT_C,hw);
    DoMap(0x3a);
    ExportReg(EXPORT_C,hw+0x20);
    DoMap(0x43);
    DoMap(0x44,hw);
    hw[0]&=7;
    ExportReg(EXPORT_B,hw+3);
    memset(hw+3+0x20,0,128-(3+0x20));
    return true;
    }

  printf("nagra2: unknown MECM algo %02x\n",algo);
  return false;
}


void cNagra2::ExpandInput(unsigned char *hw)
{
  hw[0]^=(0xDE +(0xDE<<1)) & 0xFF;
  hw[1]^=(hw[0]+(0xDE<<1)) & 0xFF;
  for(int i=2; i<128; i++) hw[i]^=hw[i-2]+hw[i-1];
  IdeaKS ks;
  idea.SetEncKey((unsigned char *)"NagraVision S.A.",&ks);
  unsigned char buf[8];
  memset(buf,0,8);
  for(int i=0; i<128; i+=8) {
    xxor(buf,8,buf,&hw[i]);
    idea.Encrypt(buf,8,buf,&ks,0);
    xxor(buf,8,buf,&hw[i]);
    memcpy(&hw[i],buf,8);
    }
}

bool cNagra2::MECM(unsigned char in15, int algo, unsigned char *cw)
{
  unsigned char hd[5], hw[128+64], buf[20];
  hd[0]=in15&0x7F;
  hd[1]=cw[14];
  hd[2]=cw[15];
  hd[3]=cw[6];
  hd[4]=cw[7];

  /*if(keyValid && !memcmp(seed,hd,5)) {	// key cached
    memcpy(buf,cwkey,8);
    }
*/
  //else {				// key not cached
    memset(hw,0,sizeof(hw));
    if(!Algo(algo,hd,hw)) return false;
    memcpy(&hw[128],hw,64);
    RotateBytes(&hw[64],128);
    SHA1(&hw[64],128,buf);
    RotateBytes(buf,20);

    memcpy(seed,hd,5);
    memcpy(cwkey,buf,8);
    keyValid=true;
    //}  

  memcpy(&buf[8],buf,8);
  IdeaKS ks;
  idea.SetEncKey(buf,&ks);
  memcpy(&buf[0],&cw[8],6);
  memcpy(&buf[6],&cw[0],6);
  idea.Encrypt(&buf[4],8,&buf[4],&ks,0);
  idea.Encrypt(buf,8,buf,&ks,0);

  memcpy(&cw[ 0],&buf[6],3);
  memcpy(&cw[ 4],&buf[9],3);
  memcpy(&cw[ 8],&buf[0],3);
  memcpy(&cw[12],&buf[3],3);
  for(int i=0; i<16; i+=4) cw[i+3]=cw[i]+cw[i+1]+cw[i+2];
  return true;
}

void cNagra2::swapCW(unsigned char *cw)
{
  printf("nagra2: calling swapCW\n");
  
/*if(NeedsCwSwap()) */

    {
	unsigned char tt[8];
	memcpy(&tt[0],&cw[0],8);
	memcpy(&cw[0],&cw[8],8);
	memcpy(&cw[8],&tt[0],8);
    } 
}
