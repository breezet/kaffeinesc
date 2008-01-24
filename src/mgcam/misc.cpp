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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>

#include "misc.h"


// -----------------------------------------------------------------------------

void SetSctLen(unsigned char *data, int len)
{
  data[1]=(len>>8) | 0x70;
  data[2]=len & 0xFF;
}

static void SortNanos(unsigned char *dest, const unsigned char *src, int len)
{
  int w=0, c=-1;
  while(1) {
    int n=0x100;
    for(int j=0; j<len;) {
      int l=src[j+1]+2;
      if(src[j]==c) {
        if(w+l>len) {
          memset(dest,0,len); // zero out everything
          return;
          }
        memcpy(&dest[w],&src[j],l);
        w+=l;
        }
      else if(src[j]>c && src[j]<n)
        n=src[j];
      j+=l;
      }
    if(n==0x100) break;
    c=n;
    }
}

void RotateBytes(unsigned char *out, const unsigned char *in, int n)
{
  // loop is executed atleast once, so it's not a good idea to
  // call with n=0 !!
  out+=n;
  do { *(--out)=*(in++); } while(--n);
}

void RotateBytes(unsigned char *in, int n)
{
  // loop is executed atleast once, so it's not a good idea to
  // call with n=0 !!
  unsigned char *e=in+n-1;
  do {
    unsigned char temp=*in;
    *in++=*e;
    *e-- =temp;
    } while(in<e);
}

bool CheckNull(const unsigned char *data, int len)
{
  while(--len>=0) if(data[len]) return false;
  return true;
}

bool CheckFF(const unsigned char *data, int len)
{
  while(--len>=0) if(data[len]!=0xFF) return false;
  return true;
}

unsigned char XorSum(const unsigned char *mem, int len)
{
  unsigned char cs=0;
  while(len>0) { cs ^= *mem++; len--; }
  return cs;
}

// crc stuff taken from linux-2.6.0/lib/crc32.c
/*
 * There are multiple 16-bit CRC polynomials in common use, but this is
 * *the* standard CRC-32 polynomial, first popularized by Ethernet.
 * x^32+x^26+x^23+x^22+x^16+x^12+x^11+x^10+x^8+x^7+x^5+x^4+x^2+x^1+x^0
 */
#define CRCPOLY_LE 0xedb88320

unsigned int crc32_le(unsigned int crc, unsigned char const *p, int len)
{
  crc^=0xffffffff; // zlib mod
  while(len--) {
    crc^=*p++;
    for(int i=0; i<8; i++)
      crc=(crc&1) ? (crc>>1)^CRCPOLY_LE : (crc>>1);
    }
  crc^=0xffffffff; // zlib mod
  return crc;
}

// -- cBN ----------------------------------------------------------------------

bool cBN::Get(const unsigned char *in, int n)
{
  return BN_bin2bn(in,n,&big)!=0;
}

int cBN::Put(unsigned char *out, int n) const
{
  int s=BN_num_bytes(&big);
  if(s>n) {
    unsigned char buff[s];
    BN_bn2bin(&big,buff);
    memcpy(out,buff+s-n,n);
    }
  else if(s<n) {
    int l=n-s;
    memset(out,0,l);
    BN_bn2bin(&big,out+l);
    }
  else BN_bn2bin(&big,out);
  return s;
}

bool cBN::GetLE(const unsigned char *in, int n)
{
  unsigned char tmp[n];
  RotateBytes(tmp,in,n);
  return BN_bin2bn(tmp,n,&big)!=0;
}

int cBN::PutLE(unsigned char *out, int n) const
{
  int s=Put(out,n);
  RotateBytes(out,n);
  return s;
}

// -- cSimpleListBase --------------------------------------------------------------

cSimpleListBase::cSimpleListBase(void)
{
  first=last=0; count=0;
}

cSimpleListBase::~cSimpleListBase()
{
  Clear();
}

void cSimpleListBase::Add(cSimpleItem *Item, cSimpleItem *After)
{
  if(After) {
    Item->next=After->next;
    After->next=Item;
    }
  else {
    Item->next=0;
    if(last) last->next=Item;
    else first=Item;
    }
  if(!Item->next) last=Item;
  count++;
}

void cSimpleListBase::Ins(cSimpleItem *Item)
{
  Item->next=first;
  first=Item;
  if(!Item->next) last=Item;
  count++;
}

void cSimpleListBase::Del(cSimpleItem *Item, bool Del)
{
  if(first==Item) {
    first=Item->next;
    if(!first) last=0;
    }
  else {
    cSimpleItem *item=first;
    while(item) {
      if(item->next==Item) {
        item->next=Item->next;
        if(!item->next) last=item;
        break;
        }
      item=item->next;
      }
    }
  count--;
  if(Del) delete Item;
}

void cSimpleListBase::Clear(void)
{
  while(first) Del(first);
  first=last=0; count=0;
}

// -- cAssSct ------------------------------------------------------------------

cAssSct::cAssSct(const unsigned char *Data)
{
  data=Data;
}

// -- cAssembleData ------------------------------------------------------------

cAssembleData::cAssembleData(const unsigned char *Data)
{
  data=Data;
  curr=0;
}

void cAssembleData::SetAssembled(const unsigned char *Data)
{
  Add(new cAssSct(Data));
  curr=First();
}

const unsigned char *cAssembleData::Assembled(void)
{
  const unsigned char *ret=0;
  if(First()) {
    if(curr) {
      ret=curr->Data();
      curr=Next(curr);
      }
    }
  else {
    ret=data;
    data=0;
    }
  return ret;
}

// -- cParseViaccess -----------------------------------------------------------

const unsigned char *cParseViaccess::NanoStart(const unsigned char *data)
{
  switch(data[0]) {
    case 0x88: return &data[8];
    case 0x8e: return &data[7];
    case 0x8c:
    case 0x8d: return &data[3];
    case 0x80:
    case 0x81: return &data[4];
    }
  return 0;
}

const unsigned char *cParseViaccess::CheckNano90(const unsigned char *data)
{
  return CheckNano90FromNano(NanoStart(data));
}

const unsigned char *cParseViaccess::CheckNano90FromNano(const unsigned char *data)
{
  if(data && data[0]==0x90 && data[1]==0x03) return data;
  return 0;
}

int cParseViaccess::KeyNr(const unsigned char *data)
{
  return KeyNrFromNano(CheckNano90(data));
}

int cParseViaccess::KeyNrFromNano(const unsigned char *data)
{
  return data ? data[4]&0x0f : -1;
}

const unsigned char *cParseViaccess::ProvIdPtr(const unsigned char *data)
{
  data=CheckNano90(data);
  return data ? &data[2] : 0;
}

int cParseViaccess::ProvId(const unsigned char *data)
{
  const unsigned char *id=cParseViaccess::ProvIdPtr(data);
  return id ? (id[0]<<16)+(id[1]<<8)+(id[2]&0xf0) : -1;
}

// -- cProviderViaccess --------------------------------------------------------

cProviderViaccess::cProviderViaccess(void)
{
  sharedEmm=0; sharedLen=sharedToggle=0;
}

cProviderViaccess::cProviderViaccess(const unsigned char *id, const unsigned char *s)
{
  sharedEmm=0; sharedLen=sharedToggle=0;
  memcpy(ident,id,sizeof(ident));
  ident[2]&=0xf0;
  memcpy(sa,s,sizeof(sa));
}

cProviderViaccess::~cProviderViaccess()
{
  free(sharedEmm);
}

bool cProviderViaccess::MatchID(const unsigned char *data)
{
  const unsigned char *id=cParseViaccess::ProvIdPtr(data);
  return id && id[0]==ident[0] && id[1]==ident[1] && (id[2]&0xf0)==ident[2];
}

bool cProviderViaccess::MatchEMM(const unsigned char *data)
{
  switch(data[0]) {
    case 0x8e:
      if(memcmp(&data[3],sa,sizeof(sa)-1)) break;
      if((data[6]&2)==0)
        return sharedEmm && MatchID(sharedEmm);
      // fall through
    case 0x8c:
    case 0x8d:
      return MatchID(data);
    }
  return false;
}

unsigned long long cProviderViaccess::ProvId(void)
{
  return (ident[0]<<16)+(ident[1]<<8)+ident[2];
}

int cProviderViaccess::UpdateType(const unsigned char *data)
{
  switch(data[0]) {
    case 0x8e: return 2; // shared
    case 0x8c:
    case 0x8d:
    default:   return 0; // global
    }
}

int cProviderViaccess::Assemble(cAssembleData *ad)
{
  const unsigned char *data=ad->Data();
  int len=SCT_LEN(data);
  switch(data[0]) {
    case 0x8C:
    case 0x8D:
      if(data[0]!=sharedToggle) {
        free(sharedEmm);
        sharedLen=len;
        sharedEmm=(unsigned char *)malloc(len);
        if(sharedEmm) memcpy(sharedEmm,data,sharedLen);
        sharedToggle=data[0];
        }
      break;

    case 0x8E:
      if(sharedEmm) {
        unsigned char tmp[len+sharedLen];
        unsigned char *ass=(unsigned char *)cParseViaccess::NanoStart(data);
        len-=(ass-data);
        if((data[6]&2)==0) {
          const int addrlen=len-8;
          len=0;
          tmp[len++]=0x9e;
          tmp[len++]=addrlen;
          memcpy(&tmp[len],&ass[0],addrlen); len+=addrlen;
          tmp[len++]=0xf0;
          tmp[len++]=0x08;
          memcpy(&tmp[len],&ass[addrlen],8); len+=8;
          }
        else {
          memcpy(tmp,ass,len);
          }
        ass=(unsigned char *)cParseViaccess::NanoStart(sharedEmm);
        int l=sharedLen-(ass-sharedEmm);
        memcpy(&tmp[len],ass,l); len+=l;

        ass=(unsigned char *)malloc(len+7);
        if(ass) {
          memcpy(ass,data,7);
          SortNanos(ass+7,tmp,len);
          SetSctLen(ass,len+4);
          ad->SetAssembled(ass);
          return 1; // assembled
          }
        }
      break;
    }
  return -1; // ignore
}
