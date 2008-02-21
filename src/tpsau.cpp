#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <qdir.h>
#include <qfile.h>
#include <qdatastream.h>

#include "mgcam/helper.h"
#include "tpsau.h"

#define COMP_SECTION_HDR 0x434F4D50
#define INFO_SECTION_HDR 0x494E464F
#define CODE_SECTION_HDR 0x434F4445
#define DATA_SECTION_HDR 0x44415441
#define GDBO_SECTION_HDR 0x4744424F
#define LAST_SECTION_HDR 0x4C415354
#define SWAP_SECTION_HDR 0x53574150

typedef struct comp_header {
	unsigned int magic;
	unsigned int csize, dsize, usize;
	unsigned char end;
} comp_header_t;

typedef struct info_header {
	unsigned int magic;
	unsigned int bsssize;
	unsigned int stacksize;
} info_header_t;

typedef struct code_header {
	unsigned int magic;
	unsigned int size, m_id;
	unsigned short entry_point;
	unsigned short end;
	const unsigned char *code;
} code_header_t;

typedef struct data_header {
	unsigned int magic;
	unsigned int dlen;
	const unsigned char *data;
} data_header_t;



class cOpenTVModule {
private:
  int id, modlen;
  unsigned char *mem;
  int received;
  info_header_t info;
  code_header_t code;
  data_header_t data;
  //
  bool Decompress(void);
  bool DoDecompress(unsigned char *out_ptr, const unsigned char *in_ptr, int dsize, int data_size, int usize);
  bool ParseSections(void);
  void Dump(void);
public:
  cOpenTVModule(const unsigned char *data);
  ~cOpenTVModule();
  int AddPart(const unsigned char *data, int len);
  const info_header_t *InfoHdr(void) const { return &info; }
  const code_header_t *CodeHdr(void) const { return &code; }
  const data_header_t *DataHdr(void) const { return &data; }
  //
  inline static int Id(const unsigned char *data) { return UINT16_BE(&data[3]); }
  inline static int Offset(const unsigned char *data) { return UINT32_BE(&data[16]); }
  inline static int Length(const unsigned char *data) { return UINT32_BE(&data[20]); }
  };

cOpenTVModule::cOpenTVModule(const unsigned char *data)
{
  id=Id(data); modlen=Length(data);
  received=0;
  mem=(unsigned char*)malloc(modlen);
}

cOpenTVModule::~cOpenTVModule()
{
  free(mem);
}

int cOpenTVModule::AddPart(const unsigned char *data, int slen)
{
  if(Id(data)==id) {
    int off=Offset(data);
    int mlen=Length(data);
    int rec=slen-28;
    if(mlen!=modlen || (off+rec)>mlen || !mem) {
      fprintf(stderr,"TpsAu : length mismatch while adding to OpenTV module\n");
      return -1;
      }
    memcpy(&mem[off],data+24,rec);
    received+=rec;
    if(received==mlen) {
      if(!Decompress()) {
        fprintf(stderr,"TpsAu : failed to decompress OpenTV module\n");
        return -1;
        }
      if(!ParseSections()) {
        fprintf(stderr,"TpsAu : DATA & CODE section not located in OpenTV module\n");
        return -1;
        }
      Dump();
      return 1;
      }
    }
  return 0;
}

void cOpenTVModule::Dump(void)
{
}

bool cOpenTVModule::ParseSections(void)
{
  int sections=0;
  for(int idx=0; idx<modlen;) {
    unsigned int hdr=UINT32_BE(mem+idx);
    unsigned int s_len=UINT32_BE(mem+idx+4);
    switch(hdr) {
      case INFO_SECTION_HDR:
	info.magic=hdr;
	info.bsssize=UINT32_BE(mem+idx+8);
	info.stacksize=UINT32_BE(mem+idx+12);
        sections|=1;
        break;
      case CODE_SECTION_HDR:
	code.magic=hdr;
	code.size=s_len-8;
	code.m_id=UINT32_BE(mem+idx+8);
	code.entry_point=UINT16_BE(mem+idx+12);
	code.end=UINT16_BE(mem+idx+14);
	code.code=mem+idx+8;
        sections|=2;
        break;
      case DATA_SECTION_HDR:
	data.magic=hdr;
	data.dlen=s_len-8;
	data.data=mem+idx+8;
        sections|=4;
        break;
      case SWAP_SECTION_HDR:
      case GDBO_SECTION_HDR:
        break;
      case LAST_SECTION_HDR:
      case 0:
        idx=modlen;
        break;
      case COMP_SECTION_HDR:
        fprintf(stderr,"TpsAu : OpenTV module still compressed in ParseSections()");
        return 0;
      default:
        break;
      }
    idx+=s_len;
    }
  return sections>=6;
}

bool cOpenTVModule::Decompress(void)
{
  comp_header_t comp;
  comp.magic=UINT32_BE(mem);
  comp.csize=UINT32_BE(mem+4);
  comp.dsize=UINT32_BE(mem+8);
  comp.usize=UINT32_BE(mem+12);
  comp.end  =UINT8_BE(mem+16);
  if((COMP_SECTION_HDR!=comp.magic) || (comp.dsize<=comp.csize) ||
     (comp.usize>comp.dsize) || (comp.end>=1) || (comp.csize<=17))
    return true;
  unsigned char *decomp=(unsigned char*)malloc(comp.dsize);
  if(!decomp || !DoDecompress(decomp,mem+17,comp.dsize,comp.csize-17,comp.usize))
    return false;
  free(mem);
  mem=decomp; modlen=comp.dsize;
  return true;
}

#define BYTE() ((odd)?((in_ptr[0]&0x0F)|(in_ptr[1]&0xF0)):in_ptr[0])

#define NIBBLE(__v) \
  do { \
    odd^=1; \
    if(odd) __v=in_ptr[0]&0xF0; \
    else {  __v=(in_ptr[0]&0xF)<<4; in_ptr++; } \
    } while(0)

bool cOpenTVModule::DoDecompress(unsigned char *out_ptr, const unsigned char *in_ptr, int dsize, int data_size, int usize)
{
  if(usize==0) return false;
  const unsigned char *data_start=in_ptr;
  unsigned char *out_start=out_ptr;
  unsigned char *out_end=out_ptr+usize;
  int odd=0;
  while(1) {
    unsigned char mask=BYTE(); in_ptr++;
    for(int cnt=8; cnt>0; mask<<=1,cnt--) {
      if(mask&0x80) {
        out_ptr[0]=BYTE(); in_ptr++;
        out_ptr++;
        }
      else {
        int off=0, len=0;
        unsigned char cmd=BYTE(); in_ptr++;
        switch(cmd>>4) {
          case 0x0 ... 0x6:
            off=((cmd&0xF)<<8)+BYTE(); in_ptr++;
            len=((cmd>>4)&0x7)+3;
            break;
          case 0x7:
            {
            unsigned char high=BYTE(); in_ptr++;
            off=((high&0x7F)<<8)+BYTE(); in_ptr++;
            if((cmd==0x7F) && (high&0x80)) {
              len=BYTE(); in_ptr++;
              if(len==0xFF) {
                len=BYTE(); in_ptr++;
                len=((len<<8)+BYTE()+0x121)&0xFFFF; in_ptr++;
                }
              else len+=0x22;
              }
            else {
              len=((cmd&0x0F)<<1)+3; if(high&0x80) len++;
              }
            break;
            }
          case 0x8 ... 0xB:
            if(cmd&0x20) NIBBLE(off); else off=0;
            off=(off<<1)|(cmd&0x1F); len=2;
            break;
          case 0xC:
            off=cmd&0x0F; len=3;
            break;
          case 0xD ... 0xF:
            NIBBLE(off);
            off|=cmd&0x0F; len=((cmd>>4)&0x3)+2;
            break;
          }
        const unsigned char *from=out_ptr-(off+1);
        if(out_start>from || len>(out_end-out_ptr)) {
          fprintf(stderr,"TpsAu : length mismatch in OpenTV decompress\n");
          return false;
          }
        while(--len>=0) *out_ptr++=*from++;
        }
      if(out_end<=out_ptr) {
        if(out_end!=out_ptr) {
          fprintf(stderr,"TpsAu : pointer mismatch in OpenTV decompress\n");
          return false;
          }
        int len=out_start+dsize-out_ptr;
        if(len>0) memmove(out_ptr,data_start+(data_size-(dsize-usize)),len);
        return true;
        }
      }
    }
}

#undef BYTE
#undef NIBBLE



void tpsKey::set( unsigned char* buf )
{
	timestamp[0] = buf[0];
	timestamp[1] = buf[1];
	timestamp[2] = buf[2];
	timestamp[3] = buf[3];
	memcpy( key[0], &buf[4], 16 );
	memcpy( key[1], &buf[4+16], 16 );
	memcpy( key[2], &buf[4+32], 16 );
	step[0] = buf[52];
	step[1] = buf[53];
	step[2] = buf[54];
	step[3] = buf[55];
}



TpsAu::TpsAu() : DVBsection()
{
	keys.setAutoDelete( true );
}



TpsAu::~TpsAu()
{
	keys.clear();
}



bool TpsAu::getSection( int timeout )
{
	int n=0;
//	int skip=0; //unused var
	int min=4;

	if ( poll(pf,1,timeout)>0 ){
		if ( pf[0].revents & POLLIN )
			n = read( fdDemux, sbuf, 4096 );
	}

	if ( n<min ) {
		sbufLen = 0;
		return false;
	}

	sbufLen = n;
	return true;
}



void TpsAu::go( int anum, int tnum )
{
	if ( isRunning )
		return;
	adapter = anum;
	tuner = tnum;
	keys.clear();
	isRunning = true;
	start();
}



void TpsAu::run()
{
	cOpenTVModule *mod=0;

	if ( !openFilter( 4850, 0, 1000, true ) ) {
		isRunning = false;
		return;
	}
	int r=0;
	while ( r==0 ) {
		if ( !getSection( 1000 ) )
			break;

		if(cOpenTVModule::Id(sbuf)==2) {
			if(!mod) mod=new cOpenTVModule(sbuf);
			if(mod) {
				r=mod->AddPart(sbuf,sbufLen);
				if(r>0) {
					fprintf(stderr,"TpsAu : received complete OpenTV module ID 2\n");
				}
				if(r<0) {
					delete mod;
					mod=0;
					r = 0;
				}
			}
		}
	}
	closeFilter();

	if ( r<=0 ) {
		isRunning = false;
		return;
	}

	processAU( mod );

	if ( keys.count() ) {
		save();
		DumpAlgo3();
		QString s = QDir::homeDirPath()+"/.kaffeine/wantTpsAu";
		QFile f( s );
		if ( f.exists() )
			f.remove();
	}

	if ( mod )
		delete mod;
	isRunning = false;
}



bool TpsAu::processAU( const cOpenTVModule *mod )
{
	unsigned char keys_list[128]={ 0x36,0x1B,0x3E,0x2B,0x64,0xC0,0x8A,0x22,0x3C,0x6B,0x12,0xB8,0xD4,0xA9,0x29,0xF3,
		0xA1,0x19,0x36,0x61,0x94,0x44,0x6D,0x3A,0xC9,0xDD,0x3C,0x96,0xD1,0x24,0x73,0x23,
		0x67,0x01,0x9F,0x28,0xA0,0x47,0x6E,0x9C,0x5B,0x8C,0x51,0xC3,0x63,0x19,0x4A,0x7B,
		0x9F,0x0D,0x0B,0xF5,0x46,0x02,0xB0,0x38,0x4B,0x27,0xBA,0xF3,0xF9,0xAC,0x16,0x2B,
		0x37,0x00,0xEB,0x28,0x8C,0x59,0x0B,0x6A,0x8E,0x24,0x88,0x7E,0xB0,0x58,0xA9,0x85,
		0x12,0xD5,0xB0,0xB2,0x60,0xAF,0x62,0x89,0xB5,0xAC,0x51,0x1E,0x27,0x6B,0x36,0xDB,
		0x54,0xE6,0x1C,0x9E,0xBA,0xBE,0x65,0x36,0x29,0xE4,0xEC,0x0B,0x10,0x64,0xF9,0x16,
		0x46,0x1B,0x7A,0x0B,0xDA,0x5E,0x27,0xE5,0x5A,0x62,0x64,0xBE,0x08,0xA0,0xFF,0xC4 };
	tpsKey *k;

  const code_header_t *codehdr=mod->CodeHdr();
  const data_header_t *datahdr=mod->DataHdr();
  const unsigned char *c=codehdr->code;
  const unsigned char *d=datahdr->data;
  unsigned int kd=0, cb1=0, cb2=0, cb3=0;
  for(unsigned int i=0; i<codehdr->size; i++) {
    if(c[i] == 0x81) { // PushEA DS:$xxxx
      unsigned int addr=(c[i+1]<<8)|c[i+2];
      if(addr<(datahdr->dlen-3)) {
        if(d[addr+1]==0x00 && d[addr+3]==0x00 && (d[addr+4]==3|d[addr+4]==2)) kd=addr;
        else if(d[addr]==0x73 && d[addr+1]==0x25) {
          static const unsigned char scan1[] = { 0x28, 0x20, 0x20, 0xC0 };
          for(int j=2; j < 0xC; j++)
            if(!memcmp(&d[addr+j],scan1,sizeof(scan1))) { cb1=addr; break; }
          }
        else if(cb1 && !cb2) cb2=addr;
        else if(cb1 && cb2 && !cb3) cb3=addr;
        /*else if((d[addr]&0xF0)==0x60 && (d[addr+1]&0xF0)==0xB0) {
          int vajw = (int)(((~(d[addr]&0x0F))<<4)|(d[addr+1]&0x0F));
          unsigned char hits=0;
          for(int j=2; j < 0x30; j++) {
            int vld = ((d[addr+j]&0x0F)<<4)|(d[addr+j+1]&0x0F);
            if((d[addr+j]&0xF0)==0x20 && (d[addr+j+1]&0xF0)==0x70) {
              int val=vajw+vld;
              if(val==3 || val==4 || val==5) hits++;
              }
            }
          if(hits==3) cb3=addr;
          else if(cb2 == 0 && hits==2) cb2=addr;
          else if(hits==2) cb3=addr;
          }*/
        }
      }
    }
  if(!kd || !cb1 || !cb2 || !cb3) {
    fprintf(stderr,"TpsAu : couldn't locate all pointers in data section\n");
    return false;
    }
  RegisterAlgo3(d,cb1,cb2,cb3,datahdr->dlen);

  const unsigned char *data=&d[kd];
  int seclen, numkeys;
  seclen=data[0] | (data[1]<<8);
  numkeys=data[2] | (data[3]<<8);
  int algo=data[4];
  int mkidx=data[5]&7;
  unsigned char *sec[7];
  sec[0]=(unsigned char *)data+6;
  for(int i=1; i<6; i++) sec[i]=sec[i-1]+seclen;
  sec[6]=sec[5]+numkeys;
  unsigned char key[16];
  memcpy( key, keys_list+(mkidx*16), 16 );

  if(sec[6]>=d+datahdr->dlen) {
    fprintf(stderr,"TpsAu : section 5 exceeds buffer\n");
    return false;
    }
  int keylen=0;
  for(int i=0; i<numkeys; i++) keylen+=sec[5][i];
  keylen=(keylen+15)&~15;
  if(sec[6]+keylen>=d+datahdr->dlen) {
    fprintf(stderr,"TpsAu : section 6 exceeds buffer\n");
    return false;
    }
  unsigned char tmpkey[16];
  memcpy( tmpkey, key, 16 );
  for(int i=0; i<keylen; i+=16) {
  	memcpy( key, tmpkey, 16 );
  	TpsDecrypt(&sec[6][i],algo,key);
  }

  for(int i=0; i<seclen; i++) {
    static const unsigned char startkey[] = { 0x01,0x01 };
    static const unsigned char startaes[] = { 0x09,0x10 };
    static const unsigned char startse[] = { 0x0a,0x10 };
    unsigned char tmp[56];
    tmp[0]=sec[0][i];
    tmp[1]=sec[1][i];
    tmp[2]=sec[2][i];
    tmp[3]=sec[3][i];
    if(CheckFF(tmp,4)) continue;
    int keyid=sec[4][i];
    int keylen=sec[5][keyid];
    if(keylen<32) continue;
    const unsigned char *tkey=sec[6];
    for(int j=0; j<keyid; j++) tkey+=sec[5][j];

    unsigned char ke[128];
    if(keylen!=45) {
      if(!Handle80008003(tkey,keylen,ke)) continue;
      tkey=ke;
      }

    if(memcmp(tkey,startkey,sizeof(startkey))) continue;
    tmp[52]=0;
    tmp[53]=tkey[5]; //tkey[4];
    tmp[54]=1;       //tkey[5];
    tmp[55]=0x1c;
    tkey+=9;
    if(memcmp(tkey,startaes,sizeof(startaes))) continue;
    memset(&tmp[4+ 0],0,16);
    memcpy(&tmp[4+16],&tkey[2],16);
    tkey+=18;
    if(memcmp(tkey,startse,sizeof(startse))) continue;
    memcpy(&tmp[4+32],&tkey[2],16);
    k = new tpsKey();
    keys.append( k );
    k->set( tmp );
    }
  fprintf(stderr,"TpsAu : got %d keys from AU data\n",keys.count());
  return keys.count()>0;
}



void TpsAu::DumpAlgo3()
{
	if ( !mem )
		return;
	QString  s = QDir::homeDirPath()+"/.kaffeine/tps.algo3";
	QFile f( s );
	if ( f.open(IO_WriteOnly) ) {
		QDataStream t( &f );
		t << memLen;
		t << cb1off;
		t << cb2off;
		t << cb3off;
		t.writeRawBytes( (char*)mem, memLen );
		f.close();
		fprintf(stderr,"TpsAu : algo3 dumped, memLen=%d\n",memLen);
	}
}



void TpsAu::save()
{
	QString s;
	tpsKey *k;
	int i;

	s = QDir::homeDirPath()+"/.kaffeine/tps.au";
	QFile f( s );
	if ( !f.open(IO_WriteOnly) )
		return;
	QDataStream t( &f );
	for ( i=0; i<(int)keys.count(); i++ ) {
		k = keys.at(i);
		t.writeRawBytes( (char*)k->timestamp, 4 );
		t.writeRawBytes( (char*)k->key[0], 16 );
		t.writeRawBytes( (char*)k->key[1], 16 );
		t.writeRawBytes( (char*)k->key[2], 16 );
		t.writeRawBytes( (char*)k->step, 4 );
	}

	f.close();

	keys.clear();
}
