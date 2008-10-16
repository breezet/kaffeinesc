#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <openssl/des.h>

#include <qdir.h>
#include <qfile.h>
#include <qregexp.h>

#include "emm.h"



CatParser::CatParser( int anum, int tnum ) : DVBsection( anum, tnum )
{
	emm.setAutoDelete( true );
}



CatParser::~CatParser()
{
	isRunning = false;
	wait();
	reset();
	emm.clear();
}



bool CatParser::parseCAT()
{
	int i;
	int length;
	bool ret=false;
	int system, pid;
	Emm *e;

	for ( i=0; i<(int)emm.count(); i++ ) {
		e = emm.at(i);
		if ( !e->running() ) {
			emm.remove( e );
			--i;
		}
	}
	//fprintf( stderr, "NUMBER OF EMM PIDS: %d\n", emm.count() );

	if ( !getSection( 1, 1, 2000 ) ) {
		return false;
	}

	unsigned char *buf = sbuf;
	length = getBits(buf,12,12);
	buf +=8;

	while ( length>4 ) {
		switch ( getBits(buf,0,8) ) {
			case 0x09 :
				system = getBits(buf+2,0,16);
				pid = getBits(buf+4,3,13);
				/*fprintf( stderr, "\n" );
				fprintf( stderr, "CAT descriptor : %02X\n", getBits(buf,0,8) );
				fprintf( stderr, "CAT length : %d\n", getBits(buf+1,0,8) );
				fprintf( stderr, "CAT system : %04X\n", system );
				fprintf( stderr, "CAT pid : %d\n", pid );
				fprintf( stderr, "\n" );*/
				e = 0;
				for ( Emm *te=emm.first(); te; te=emm.next() ) {
					if ( te->getPid()==pid ) {
						e = te;
						break;
					}
				}
				if ( !e ) {
					switch ( system&0xFFFFFF00 ) {
						case VIACCESS_CA_SYSTEM:
						//case NAGRA_CA_SYSTEM:
						case BETA_CA_SYSTEM:
						case IRDETO_CA_SYSTEM:
							e = new Emm( system, pid, adapter, tuner );
							emm.append( e );
							connect( e, SIGNAL(newKey(const QStringList&)), this, SIGNAL(newKey(const QStringList&)) );
							break;
						default:
							break;
					}
				}
				ret = true;
				break;
			default :
				break;
		}
		length -=( getBits(buf+1,0,8)+2 );
		buf +=( getBits(buf+1,0,8)+2 );
	}

	//fprintf( stderr, "NUMBER OF EMM PIDS: %d\n", emm.count() );

	return ret;
}



bool CatParser::getSection( int pid, int tid, int timeout, bool checkcrc )
{
	int n=0;
	int min=4;

	if ( !setFilter( pid, tid, timeout, checkcrc ) )
		return false;

	if ( poll(pf,1,timeout)>0 ) {
		if ( pf[0].revents & POLLIN )
			n = read( fdDemux, sbuf, 4096 );
	}
	stopFilter();
	if ( n<min ) {
		return false;
	}
	sbufLen = n;
	return true;
}



bool CatParser::go()
{
	if ( isRunning )
		return false;
	isRunning = true;
	start();
	return true;
}



void CatParser::reset()
{
	for ( Emm *e=emm.first(); e; e=emm.next() )
		e->stop();
}



void CatParser::run()
{
	int j;

	while ( isRunning ) {
		parseCAT();
		for ( j=0; j<100; j++ ) {
			if ( !isRunning )
				return;
			usleep( 100000 );
		}
	}
}



Emm::Emm( int sys, int p, int anum, int tnum ) : DVBsection( anum, tnum )
{
	system = sys;
	pid = p;
	lastKey=0;
	nkeys.setAutoDelete( true );
	switch ( system&0xFFFFFF00 ) {
		case VIACCESS_CA_SYSTEM:
			viakid.load();
			break;
		case BETA_CA_SYSTEM:
		case IRDETO_CA_SYSTEM:
			irdkid.load();
			break;
		case NAGRA_CA_SYSTEM:
			getNagra2Keys();
			break;
	}
	isRunning = true;
	start();
}



Emm::~Emm()
{
	isRunning = false;
	wait();
	nkeys.clear();
}



bool Emm::getSection( int timeout )
{
	int n=0;
	int ret;

	if ( (ret=poll(pf,1,timeout))>0 ) {
		if ( pf[0].revents & POLLIN )
			n = read( fdDemux, sbuf, 4096 );
	}
	sbufLen = n;
	if ( ret==0 )
		return false;
	return true;
}



void Emm::stop()
{
	isRunning = false;
}



void Emm::run()
{
	if ( !setFilter( pid, 0, 1000, true ) )
		return;

	while( isRunning ) {
		if ( !getSection( 1000 ) )
			continue;
		if ( sbufLen>4 )
			process();
	}
	stopFilter();
	isRunning = false;
}



void Emm::process()
{
	switch ( system&0xFFFFFF00 ) {
		case VIACCESS_CA_SYSTEM:
			Viaccess( sbuf );
			break;
		case BETA_CA_SYSTEM:
		case IRDETO_CA_SYSTEM:
			Irdeto( sbuf );
			break;
		case NAGRA_CA_SYSTEM:
			if ( sbufLen<11 )
				break;
			int id=sbuf[10]*256+sbuf[11];
			if ( id==0x501 ||id==0x503 ||id==0x511 || id==0x7001 )
				Nagra2( sbuf );
			break;
	}
}

#define WORD(buffer,index,mask) (((buffer[(index)]<<8) + buffer[(index)+1]) & mask)

void IrdetoKID::load()
{
	QString s, t;
	unsigned int prov, provid, serial;
	char hmk[100];
	char pmk[100];
	IrdetoCard *c;
	int i;

	cards.setAutoDelete( true );

	s = QDir::homeDirPath()+"/.kaffeine/Ird-Beta.KID";
	QFile f( s );
	if ( !f.open(IO_ReadOnly) )
		return;

	QTextStream ts( &f );
	while ( !ts.eof() ) {
		s = ts.readLine().upper();
		if ( !s.startsWith(";") || !s.startsWith("#")) {
			s.remove( QRegExp(";.*") );
			if ( sscanf( s.latin1(), "%x %s %x %x %s", &serial, hmk, &prov, &provid, pmk) != 5 )
				continue;
			c = new IrdetoCard();
			c->serial = serial;
			c->prov = prov;
			c->provid = provid;
			t = hmk;
			if ( t.length()==20 )
				for ( i=0; i<10; i++ )
					c->hmk[i] = t.mid(2*i,2).toUShort( 0, 16 );
			t = pmk;
			if ( t.length()==16 )
				for ( i=0; i<8; i++ )
					c->pmk[i] = t.mid(2*i,2).toUShort( 0, 16 );
			cards.append( c );
		}
	}
	f.close();
}



IrdetoKID::~IrdetoKID()
{
	cards.clear();
}



void Emm::Irdeto( unsigned char *buffer )
{
	int i, numKeys=0, date=0;
	unsigned char adr[10], id[4], *pk[4], prov=0, *mk=0, prvId[3]={0,0,0};

	int n=SCT_LEN(buffer);
	unsigned char savebuf[4096];
	if(n>(int)sizeof(savebuf)) {
		//fprintf( stderr, "logger-ird : paket size %d too big for savebuffer in IrdetoLog\n",n);
		return;
	}

	int index=buffer[3] & 0x07;
	memset(adr,0,sizeof(adr));
	memcpy(adr,&buffer[3],index+1);
	index+=4+4; // 3 header + adr type + 4 {0x01 0x00 0x00 len}

	int sindex=index;           // save index for sig. check
	int slen=buffer[index-1]-5; // save packet length, 5 signature bytes
	int maxIndex=index+slen;
	if(maxIndex>n-5) {
		//fprintf(stderr,"logger-ird : bad packet length (%d > %d)\n",maxIndex,n-5);
		maxIndex=n-5;
	}
	bool badnano=false;
	while(!badnano && index<maxIndex) {
		unsigned char nlen=buffer[index+1] & 0x3F;
		//unsigned char prio=buffer[index] & 0x40;
		unsigned char nano=buffer[index] & ~0x40;
		switch(nano) {
			case 0x10: {// key update
				int k=(buffer[index+1]>>6)+1; // key counter
				if(nlen!=k*9) { badnano=true; break; }
				for(i=0 ; i<k ; i++) {
					id[i]= buffer[index+2+0+i*9];
					pk[i]=&buffer[index+2+1+i*9];
					numKeys++;
				}
				break;
			}
			case 0x00: // date
				if(nlen<2) { badnano=true; break; }
				date=WORD(buffer,index+2,0xFFFF);
				break;
			case 0x28: // pmk & provid update
				if(nlen!=13) { badnano=true; break; }
				prov= buffer[index+2+0];
				mk=  &buffer[index+2+2];
				prvId[0]=buffer[index+2+10];
				prvId[1]=buffer[index+2+11];
				prvId[2]=buffer[index+2+12];
				break;
			case 0x29: // pmk update
				if(nlen!=10) { badnano=true; break; }
				prov= buffer[index+2+0];
				mk=  &buffer[index+2+2];
				break;
			case 0x11: // channel id
				if(nlen!=6) { badnano=true; break; }
				//chId[0]=buffer[index+2+0];
				//chId[1]=buffer[index+2+1];
				break;
			case 0x91: // erase channel id
				if(nlen!=6) { badnano=true; break; }
				//eraseChId[0]=buffer[index+2+0];
				//eraseChId[1]=buffer[index+2+1];
				break;
			case 0x8B: // CB20-matrix
				if(nlen!=0x20) { badnano=true; break; }
				//cb20ptr=&buffer[index+2];
				break;
			case 0x22: // set country code
				if(nlen!=3) { badnano=true; break; }
				//
				break;
			case 0x95: // unknown
				if(nlen!=2) { badnano=true; break; }
				//
				break;
			case 0x1E: // unknown
				if(nlen!=15) { badnano=true; break; }
				//
				break;
			case 0x1F: // unknown
				if(nlen!=3) { badnano=true; break; }
				//
				break;
			case 0x16: // unknown
				if(nlen!=2) { badnano=true; break; }
				//
				break;
			case 0x12: // unknown
				if(nlen!=6) { badnano=true; break; }
				//
				break;
			default:
				//fprintf(stderr,"logger-ird : unhandled nano 0x%02x\n",nano);
				break;
		}
		index+=nlen+2;
	}

	if(badnano || index!=maxIndex) {
		//fprintf(stderr,"logger-ird : bad nano/bad paket\n");
		return;
	}

	// lastKey: save cpu time if we get bursts of the same key
	if((numKeys>0 && (id[0]!=lastKey || numKeys>1)) || mk) {
		memcpy(savebuf,buffer,n); // save the buffer
		IrdetoCard *ci=0;
		for ( ci=irdkid.cards.first(); ci; ci=irdkid.cards.next() ) {
			if ( numKeys>0 ) {
				for(i=0 ; i<numKeys ; i++) {
					lastKey=id[i];
					sessionKeyCrypt(pk[i],ci->pmk,date);
				}
				unsigned char chkkey[sizeof(ci->hmk)];
				int keylen;
				if(mk) {
					memcpy(chkkey,ci->hmk,sizeof(ci->hmk)); // key is modified in decryptIrd()
					decryptIrd(mk,chkkey,128,16);
					keylen=sizeof(ci->hmk);
					memcpy(chkkey,ci->hmk,sizeof(ci->hmk)); // signature check with HMK
				}
				else {
					keylen=sizeof(ci->pmk);
					memcpy(chkkey,ci->pmk,sizeof(ci->pmk)); // signature check with PMK
				}

				memcpy(&buffer[sindex-6],adr,5);
				if(signatureCheck(&buffer[sindex-6],slen+6,chkkey,date,&buffer[sindex+slen],keylen)) {
					QStringList skey;
					QString tkey;
					for(i=0 ; i<numKeys ; i++) {
						skey.clear();
						skey.append( "I" );
						skey.append( "00" );
						skey.append( QString().sprintf("%02X", id[i]) );
						tkey="";
						for ( int j=0; j<8; j++ )
							tkey+= QString().sprintf( "%02X", *(pk[i]+j) );
						skey.append( tkey);
						emit newKey( skey );
					}
					break;
				}
				else {
					//fprintf( stderr, "WRONG IRDETO KEY\n" );
				}
				memcpy(buffer,savebuf,n); // restore the buffer
			}
		}
	}
}



void Emm::getNagra2Keys()
{
	QString s, c;
	unsigned int id, knr;
	char key[500];
	int i, j;
	Nagra2Key *nk=0;

	nkeys.clear();

	s = QDir::homeDirPath()+"/.kaffeine/SoftCam.Key";
	QFile f( s );
	if ( !f.open(IO_ReadOnly) )
		return;

	QTextStream t( &f );
	while ( !t.eof() ) {
		s = t.readLine().upper();
		if ( !s.startsWith(";") || !s.startsWith("#")) {
			s.remove( QRegExp(";.*") );
			if ( !s.startsWith("N") || !s.contains("NN") )
				continue;
			if ( sscanf( s.latin1(), "N %x NN %x %s", &id, &knr, key) != 3 )
				continue;
			c = key;
			if ( c.length()!=192 && c.length()!=32 && c.length()!=48 )
				continue;
			nk = new Nagra2Key();
			nk->provid = id;
			nk->keynr = knr;
			if ( c.length()==192 ) {
				j=0;
				char revkey[192];
				for ( i=192-2; i>=0; i-=2 ) {
					revkey[j++] = key[i];
					revkey[j++] = key[i+1];
				}
				BIGNUM* big=nk->big;
				BN_hex2bn( &big, revkey );
			}
			else {
				for ( i=0; i<c.length()/2; i++ )
					nk->key[i] = c.mid(2*i,2).toUShort(0,16);
			}
			nk->keyLen = c.length()/2;
			nkeys.append( nk );
		}
	}
	f.close();
}



Nagra2Key* Emm::findKey( int id, int knr, int len )
{
	Nagra2Key *key;
	for ( key=nkeys.first(); key; key=nkeys.next() ) {
		if ( key->provid==id && key->keynr==knr && key->keyLen==len )
			return key;
	}
	return NULL;
}


#define DES_CAST(x) ((DES_cblock *)(x))

void Emm::Nagra2( unsigned char *buffer )
{
	QStringList skey;
	QString tkey;
	cNagra2 nagra;
	int lastEmmId, updateSel=0;;
	Nagra2Key *rsakey, *rsakey2, *ideakey, *triplekey;

	int cmdLen=buffer[9]-5;
	int id=buffer[10]*256+buffer[11];

	if(cmdLen<96 || SCT_LEN(buffer)<cmdLen+15) {
		//fprintf(stderr,"logger-nagra2: bad EMM message msgLen=%d sctLen=%d\n",cmdLen,SCT_LEN(buffer));
		return;
	}

	int keyset=(buffer[12]&0x03);
	int sel=(buffer[12]&0x10)<<2;

	if ( !(ideakey=findKey( id, keyset, 24 )) ) {
		if ( !(ideakey=findKey( id, keyset, 16 )) ) {
			//fprintf(stderr,"logger-nagra2: missing %04x NN %.02x IDEA key (24 or 16 bytes)\n",id,keyset+sel);
			return;
		}
		else {
			//fprintf(stderr,"logger-nagra2: got %04x NN %.02x IDEA key (24 or 16 bytes)\n",id,keyset+sel);
		}
	}
	else {
		//fprintf(stderr,"logger-nagra2: got %04x NN %.02x IDEA key (24 or 16 bytes)\n",id,keyset+sel);
	}

	unsigned char emmdata[256];
	memset( emmdata, 0, 256 );
	if ( !nagra.DecryptEMM( buffer+14, emmdata, ideakey->key, cmdLen, 0, rsakey->big ) ) {
		//fprintf(stderr,"logger-nagra2: decrypt of EMM failed (%04x)\n",id);
		return;
	}
	else {
		//fprintf(stderr,"logger-nagra2: decrypt of EMM success (%04x)\n",id);
	}

	lastEmmId=id;
	id=(emmdata[8]<<8)+emmdata[9];

	if ( id!=lastEmmId || id==0x7001) {
		//fprintf(stderr,"logger-nagra2: id!=lastEmmId (%04x != %04x)\n",id,lastEmmId);
		if ( !(rsakey2=findKey( lastEmmId, 0x52, 96 )) ) {
			//fprintf(stderr,"logger-nagra2: missing %04x NN %.02X RSA key (96 bytes)\n",id,0x52);
			return;
    		}
		if ( !nagra.DecryptEMM( buffer+14, emmdata, ideakey->key, cmdLen, 0, rsakey2->big ) ) {
			//fprintf(stderr,"logger-nagra2: decrypt of EMM failed (%04x)\n",id);
			return;
		}
		updateSel++;
	}
	id=(emmdata[8]<<8)+emmdata[9];
	if ( id!=lastEmmId ) { // decryption failed
		//fprintf(stderr,"logger-nagra2: decryption failed (%04x)\n",id);
		return;
	}

	for ( int i=8+2+4+4; i<cmdLen-22; ) {
		switch(emmdata[i]) {
			case 0x42: // plain Key update
				if(emmdata[i+2]==0x10 && (emmdata[i+3]&0xBF)==0x06 &&
				(emmdata[i+4]&0xF8)==0x08 && emmdata[i+5]==0x00 && emmdata[i+6]==0x10) {
					if(emmdata[i+1]==0x01) {
						if ( !(triplekey=findKey( id, 0x30, 16 )) )  {
							//fprintf(stderr,"logger-nagra2: missing %04x NN 30 3DES key (16 bytes)\n",id);
							return;
						}
						unsigned char dkey[16];
						memcpy(dkey,triplekey->key,16);
						DES_key_schedule ks1, ks2;
						DES_key_sched((DES_cblock *)&dkey[0],&ks1);
						DES_key_sched((DES_cblock *)&dkey[8],&ks2);
						DES_ecb2_encrypt(DES_CAST(&emmdata[i+7]),DES_CAST(&emmdata[i+7]),&ks1,&ks2,DES_DECRYPT);
						DES_ecb2_encrypt(DES_CAST(&emmdata[i+7+8]),DES_CAST(&emmdata[i+7+8]),&ks1,&ks2,DES_DECRYPT);
						updateSel++;
					}
					skey.clear();
					skey.append( "N" );
					skey.append( QString().sprintf("%04X", id) );
					skey.append( QString().sprintf("%02X", (emmdata[i+3]&0x40)>>6) );
					tkey="";
					for ( int j=0; j<16; j++ )
						tkey+= QString().sprintf( "%02X", emmdata[i+7+j] );
					skey.append( tkey);

					emit newKey( skey );
				}
				i+=23;
				break;
			case 0xE0: // DN key update
				if(emmdata[i+1]==0x25) {
					skey.clear();
					skey.append( "N" );
					skey.append( QString().sprintf("%04X", id) );
					skey.append( QString().sprintf("%02X", (emmdata[i+16]&0x40)>>6) );
					tkey="";
					for ( int j=0; j<16; j++ )
						tkey+= QString().sprintf( "%02X", emmdata[i+23+j] );
					skey.append( tkey);
					emit newKey( skey );
				}
				i+=39;
				break;
			case 0x83: // change data prov. id
				id=(emmdata[i+1]<<8)|emmdata[i+2];
				i+=3;
				break;
			case 0xA4: // conditional (always no match assumed for now)
				i+=emmdata[i+1]+2+4;
				break;
			case 0xA6:
				i+=emmdata[i+1]+1;
				break;
			case 0x13:
			case 0x14:
			case 0x15:
				i+=4;
				break;
			/*case 0xB0: // Update with ROM101 CPU code
				i+=6;
				break;
			case 0xB1: // Update with ROM102 CPU code
				break;
			case 0xE3: // Eeprom update
				i+=emmdata[i+4]+4;
				break;*/
			case 0xE1:
			case 0xE2:
			case 0x00: // end of processing
				i=cmdLen;
				break;
			default:
				i++;
				break;
		}
	}
}



void ViaccessKID::load()
{
	QString s, t;
	unsigned int provid, sa, mknum;
	char ua[100];
	char mk[100];
	ViaccessCard *c;
	int i;
	unsigned char pid[4], psa[4], *p;

	cards.setAutoDelete( true );

	s = QDir::homeDirPath()+"/.kaffeine/Viaccess.KID";
	QFile f( s );
	if ( !f.open(IO_ReadOnly) )
		return;

	QTextStream ts( &f );
	while ( !ts.eof() ) {
		s = ts.readLine().upper();
		if ( !s.startsWith(";") || !s.startsWith("#")) {
			s.remove( QRegExp(";.*") );
			if ( sscanf( s.latin1(), "%x %s %x %x %s", &provid, ua, &sa, &mknum, mk) != 5 )
				continue;
			c = new ViaccessCard();
			c->provid = provid;
			c->sa = sa;
			c->mknum = mknum;
			t = ua;
			if ( t.length()==10 )
				for ( i=0; i<5; i++ )
					c->ua[i] = t.mid(2*i,2).toUShort( 0, 16 );
			t = mk;
			if ( t.length()==16 )
				for ( i=0; i<8; i++ )
					c->mk[i] = t.mid(2*i,2).toUShort( 0, 16 );

			p = (unsigned char *)&(c->provid);
			for ( i=0; i<4; i++ ) pid[i] = p[3-i];
			p = (unsigned char*)&(c->sa);
			for ( i=0; i<4; i++ ) psa[i] = p[3-i];
			c->pv = cProviderViaccess( &pid[1], psa );
			cards.append( c );
		}
	}
	f.close();
}



ViaccessKID::~ViaccessKID()
{
	cards.clear();
}


#define MAX_NEW_KEYS 5

void Emm::Viaccess( unsigned char *buffer )
{
	ViaccessCard *vc=0;

	for ( vc=viakid.cards.first(); vc; vc=viakid.cards.next() ) {
		int updtype;
		cAssembleData ad(buffer);
		if( buffer[0]==0x88 && !memcmp(&buffer[3], vc->ua, sizeof(vc->ua)) ) {
			updtype=3;
			vc->cv.HashClear();
			vc->cv.FillHbuf( 3, vc->ua, sizeof(vc->ua) );
		}
		else if( vc->pv.MatchEMM(buffer)) {
			if( vc->pv.Assemble(&ad)<0) continue;
			updtype=2;
			vc->cv.HashClear();
			vc->cv.FillHbuf( 5, vc->pv.sa, sizeof(vc->pv.sa)-1 );
		}
		else
			continue;

		/*for ( int loop=0; loop<sbufLen; loop++ )
			printf( "%02X ", sbuf[loop] );
		printf( "\n\n" );*/

		const unsigned char *buff;
		if((buff=ad.Assembled())) {
			const unsigned char *scan=cParseViaccess::NanoStart(buff);
			unsigned int scanlen=SCT_LEN(buff)-(scan-buff);

			if(scanlen>=5 && vc->pv.MatchID(buff) &&
				cParseViaccess::KeyNrFromNano(scan)==vc->mknum) {
				scan+=5; scanlen-=5;
				vc->cv.SetHashKey(vc->mk);
				vc->cv.Hash();

				unsigned int n;
				if(scan[0]==0x9e && scanlen>=(n=scan[1]+2)) {
					for(unsigned int i=0; i<n; i++)
						vc->cv.HashByte(scan[i]);
					vc->cv.Hash(); vc->cv.SetPH(0);
					scan+=n; scanlen-=5;
				}
				if(scanlen>0) {
					unsigned char newVKey[MAX_NEW_KEYS][8];
					int numKeys=0, updPrv[MAX_NEW_KEYS]={}, updKey[MAX_NEW_KEYS]={};

					for(unsigned int cnt=0; cnt<scanlen && numKeys<MAX_NEW_KEYS;) {
						const unsigned int parm=scan[cnt++];
						unsigned int plen=scan[cnt++];
						switch(parm) {
							case 0x90:
							case 0x9E:
								cnt+=plen;
								break;
							case 0xA1: // keyupdate
								updPrv[numKeys]=(scan[cnt]<<16)+(scan[cnt+1]<<8)+(scan[cnt+2]&0xF0);
								updKey[numKeys]=scan[cnt+2]&0x0F;
							// fall through
							default:
								vc->cv.HashByte(parm); vc->cv.HashByte(plen);
								while(plen--) vc->cv.HashByte(scan[cnt++]);
								break;
							case 0xEF: // crypted key(s)
								vc->cv.HashByte(parm); vc->cv.HashByte(plen);
								if(plen==sizeof(newVKey[0])) {
									const unsigned char k7=vc->mk[7];
									for(unsigned int kc=0 ; kc<sizeof(newVKey[0]) ; kc++) {
										const unsigned char b=scan[cnt++];
										if(k7&1)
											newVKey[numKeys][kc]=b^(vc->cv.hbuff[vc->cv.pH]&(k7<0x10 ? 0x5a : 0xa5));
										else
											newVKey[numKeys][kc]=b;
										vc->cv.HashByte(b);
									}
									numKeys++;
								}
								else
									cnt=scanlen;
								break;
							case 0xF0: { // signature
//								char str[20], str2[20]; // unused vars
								vc->cv.Hash();
								if(!memcmp(&scan[cnt],vc->cv.hbuff,sizeof(vc->cv.hbuff))) {
									unsigned char key[8];
									memcpy(key,vc->mk,sizeof(key));
									if(key[7]) { // Rotate key
										const unsigned char t1=key[0], t2=key[1];
										key[0]=key[2]; key[1]=key[3]; key[2]=key[4]; key[3]=key[5]; key[4]=key[6];
										key[5]=t1; key[6]=t2;
									}
									while(numKeys--) {
										vc->cv.Decode(newVKey[numKeys],key);
										QStringList skey;
										skey.append( "V" );
										skey.append( QString().sprintf("%06X", updPrv[numKeys]) );
										skey.append( QString().sprintf("%02X", updKey[numKeys]) );
										QString tkey="";
										for ( int j=0; j<8; j++ )
											tkey+= QString().sprintf( "%02X", newVKey[numKeys][j] );
										skey.append( tkey);
										emit newKey( skey ); //connected to KaffeineSc::newKey()
									}
								}
								cnt=scanlen;
								break;
							}
						}
					}
				}
			}
		}
	}
}


#include "emm.moc"
