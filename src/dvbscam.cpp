#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <qdir.h>
#include <qfile.h>
#include <qregexp.h>

#include <klocale.h>

#include "dvbscam.h"



Ecm::Ecm()
{
	csPort=csCAID=id=pid=system=sid=tsid=chid=0;
}



Ecm::~Ecm()
{
	counter.clear();
}



Skey::Skey()
{
	type=0;
	id=tsid=0;
	keynr=0;
	key=v2key=0;
	bkey=0;
}



Skey::~Skey()
{
	if ( bkey )
		delete bkey;
}



DVBscam::DVBscam( int anum, int tnum, QPtrList<CardClient> *list ) : DVBsection( anum, tnum )
{
	int fd;

	csList = list;

	QString s = QString("/dev/dvb/adapter%1/video%2").arg( anum ).arg( tnum );
	if ( (fd=open( s.ascii(), O_RDWR | O_NONBLOCK ))<0 ) {
  perror ("open failed");
		fd = 0;
	}
	else {
		close( fd );
		s = QString("/dev/dvb/adapter%1/ca%2").arg( anum ).arg( tnum );
		if ( (fd=open( s.ascii(), O_RDWR | O_NONBLOCK ))<0 ) {
			perror ("open failed");
			fd = -1;
		}
	}

	cafd = fd;

	getCachedEcms();
	getFineTune();
	cEcms.setAutoDelete( true );
	ecms.setAutoDelete( true );
	keys.setAutoDelete( true );
 	cw = false;
	tsID = 0;
	tsbuf = NULL;
	tsbuf_seek = 0;
	ntune = 0;
	tsbuf_full = false;
	naes = -1;
}



DVBscam::~DVBscam()
{
	int j;

	isRunning = false;
	wait();
	ecms.clear();
	keys.clear();
	saveCachedEcms();
	cEcms.clear();
	for ( j=0; j<(int)csList->count(); j++ )
		csList->at(j)->unregisterProgram( programNumber, tsID );
	if ( tsbuf )
		delete [] tsbuf;
}



void DVBscam::printError( QString msg )
{
	fprintf( stderr, "%s\n", msg.latin1() );
}



void DVBscam::addCaDesc( Ecm *e )
{
	int i;
	bool add=true;
	Ecm *c;

	for ( i=0; i<(int)ecms.count(); i++ ) {
		c = ecms.at(i);
		if ( c->system==e->system && c->id==e->id && c->pid==e->pid ) {
			add = false;
			break;
		}
	}
	if ( add ) {
		ecms.append( e );
		if ( e->id )
			fprintf( stderr, "Found %s id %x\n", e->name.ascii(), e->id );
		else
			fprintf(stderr, "Found %s\n", e->name.ascii() );
	}
	else
		delete e;
}



void DVBscam::caDesc( unsigned char *buf )
{
	Ecm *e;
	int ca_system, ca_system_up;
	int j, length, pid=0, id=0;
	QString name;

	length = getBits(buf+1,0,8);
	buf +=2;

	/*printf("ca_descr");
	for (j=0; j<length; j++) printf(" %02x",buf[j]);
	printf("\n");*/

	ca_system = (buf[0] << 8) | buf[1];
	ca_system_up = (buf[0] << 8);

	if ( ca_system_up==SECA_CA_SYSTEM ) {
		for (j=2; j<length; j+=15) {
			pid = ((buf[j] & 0x1f) << 8) | buf[j+1];
			id = (buf[j+2] << 8) | buf[j+3];
			if ( id && pid ) {
				e = new Ecm();
				e->system = ca_system;
				e->name = "Seca";
				e->pid = pid;
				e->id = id;
				addCaDesc( e );
			}
		}
	}
	else if ( ca_system_up==VIACCESS_CA_SYSTEM ) {
		j = 4;
		while (j < length) {
			if (buf[j]==0x14) {
				pid = ((buf[2] & 0x1f) << 8) | buf[3];
				id = (buf[j+2] << 16) | (buf[j+3] << 8) | (buf[j+4] & 0xf0);
				if ( id && pid ) {
					e = new Ecm();
					e->system = ca_system;
					e->name = "Viaccess";
					e->pid = pid;
					e->id = id;
					addCaDesc( e );
				}
			}
			j += 2+buf[j+1];
		}
	}
	else if ( ca_system>=DREAMCRYPT_CA_SYSTEM && ca_system<=DREAMCRYPT_CA_SYSTEM_LAST ) {
		if ( (pid=((buf[2] & 0x1f) << 8) | buf[3])!=0 ) {
			e = new Ecm();
			e->system = ca_system;
			e->name = "Dreamcrypt";
			e->pid = pid;
			addCaDesc( e );
		}
	}
	else {
		switch ( ca_system_up ) {
			case IRDETO_CA_SYSTEM:
				name = "Irdeto";
				break;
			case BETA_CA_SYSTEM:
				name = "Betacrypt";
				break;
			case NAGRA_CA_SYSTEM:
				name = "Nagra";
				break;
			case CRYPTOWORKS_CA_SYSTEM:
				name = "Cryptoworks";
				break;
			case CONAX_CA_SYSTEM:
				name = "Conax";
				break;
			case NDS_CA_SYSTEM:
				name = "NDS/Videguard";
				break;
			case POWERVU_CA_SYSTEM:
				name = "PowerVU";
				break;
			case BISS_CA_SYSTEM:
				name = "BISS";
				break;
			default:
				name = "ConstantCW";
				break;
		}
		if ( (name=="ConstantCW") || (name=="BISS") )
			pid = -1;
		else
			pid = ((buf[2] & 0x1f) << 8) | buf[3];
		if ( pid!=0 ) {
			e = new Ecm();
			e->system = ca_system;
			e->name = name;
			if ( pid>0 )
				e->pid = pid;
			else
				e->pid = 0;
			addCaDesc( e );
		}
	}
}



bool DVBscam::parsePAT( unsigned char *buf, int sid, int &pmt, bool tsidOnly )
{
	int length;
	int cursid;
	int curpmt;

	tsID = getBits(buf+3,0,16);
	if ( tsidOnly )
		return true;

	length = getBits(buf,12,12);
	length -=5;
	buf +=8;

	while ( length>4 ) {
		cursid = getBits(buf,0,16);
		curpmt = getBits(buf,19,13);
		buf +=4;
		length -=4;
		if ( cursid==sid ) {
			pmt = curpmt;
			return true;
		}
	}

	return false;
}



bool DVBscam::parsePMT( unsigned char* buf )
{
	int length, loop;
	bool ret=false;

	length = getBits(buf,12,12);
	loop = getBits(buf+10,4,12);
	length -=(9+loop);
	buf +=12;

	while ( loop>0 ) {
		switch ( getBits(buf,0,8) ) {
			case 0x09 :
				caDesc( buf );
				ret = true;
				break;
			default :
				break;
		}
		loop -=( getBits(buf,8,8)+2 );
		buf +=( getBits(buf,8,8)+2 );
	}

	while ( length>4 ) {
		loop = getBits(buf,28,12);
		buf +=5;
		length -=(5+loop);
		while ( loop>0 ) {
			switch ( getBits(buf,0,8) ) {
				case 0x09 :
					caDesc( buf );
					ret = true;
					break;
				default :
					break;
			}
			loop -=( getBits(buf,8,8)+2 );
			buf +=( getBits(buf,8,8)+2 );
		}
	}

	return ret;
}



bool DVBscam::getSection( int pid, int tid, int timeout, bool checkcrc, int sid )
{
	int n=0;
	int min;
	bool loop=false;
	QValueList<int> sidList;
	int cursid;

	if ( pid==0 )
		min = 12;
	else if ( tid==0x02 )
		min = 16;
	else min = 4;

	if ( !setFilter( pid, tid, timeout, checkcrc ) ) return false;

	do {
		if ( poll(pf,1,timeout)>0 ){
			if ( pf[0].revents & POLLIN ){
				n = read( fdDemux, sbuf, 4096 );
				cursid = getBits(sbuf+3,0,16);
				if ( sid && cursid!=sid && !sidList.contains(cursid) ) {
					sidList.append( cursid );
					loop = true;
				}
				else
					loop = false;
			}
		}
	} while ( loop );

	stopFilter();

	if ( n<min )
		return false;

	sbufLen = n;
	return true;
}



bool DVBscam::go( int sid )
{
	if ( isRunning || (cafd==-1) )
		return false;
	cw = false;
	ecms.clear();
	programNumber = sid;
	isRunning = true;
	printError( i18n("Softcam : searching key ...") );
	start();
	return true;
}



void DVBscam::stop()
{
	if ( isRunning ) {
		isRunning = false;
		wait();
	}
	if ( cafd>0 )
		close( cafd );
}



CardClient *DVBscam::getCardClient( Ecm *e )
{
	int j;
	CardClient *cc;

	for ( j=0; j<(int)csList->count(); j++ ) {
		cc = csList->at(j);
		if ( cc->canHandle(e->csCAID, e->id) && cc->getHost()==e->csHost && cc->getPort()==e->csPort )
			return cc;
	}
	return NULL;
}



void DVBscam::run()
{
	int pmtpid=0;
	Ecm *e=0;
	Ecm *ce;
	int i, j;
	unsigned char parity=0xff;
	int loop=0;
	bool stop;
	CardClient *currentCC=0;

	if ( !tsID ) {
		if ( getSection( 0x00, 0x00, 5000 ) )
			parsePAT( sbuf, programNumber, pmtpid );
	}
	getFineTune();

	if ( !getKeys() )
		printError( i18n("Softcam : Can't read SoftCam.Key !") );

	// search in cache
	for ( i=0; i<(int)cEcms.count(); i++ ) {
		if ( !isRunning ) return;
		if ( cEcms.at(i)->sid==programNumber && cEcms.at(i)->tsid==tsID ) {
			currentCC = getCardClient( cEcms.at(i) );
			if ( process( currentCC, cEcms.at(i), 0xff ) ) {
				e = cEcms.at(i);
				parity = sbuf[0];
				loop = 1;
				break;
			}
			else cEcms.remove(i);
		}
	}

	while ( isRunning ) {
		if ( !e && !pmtpid ) {
			fprintf( stderr, "Reading PAT\n" );
			if ( !getSection( 0x00, 0x00, 5000 ) ) {
				printError( i18n("Softcam : Can't read PAT !") );
				sleep(1);
				continue;
			}
			if ( !parsePAT( sbuf, programNumber, pmtpid ) ) {
				printError( i18n("Softcam : Program not found in PAT !") );
				sleep(1);
				continue;
			}
		}

		if ( !e ) {
			fprintf( stderr, "Reading PMT\n" );
			if ( !getSection( pmtpid, 0x02, 5000, true, programNumber ) ) {
				printError( i18n("Softcam : Can't read PMT !") );
				sleep(1);
				continue;
			}

			ecms.clear();
			if ( !parsePMT( sbuf ) ) {
				cw = true;
				printError( i18n("Softcam : No encryption system found.") );
				for ( j=0; j<10; j++ ) {
					if ( !isRunning ) return;
					usleep( 100000 );
				}
				loop = 0;
			}
			else loop = 1;
		}

		badcwhack = false;
		while ( loop && isRunning ) {
			if ( e ) {
				if ( process( currentCC, e, parity ) ) {
					parity = sbuf[0];
					for ( j=0; j<10; j++ ) {
						if ( !isRunning )
							return;
						usleep( 100000 );
					}
				}
				else {
					e = 0;
					currentCC = 0;
				}
			}
			else {
				currentCC = 0;
				for ( i=0; i<(int)cEcms.count(); i++ ) {
					if ( !isRunning ) return;
					if ( cEcms.at(i)->sid==programNumber && cEcms.at(i)->tsid==tsID ) {
						currentCC = getCardClient( cEcms.at(i) );
						if ( process( currentCC, cEcms.at(i), 0xff ) ) {
							e = cEcms.at(i);
							parity = sbuf[0];
							break;
						}
						else cEcms.remove(i);
					}
				}
				if ( e ) continue;
				for ( i=0; i<(int)ecms.count(); i++ ) {
					if ( !isRunning ) return;
					if ( process( 0, ecms.at(i), 0xff ) ) {
						e = ecms.at(i);
						ce = new Ecm();
						ce->tsid = tsID;
						ce->sid = programNumber;
						ce->id = e->id;
						ce->system = e->system;
						ce->pid = e->pid;
						cEcms.append( ce );
						parity = sbuf[0];
						break;
					}
				}
				if ( e ) continue;
				stop = false;
				for ( i=0; i<(int)ecms.count(); i++ ) {
					if ( !isRunning ) return;
					for ( j=0; j<(int)csList->count(); j++ ) {
						if ( csList->at(j)->canHandle( ecms.at(i)->system, ecms.at(i)->id ) ) {
							if ( !isRunning ) return;
							if ( process( csList->at(j), ecms.at(i), 0xff ) ) {
								currentCC = csList->at(j);
								e = ecms.at(i);
								ce = new Ecm();
								ce->tsid = tsID;
								ce->sid = programNumber;
								ce->id = e->id;
								ce->system = e->system;
								ce->pid = e->pid;
								ce->csHost = currentCC->getHost();
								ce->csPort = currentCC->getPort();
								ce->csCAID = currentCC->getCaId();
								cEcms.append( ce );
								parity = sbuf[0];
								stop = true;
								break;
							}
						}
					}
					if ( stop )
						break;
				}
				if ( !e ) {
					loop = 0;
					if ( !getKeys() )
						printError( i18n("Softcam : Can't read SoftCam.Key !") );
				}
			}
		}
	}
}



bool DVBscam::checkCHID( Ecm *e, int evod )
{
#define MAX_LOOP 5
	unsigned char tmp[4096];
	int tmplen=0;
	unsigned char *buf;
	bool stop=false;
	int counter = 0;
	int max = 0;
	int loop = 0;
	int dmx, n;
	unsigned char tbuf[500];
	struct dmx_pes_filter_params pesFilterParams;
	dmx_pes_type_t pestype = DMX_PES_OTHER;
	struct pollfd pfd[1];

	if ( ( dmx = open( QString("/dev/dvb/adapter%1/demux%2").arg(adapter).arg(tuner).ascii(), O_RDWR | O_NONBLOCK )) < 0 ) {
		perror("DEMUX DEVICE: ");
		return false;
	}
	pfd[0].fd = dmx;
	pfd[0].events = POLLIN;

	pesFilterParams.pid = e->pid;
	pesFilterParams.input = DMX_IN_FRONTEND;
	pesFilterParams.output = DMX_OUT_TAP;
	pesFilterParams.pes_type = pestype;
	pesFilterParams.flags = DMX_IMMEDIATE_START;
	if ( ioctl( dmx, DMX_SET_PES_FILTER, &pesFilterParams) < 0)  {
		perror("DMX SET PES FILTER");
		close( dmx );
		return false;
	}

	if ( e->chid ) {
		do {
			n = 0;
			if ( poll(pfd,1,2000)>0 ){
				if ( pfd[0].revents & POLLIN ){
					n = read( dmx, tbuf, 184 );
				}
			}
			if ( !n ) {
				fprintf( stderr, "can't get section for pid : %06x\n", e->pid );
				close( dmx );
				return false;
			}

			if ( evod==tbuf[1] ) {
				close( dmx );
				return true;
			}

			++loop;
			buf = &tbuf[1];
			max = buf[5];
			do {
				if ( e->chid!=((buf[6]<<8)+buf[7]) ) {
					++counter;
					buf+=(buf[11]+12);
				}
				else {
					stop = true;
					break;
				}
			} while ( buf[0]==0x80 || buf[0]==0x81 );
		} while ( counter<=max && loop<MAX_LOOP && !stop );

		if ( !stop ) {
			close( dmx );
			return false;
		}
		else {
			sbufLen = buf[11]+12;
			memcpy( sbuf, buf, sbufLen );
			close( dmx );
			return true;
		}
	}
	else {
		do {
			n = 0;
			if ( poll(pfd,1,2000)>0 ){
				if ( pfd[0].revents & POLLIN ){
					n = read( dmx, tbuf, 184 );
				}
			}
			if ( !n ) {
				fprintf( stderr, "can't get section for pid : %06x\n", e->pid );
				close( dmx );
				return false;
			}

			if ( evod==tbuf[1] ) {
				close( dmx );
				return true;
			}

			++loop;
			buf = &tbuf[1];
			max = buf[5];
			do {
				if ( e->counter.contains(buf[4]) )
					break;
				else {
					e->counter.append(buf[4]);
					memcpy( tmp+tmplen, buf, buf[11]+12 );
					tmplen+=(buf[11]+12);
					buf+=(buf[11]+12);
				}
			} while ( buf[0]==0x80 || buf[0]==0x81 );
		} while ( (int)e->counter.count()<=max && loop<MAX_LOOP );

		sbufLen = tmplen;
		memcpy( sbuf, tmp, sbufLen );
		close( dmx );
		return true;
	}
}



bool DVBscam::process( CardClient *cc, Ecm *e, int evod )
{
	unsigned char *buf;
	int buflen;
	int id=e->id;

	if ( !e->pid ) {
		if(e->system==0x2600)
			return ConstantCW( e, programNumber, 1 );
		else
			return ConstantCW( e, programNumber, 0 );
	}

	if ( (e->system&0xFFFFFF00)==IRDETO_CA_SYSTEM && cc ) {
		if ( !checkCHID( e, evod ) )
			return false;
	}
	else {
		if ( !getSection( e->pid, 0, 1000, false ) ) {
			fprintf( stderr, "can't get section for pid : %06x\n", e->pid );
			return false;
		}
	}

	if ( evod==sbuf[0] )
		return true;

	buf = sbuf;
	if ( (e->system&0xFFFFFF00)==IRDETO_CA_SYSTEM && cc )
		buflen = buf[11]+12;
	else
		buflen = sbufLen;

	if ( cc ) {
		switch( (e->system&0xFFFFFF00) ) {
			case IRDETO_CA_SYSTEM:
			case BETA_CA_SYSTEM:
				e->id = sbuf[8];
				break;
			case NAGRA_CA_SYSTEM:
				e->id = (sbuf[5]*256)+sbuf[6];
				break;
			default:
				break;
		}
		e->sid = programNumber;
		e->tsid = tsID;
again:
		if ( cc->processECM( buf, buflen, CW, e, badcwhack ) ) {
			if ( (e->system&0xFFFFFF00)==IRDETO_CA_SYSTEM )
				e->chid = ((buf[6]<<8)+buf[7]);
			writeCw();
			e->id = id;
			return true;
		}
		else {
			if ( (e->system&0xFFFFFF00)==IRDETO_CA_SYSTEM ) {
				buf+= buf[11]+12;
				if ( buf>(sbuf+sbufLen-12) ) {
					e->counter.clear();
					return false;
				}
				else
					goto again;
			}
			else
				return false;
		}
	}

	switch( (e->system&0xFFFFFF00) ) {
		case VIACCESS_CA_SYSTEM:
			return Viaccess( &sbuf[4], sbuf[2]-1, e->id );
		case SECA_CA_SYSTEM:
			return Seca( &sbuf[8], sbuf[2]-5, e->id, sbuf[7] & 0x0f);
		case IRDETO_CA_SYSTEM:
		case BETA_CA_SYSTEM:
			return Irdeto( &sbuf[6], sbuf[11]+6, sbuf[8] );
		case NAGRA_CA_SYSTEM:
			if(e->system==0x1801)
				return Nagra2( &sbuf[0] );
			else if(e->system==0x1800)
				return Nagra1( &sbuf[0] );
			else // each provider use is own id
                                return Nagra3( );
		case CRYPTOWORKS_CA_SYSTEM:
			return Cryptoworks(&sbuf[0], e->system);
	}

       // Adding CW to all channels
        if ( e->pid ) // should not try CW again if system was allready CW
	    return ConstantCW( e, programNumber, 0 );

//	return false;
}



bool DVBscam::FindKey( char type, int &id, int keynr, unsigned char *key, int keylen )
{
	Skey *k=0;
	unsigned char *p=NULL;
	int i;

	for (i=0; i<(int)keys.count(); i++ ) {
		k = keys.at(i);
		if ( k->type==type && k->id==id && k->tsid==-1 ) { // LINK
			id = k->keynr;
			i = 0;
			continue;
		}
		if ( k->type==type && k->keynr==keynr && k->id==id ) {
			if ( keylen>8 && !k->v2key )
				return false;
			if ( keylen<8 )
				return false;
			p = (unsigned char *)&(k->key);
			for (i=0; i<8; i++)
				key[i] = p[7-i];
			if ( k->v2key ) {
				if ( keylen<16 )
					return false;
				p = (unsigned char *)&(k->v2key);
				for (i=0; i<8; i++)
					key[i+8] = p[7-i];
			}
			return true;
		}
	}
	return false;
}



bool DVBscam::FindKey( char type, int id, int keynr, BIGNUM **key )
{
	int i;
	Skey *k;

	for ( i=0; i<(int)keys.count(); i++ ) {
		k = keys.at(i);
		if ( k->type==type && k->id==id && k->keynr==keynr && k->bkey ) {
			*key = k->bkey;
			return true;
		}
	}
	return false;
}



bool DVBscam::FindKey( char type, int id, BIGNUM **key )
{
	int i;
	Skey *k;

	for ( i=0; i<(int)keys.count(); i++ ) {
		k = keys.at(i);
		if ( k->type==type && k->id==id && k->bkey ) {
			*key = k->bkey;
			return true;
		}
	}
	return false;
}



bool DVBscam::Cryptoworks( unsigned char *data, int caid )
{
#define ECM_ALGO_TYP   5
#define ECM_DATA_START ECM_ALGO_TYP
#define ECM_NANO_LEN   7
#define ECM_NANO_START 8

	int i;

	fprintf( stderr, "\nbuflen : %d\n", sbufLen );
	for ( i=0; i<sbufLen; i++ ) fprintf( stderr, "%02x ", sbuf[i] );
	fprintf( stderr, "\n" );

	int len=sct_len(data);
	if(data[ECM_NANO_LEN]!=len-ECM_NANO_START) {
		fprintf( stderr, "Cryptoworks: invalid ECM structure\n");
		return false;
	}

	int prov=-1, keyid=0;
	for(int i=ECM_NANO_START; i<len; i+=data[i+1]+2) {
		if(data[i]==0x83) {
		prov =data[i+2]&0xFC;
		keyid=data[i+2]&0x03;
		break;
		}
	}
	if(prov<0) {
		fprintf( stderr, "Cryptoworks: provider ID not located in ECM\n");
		return false;
	}

	unsigned char key[22];
	if(!(FindKey('W',caid,keynrset(prov,0xff,0xcc), key+14, 8))) {
		fprintf( stderr, "Cryptoworks: missing %04X %02X CC key\n",caid,prov);
		return false;
	}
	fprintf(stderr,"Trying W %04X %02X CC ",caid,prov);
	for ( i=0; i<6; i++ )
		fprintf( stderr, "%02X", key[i+16] );
	fprintf( stderr, "\n" );

	cCryptoworks cryptoworks;

// RSA stage
	for( i=ECM_NANO_START; i<len; i+=data[i+1]+2) {
		int l=data[i+1]+2;
		switch(data[i]) {
			case 0x85:
			{
				if(!(FindKey('W',caid,keynrset(prov,0x31,keyid),key,16 ))){
					fprintf( stderr, "Cryptoworks: missing %04X %02X 31 %02X key\n",caid,prov,keyid);
					return false;
				}
				BIGNUM *mod=0;
				if ( !FindKey( 'W', caid, keynrset(prov,0x10,0x00), &mod ) ) {
					fprintf( stderr, "Cryptoworks: No RSA key found for : id %04x\n", caid );
					return false;
				}
				unsigned char *p = (unsigned char *)(mod->d);
				fprintf( stderr, "RSA key : " );
				for ( int j=0; j<64; j++ )
					fprintf( stderr, "%02X", p[j] );
				fprintf(stderr,"\n");
				l-=10;
				if(!cryptoworks.DecryptRSA(&data[i+2],l,data[ECM_ALGO_TYP],key,mod))
				{
					return false;
				}
				memmove(&data[i],&data[i+2],l);
				memmove(&data[i+l],&data[i+l+10],len-i-l);
				len-=10;
				break;
			}
			case 0x86:
				memmove(&data[i],&data[i+l],len-i-l);
				len-=l;
				continue;
		}
	}
	if(!(FindKey('W',caid,keynrset(prov,0x20,keyid),key,16 ))) {
		fprintf( stderr, "Cryptoworks: missing %04X %02X 20 %02X key\n",caid,prov,keyid);
		return false;
	}
	fprintf(stderr,"Trying W %04X %02X 20 %02X ",caid,prov,keyid);
	for ( i=0; i<16; i++ )
		fprintf( stderr, "%02X", key[i] );
	fprintf( stderr, "\n" );

// DES stage
	unsigned char sig[8];
	data[ECM_NANO_LEN]=len-ECM_NANO_START;
	cryptoworks.Signatura(&data[ECM_DATA_START],len-ECM_DATA_START-10,key,sig);
	for(int i=ECM_NANO_START; i<len; i+=data[i+1]+2) {
		switch(data[i]) {
			case 0xDA:
			case 0xDB:
			case 0xDC:
				for(int j=0; j<data[i+1]; j+=8)
					cryptoworks.DecryptDES(&data[i+2+j],data[ECM_ALGO_TYP],key);
				break;
			case 0xDF:
				if(memcmp(&data[i+2],sig,8)) {
					fprintf( stderr, "Cryptoworks: signature failed in ECM\n");
					return false;
				}
				break;
		}
	}
// CW stage
	for(int i=ECM_NANO_START; i<len; i+=data[i+1]+2) {
		switch(data[i]) {
			case 0xDB:
				if(data[i+1]==0x10) {
					memcpy(CW,&data[i+2],16);
					writeCw();
					return true;
				}
			break;
		}
	}
	return false;
}



bool DVBscam::ConstantCW( Ecm *e, int sid, int biss )
{
 	int i;
 	unsigned char *p;
 	Skey *k=0;

	if (biss) {
		for ( i=0; i<(int)keys.count(); i++ ) {
			k = keys.at(i);
			if ( (k->type=='B' || k->type=='b') && k->tsid==tsID /* && k->id==e->system */ && k->keynr==sid )
				break;
			else
				k = 0;
		}
		if ( !k ) {
			fprintf(stderr,"No BISS Key found for sid %d\n", sid );
			return false;
		}
		fprintf(stderr, "Using BISS key for sid %d\n", sid );
        }
	else {
		for ( i=0; i<(int)keys.count(); i++ ) {
			k = keys.at(i);
			if ( (k->type=='X' || k->type=='x') && k->tsid==tsID && k->id==e->system && k->keynr==sid )
				break;
			else
				k = 0;
		}
		if ( !k ) {
			fprintf(stderr,"No Constant CW found for system %x sid %d\n", e->system, sid );
			return false;
		}
		fprintf(stderr, "Using Constant CW system %x sid %d\n", e->system, sid );
	}

	p = (unsigned char *)&k->v2key;
	for ( i=0; i<8; i++ )
		CW[15-i] = p[i];
	p = (unsigned char *)&k->key;
	for ( i=0; i<8; i++ )
		CW[7-i] = p[i];
	writeCw();
	for ( i=0; i<50; i++ ) { // sleep 5 secs
		if ( !isRunning )
			return true;
		usleep( 100000 );
	}
	return true;
}



bool DVBscam::Nagra1( unsigned char *data )
{
	int i;
	cNagra1 nagra;
	unsigned char *p=NULL;
	unsigned char sessionKey[8];

	fprintf( stderr, "\nbuflen : %d\n", sbufLen );
	for ( i=0; i<sbufLen; i++ ) fprintf( stderr, "%02x ", sbuf[i] );
	fprintf( stderr, "\n" );

	int cmdLen=data[4];
	int id=(data[5]*256)+data[6];
	//cTimeMs minTime;
	if(data[3]!=0x03) {
		fprintf(stderr,"nagra1 : invalid ECM\n");
		return false;
	}
	data+=7;
	if(data[0]!=0x10) {
		fprintf(stderr,"nagra1 : no ECM data available\n");
		return false;
	}
	const int ecmLen=data[1];
	const int keynr=(data[2]>>4)&1;
	const int ecmParm=data[2]&7;
	bool decrypt;
	if(ecmParm==7) decrypt=false;
	else if(ecmParm==5) decrypt=true;
	else {
		fprintf(stderr,"nagra1 : unknown ecmParm, ignoring ECM\n");
		return false;
	}

	if ( !FindKey( 'N', id, keynr, sessionKey, 8 ) ) {
		fprintf(stderr,"No Nagra key found for :  id : %06X keynr : %02X\n", id, keynr );
		return false;
	}
	fprintf(stderr,"Trying key N %06X %02X ",id,keynr);
	for ( i=0; i<8; i++ )
		fprintf( stderr, "%02X", sessionKey[i] );
	fprintf( stderr, "\n" );

	const int desLen=(ecmLen-9) & ~7; // datalen - signature - ks byte
	unsigned char decrypted[desLen];
	for( i=(desLen/8)-1; decrypt && i>=0; i--) {
		const int off=i*8;
		nagra.Decrypt(data+11+off,sessionKey,decrypted+off);
	}
	int cwEvenMecmIndex=-1, cwOddMecmIndex=-1;
	switch(decrypted[0]) {
		case 0x10:  // Whole CW
			cwOddMecmIndex=decrypted[1];
			memcpy(CW+8,&decrypted[2],8);
			cwEvenMecmIndex=decrypted[10];
			memcpy(CW,&decrypted[11],8);
			break;
		case 0x11: // Odd CW
			cwOddMecmIndex=decrypted[1];
			memcpy(CW+8, &decrypted[2],8);
			break;
		case 0x12: // Even CW
			cwEvenMecmIndex=decrypted[1];
			memcpy(CW,&decrypted[2],8);
			break;
		default:
			fprintf(stderr,"nagra1 : failed to get CW\n");
			return false;
	}

	const unsigned char * const mecmData=data+(ecmLen+2);
	const int mecmRSALen=mecmData[1]-4;
	if((cmdLen-(ecmLen+2))>64 && (*mecmData==0x20 || *mecmData==0x39)) {
		if(mecmRSALen!=64) {
			if(mecmRSALen>64 )
				fprintf(stderr,"nagra1 : ECM too big (len: %d)\n",mecmRSALen);
			return false;
		}
		const int mecmProvId=mecmData[2]*256+mecmData[3];
		BIGNUM *e1=0, *n1=0, *n2=0;

		if ( !FindKey( 'E', id, &e1 ) ) {
			fprintf(stderr,"nagra1 : missing %04x E1 key\n",mecmProvId);
			return false;
		}
		p = (unsigned char *)(e1->d);
		fprintf( stderr, "E1 key : " );
		for ( i=0; i<64; i++ ) fprintf( stderr, "%02X", p[i] );
			fprintf(stderr,"\n");

		if ( !FindKey( '1', id, &n1 ) ) {
			fprintf(stderr,"nagra1 : missing %04x N1 key\n",mecmProvId);
			return false;
		}
		p = (unsigned char *)(n1->d);
		fprintf( stderr, "N1 key : " );
		for ( i=0; i<64; i++ ) fprintf( stderr, "%02X", p[i] );
			fprintf(stderr,"\n");

		if ( !FindKey( '2', id, &n2 ) ) {
			fprintf(stderr,"nagra1 : missing %04x N2 key\n",mecmProvId);
			return false;
		}
		p = (unsigned char *)(n2->d);
		fprintf( stderr, "N2 key : " );
		for ( i=0; i<64; i++ ) fprintf( stderr, "%02X", p[i] );
			fprintf(stderr,"\n");

		unsigned char decrMecmData[mecmRSALen];
		if(!nagra.DecryptECM(&mecmData[4],decrMecmData,0,mecmRSALen,e1,n1,n2))
			return false;
		if(*mecmData==0x39 || (*mecmData==0x20 && (mecmProvId&0xFE00)==0x4800)) {
			unsigned char xor_table[64];
			for(int i=sizeof(xor_table)-1; i>=0; i--) xor_table[i]=63-i;
			nagra.CreateRSAPair(&decrMecmData[24],xor_table,e1,n1);

			// new XOR table for MECM data
			cBNctx ctx;
			cBN x;
			BN_mod_exp(x,e1,nagra.pubExp,n1,ctx);
			int l=sizeof(xor_table)-BN_num_bytes(x);
			memset(xor_table,0,l);
			BN_bn2bin(x,xor_table+l);
			RotateBytes(xor_table,sizeof(xor_table));

			// And finally, new MECM table
			for(int i=39; i<mecmRSALen; i++) decrMecmData[i]^=xor_table[i-39];
			memcpy(&decrMecmData[3],&decrMecmData[39],mecmRSALen-39);
		}
		if(decrMecmData[0]==0x2F && decrMecmData[1]==mecmData[2] && decrMecmData[2]==mecmData[3])
		nagra.WriteTable(decrMecmData+4,decrMecmData[3]*2);
	}

	if(cwOddMecmIndex>=0 && cwOddMecmIndex<0x80) {
		const int d=cwOddMecmIndex*2;
		for(int i=0 ; i<8 ; i++) CW[i+8]^=nagra.mecmTable[(d+i)&0xFF]; // odd
	}
	if(cwEvenMecmIndex>=0 && cwEvenMecmIndex<0x80) {
		const int d=cwEvenMecmIndex*2;
		for(int i=0 ; i<8 ; i++) CW[i]^=nagra.mecmTable[(d+i)&0xFF]; // even
	}

	writeCw();
	return true;
}



bool DVBscam::Nagra2(unsigned char *data)
{
	BIGNUM *m1 = 0;
	cNagra2 nagra;
	unsigned char *p=NULL;
	unsigned char ideaKey[16];
	int i=0;
	int cmdLen=data[4]-5;
	int id=(data[5]*256)+data[6];
	int keyNr=(data[7]&0x10)>>4;

	fprintf( stderr, "\nbuflen : %d\n", sbufLen );
	for ( i=0; i<sbufLen; i++ ) fprintf( stderr, "%02x ", sbuf[i] );
	fprintf( stderr, "\n" );

	if ( !FindKey( 'N', id, keyNr, ideaKey, 16 ) ) {
		fprintf(stderr,"No Nagra key found for :  id : %04X keynr : %02X\n", id, keyNr );
		return false;
	}
	fprintf(stderr,"Trying key N %04X %02X ",id,keyNr);
	for ( i=0; i<16; i++ )
		fprintf( stderr, "%02X", ideaKey[i] );
	fprintf( stderr, "\n" );

	if ( !FindKey( 'R', id, &m1 ) ) {
		fprintf( stderr, "No RSA key found for : id %04X\n", id );
		return false;
	}
	p = (unsigned char *)(m1->d);
	fprintf( stderr, "RSA key : " );
	for ( i=0; i<64; i++ )
		fprintf( stderr, "%02X", p[i] );
	fprintf(stderr,"\n");

	unsigned char buff[256];
	if( !nagra.DecryptECM(data+9,buff,ideaKey,cmdLen,0,m1) ) {
		fprintf( stderr, "nagra2: decrypt of ECM failed (%04X)\n", id );
		return false;
	}

	int l=0, mecmAlgo=0;
	for(int i=10; i<cmdLen-10 && l!=3; ) {
		if((buff[i]==0x10 || buff[i]==0x11) && buff[i+1]==0x09) {
			int s=(~buff[i])&1;
			if (id==0x3101 || id==0x0501 || id==0x0503 || id==0x0511 || id==0x1101 || id==0x1102)
				mecmAlgo=buff[i+2]&0x60;
				/*s^=1; // inverse cw*/
			memcpy(CW+(s<<3),&buff[i+3],8);
			/*if (buff[i+2] & 0x60) {
				fprintf( stderr, "nagra2: CW hashed with $%02X \n", buff[i+2] ); //algo unknown
				return false;
			}*/
			i+=11; l|=(s+1);
		}
		else i++;
	}
	if(mecmAlgo > 0)
	{
		if (!nagra.MECM(buff[15],mecmAlgo,&CW[0])) return false;
	}
	if (id==0x3101 || id==0x0501 || id==0x0503 || id==0x0511 || id==0x1101 || id==0x1102)
		nagra.swapCW(&CW[0]);
	if( l!=3 ) {
		fprintf( stderr, "nagra2: failed (%04X)\n", id );
		return false;
	}
	writeCw();
	return true;
}


bool DVBscam::Nagra3()
{
		fprintf( stderr, "found Nagra3 (card server only)\n");
	return false;	

}


bool DVBscam::Irdeto( unsigned char *source, int length, int id )
{
	int param, extra;
	unsigned char sessionKey[8];
	Skey *k=0;
	unsigned char *p;
	unsigned char save[16];
	int keynr=0;
	int i,j;

	unsigned char *data = 0;
	int date = -1;

	i = 6;
	while (i<length-5) {
		param = source[i++];
		extra = source[i++] & 0x3f;
		switch (param) {
			case 0x78:
				keynr = source[i];
				data = &source[i+2];
				break;
			case 0x00:
			case 0x40:
				date = (source[i]<<8) | source[i+1];
				break;
		}
		i += extra;
		/* look no further if we've got everything we need */
		/* (in case the Dutch Canal + sends more crap to confuse us) */
		if (data != 0 && date != -1) break;
	}

	if (data==0 || date==-1) return false;

	for ( i=0; i<(int)keys.count(); i++ ) {
		k = keys.at(i);
		if ( (k->type=='I' || k->type=='i') && k->id==id && k->keynr==keynr ) {
			fprintf(stderr,"Trying key %c %02X %02X %016llX\n",k->type,k->id,k->keynr,k->key);
			p = (unsigned char *)&k->key;
			for ( j=0; j<8; j++) sessionKey[j] = p[7-j];
			/* save the encrypted data */
			memcpy( save, data, 16 );
			sessionKeyCrypt(&data[0],sessionKey,date);
			sessionKeyCrypt(&data[8],sessionKey,date);
			if (signatureCheck(source,length-5,sessionKey,date,&source[length-5],0)) {
				fprintf(stderr, "Using key %c %02X %02X %016llX\n",k->type,k->id,k->keynr,k->key);
				for (i=0; i<16; i++) CW[i] = data[i];
				writeCw();
				return true;
			}
			/* put back the encrypted data if it didn't work */
			memcpy( data, save, 16 );
		}
	}

	fprintf(stderr,"No Irdeto key found for :  id : %02X keynr : %02X\n", id, keynr );
	return false;
}



bool DVBscam::Seca( unsigned char *source, int length, int id, int keynr )
{
	int param, extra;
	unsigned char signature[8];
	unsigned char kkeys[16];
	int i, j;
	unsigned char *data = 0;

	fprintf( stderr, "\nbuflen : %d\n", sbufLen );
	for ( i=0; i<sbufLen; i++ ) fprintf( stderr, "%02x ", sbuf[i] );
	fprintf( stderr, "\n" );

	if ( !FindKey( 'S', id, keynr, kkeys, 8 ) ) {
		fprintf(stderr,"No Seca key found for :  id : %06x keynr : %02x\n", id, keynr );
		return false;
	}

	for ( i=0; i<8; i++ )
		kkeys[i+8] = kkeys[i];

	fprintf(stderr,"Trying key S %06x %02x ",id,keynr);
	for ( i=0; i<8; i++ )
	{
		fprintf(stderr,"%02X",kkeys[i]);
	}
	fprintf(stderr,"\n");

	memset( signature, 0, 8 );
	for ( i=0; i<length-8; i+=8 ) {
		for ( j=0; j<8 && i+j<length-8; j++ ) signature[j] ^= source[i+j];
		encrypt_seca( kkeys, signature );
	}

	i = 0;
	while (i<length) {
		param = source[i++];
		extra = (param >> 4) & 0x0f;
		switch (extra) {
			case 0x0d:
				extra = 0x10;
				break;
			case 0x0e:
				extra = 0x18;
				break;
			case 0x0f:
				extra = 0x20;
				break;
		}

		switch (param) {
			case 0xd1:
				data = &source[i];
				break;
			case 0x82:
				if ( memcmp( &source[i], signature, 8 ) != 0 ) return false;
				break;
		}

		i += extra;
	}

	if ( data == 0 ) return false;

	decrypt_seca( &kkeys[0], &data[0] );
	decrypt_seca( &kkeys[0], &data[8] );

	fprintf(stderr,"Using key S %06X %02X ",id,keynr);
	for ( i=0; i<8; i++ )
	{
		fprintf(stderr,"%02X",kkeys[i]);
	}
	fprintf(stderr,"\n");

	for (i=0; i<16; i++)
		CW[i] = data[i];
	writeCw();
	return true;
}



bool DVBscam::Viaccess( unsigned char *source, int length, int id )
{
	Skey *k=0;
	int keynr=0;
	unsigned char *table;
	int i;
	unsigned char *p;
	unsigned char key[8], v2key[8];
	unsigned char decoded_word[16];
	unsigned char rx_message[184];
	unsigned char source_copy[500];
	cViaccess cv;

	static unsigned char table0[] = {
	0x4F,0xB4,0xFC,0x9B,0x4A,0x7F,0x44,0xFB,0x05,0xFF,0xBD,0xBB,0x16,0x2D,0x6C,0xC8,
	0xD8,0x96,0xF9,0xFE,0x3F,0xFF,0x36,0x24,0xB6,0xBF,0x49,0xC9,0x2D,0x36,0x5E,0xD0,
	0x1F,0x09,0x7E,0xA9,0x7F,0xFF,0x64,0xB6,0x5B,0x7E,0xF8,0xFC,0x6E,0x3F,0x7F,0xBF,
	0xDD,0x36,0x12,0xE9,0x05,0xFE,0xB4,0x6C,0x6F,0xFE,0x7E,0xC8,0x25,0x90,0x6D,0x90
	};
	static unsigned char table1[] = {
	0x7E,0x6D,0x7E,0x12,0x76,0xFD,0x2F,0xFE,0x6D,0xFE,0xDA,0x3F,0xDA,0x6D,0xBD,0x97,
	0xD0,0x6D,0xD8,0x9F,0x69,0xFD,0xB6,0x37,0xFE,0x7F,0x36,0x92,0xBD,0x52,0x16,0xDF,
	0xFC,0x96,0xFF,0x92,0xFD,0x6D,0x7F,0xB5,0xFB,0x4C,0xB6,0xB7,0x7E,0xD9,0xFE,0x9B,
	0xFD,0xF4,0x6D,0x9B,0xB9,0x36,0xBF,0x7F,0xD2,0x2D,0xDF,0xB7,0xD9,0xFE,0x69,0xBF
	};

	fprintf( stderr, "\n" );
	fprintf( stderr, "buflen : %d\n", sbufLen );
	for ( i=0; i<sbufLen; i++ ) fprintf( stderr, "%02x ", sbuf[i] );
	fprintf( stderr, "\n" );

	int len = length;
	memcpy( source_copy, source, len );

loop:
	source = &sbuf[4];
	memcpy( source, source_copy, len );
	length = len;

	if ( source[0]==0xd2 && source[1]==0x01 && source[2]==0x01 ) {
		source+=3;
		length-=3;
		if ( source[0]!=0x40 ) {
			table = source[0]==0xdf ? table0 : table1;
			if ( source[0]==0xdf ) fprintf( stderr, "%06x xored with table 0\n", id );
			else fprintf( stderr, "%06x xored with table 1\n", id );
			for ( i=0 ; i<length ; i++ ) source[i]^=table[i&63];
		}
	}

	if ( (source[0]==0x90 || source[0]==0x40) && source[1]==0x03 ){
		bool tps=(source[0] == 0x40)?true:false;
		keynr=source[4] & 0x0f;
		source+=5;
		length-=5;
		//fprintf(stderr,"Searching Viaccess key id : %06x keynr : %02x\n", id, keynr );
		for ( i=0; i<(int)keys.count(); i++ ) {
			k = keys.at(i);
			if ( (k->type=='V' || k->type=='v') && k->id==id && k->keynr==keynr ) break;
			else k = 0;
		}
		if ( k ) {
			p = (unsigned char *)&(k->key);
			for (i=0; i<8; i++) key[i] = p[7-i];
			for (i=0; i<length; i++) rx_message[i] = source[i];
			//fprintf(stderr,"Trying key %c %06x %02x %016llx\n",k->type,k->id,k->keynr,k->key);
			if ( k->v2key ) {
				p = (unsigned char *)&(k->v2key);
				for (i=0; i<8; i++) v2key[i] = p[7-i];
				cv.SetV2Mode( v2key );
			}
			i = cv.Decrypt( key, rx_message, length, &decoded_word[0], &decoded_word[8], tps, &naes );
			if ( i ) {
				fprintf(stderr,"Using key %c %06x %02x %016llx\n",k->type,k->id,k->keynr,k->key);
				for (i=0; i<16; i++) CW[i] = decoded_word[i];
				if ( tps && naes!=-1 ) {
					fprintf( stderr, "Using tps.au line %d\n", naes+1 );
					--naes;
				}
				writeCw();
				return true;
			}
			else {
				if ( naes!=-1 )
					goto loop;
				if ( tps && naes==-1 )
					emit needTpsAu( adapter, tuner );
			}
		}
		else fprintf(stderr,"No Viaccess key found for :  id : %06x keynr : %02x\n\n", id, keynr );
	}
	else fprintf(stderr, "Wrong table for %06x - %02x %02x\n\n", id, source[0], source[1] );
	return false;
}



void DVBscam::writeCw()
{
	int i;
	ca_descr_t ca_descr;

	for ( i=0; i<16; i+=4 )
		CW[i+3] = CW[i]+CW[i+1]+CW[i+2];
	for ( i=0; i<16; i++)
		fprintf( stderr, "%02X ", CW[i] );
	fprintf( stderr, "\n" );
	cw = true;

	if ( cafd<=0 )
		return;

	ca_descr.index = 0;
	ca_descr.parity = 0;
	for ( i=0; i<8; i++ )
		ca_descr.cw[i] = CW[i];
  	if ( ioctl( cafd, CA_SET_DESCR, &ca_descr )<0 )
    		perror("CA_SET_DESCR");

	ca_descr.index = 0;
	ca_descr.parity = 1;
	for ( i=0; i<8; i++ )
		ca_descr.cw[i] = CW[i+8];
	if ( ioctl( cafd, CA_SET_DESCR, &ca_descr )<0)
		perror("CA_SET_DESCR");
}



void DVBscam::getFineTune()
{
	QString s;
	int tsid, sid, n;

	s = QDir::homeDirPath()+"/.kaffeine/kaffeine-sc-finetune";
	QFile f( s );
	if ( !f.open(IO_ReadOnly) )
		return;

	QTextStream t( &f );
	while ( !t.eof() ) {
		s = t.readLine();
		if ( !s.startsWith("#") ) {
			if ( sscanf( s.latin1(), "%d %d %d", &tsid, &sid, &n )!=3 )
				continue;
			if ( tsid==tsID && sid==programNumber && n>0 && n<257 ) {
				ntune = n;
				tsbuf = new unsigned char[ntune*64*188];
				break;
			}
		}
	}

	f.close();
}



bool DVBscam::getCachedEcms()
{
	QString s, c;
	char host[128];
	int tsid, sid, pid, id, chid, system, caid, port;
	Ecm *e;

	s = QDir::homeDirPath()+"/.kaffeine/cached.ecm";
	QFile f( s );
	if ( !f.open(IO_ReadOnly) ) return false;

	cEcms.clear();

	QTextStream t( &f );
	while ( !t.eof() ) {
		s = t.readLine();
		memset( host, 0, 128 );
		if ( !s.startsWith("#") ) {
			if ( sscanf( s.latin1(), "%d %d %d %d %d %d %s %d %d", &tsid, &sid, &system, &id, &pid, &chid, host, &port, &caid )!=9 )
				continue;
			e = new Ecm();
			e->system = system;
			e->id = id;
			e->tsid = tsid;
			e->sid = sid;
			e->pid = pid;
			e->chid = chid;
			c = host;
			e->csHost = c;
			e->csCAID = caid;
			e->csPort = port;
			cEcms.append( e );
		}
	}

	f.close();
	return true;
}



void DVBscam::saveCachedEcms()
{
	QString s;
	Ecm *e;
	int i;

	s = QDir::homeDirPath()+"/.kaffeine/cached.ecm";
	QFile f( s );
	if ( !f.open(IO_WriteOnly) ) return;

	QTextStream t( &f );
	t<< "# This file is auto generated\n";
	t<< "# It will be overwritten without warning\n";
	for ( i=0; i<(int)cEcms.count(); i++ ) {
		e = cEcms.at(i);
		t<< s.setNum( e->tsid );
		t<< " ";
		t<< s.setNum( e->sid );
		t<< " ";
		t<< s.setNum( e->system );
		t<< " ";
		t<< s.setNum( e->id );
		t<< " ";
		t<< s.setNum( e->pid );
		t<< " ";
		t<< s.setNum( e->chid );
		t<< " ";
		if ( e->csHost.length()==0 )
			e->csHost = "_";
		t<< e->csHost;
		t<< " ";
		t<< s.setNum( e->csPort );
		t<< " ";
		t<< s.setNum( e->csCAID );
		t<< "\n";
	}

	f.close();
}



bool DVBscam::getKeys()
{
	QString s, c;
	char type;
	unsigned int id, tsid, keynr,provider,keytype,link;
	char key[500];
	Skey *k;

	s = QDir::homeDirPath()+"/.kaffeine/SoftCam.Key";
	QFile f( s );
	if ( !f.open(IO_ReadOnly) )
		return false;

	keys.clear();

	QTextStream t( &f );
	while ( !t.eof() ) {
		s = t.readLine().upper();
		provider=keytype=tsid=link=0;
		if ( !s.startsWith(";") || !s.startsWith("#")) {
			s.remove( QRegExp(";.*") );
			if ( s.contains("use") || s.contains("USE") ) { // LINK
				if ( sscanf( s.latin1(), "%c %x %s %x", &type, &id, key, &keynr) != 4 )
					continue;
				link = 1;
			}
			else if ( s.startsWith("X") ) {
				if ( sscanf( s.latin1(), "%c %x %d %d %s", &type, &id, &tsid, &keynr, key) != 5 )
					continue;
			}
			else if ( s.startsWith("B") ) {
				if ( sscanf( s.latin1(), "%c %d %d %s", &type, &tsid, &keynr, key) != 4 )
					continue;
			}
			else if ( s.startsWith("M1") ) {
				if ( sscanf( s.latin1(), "M1 %x %s", &id, key) != 2 )
					continue;
				type='R'; //RSA
			}
			else if ( s.startsWith("E1") ) {
				if ( sscanf( s.latin1(), "E1 %x %s", &id, key) != 2 )
					continue;
				type='E';
			}
			else if ( s.startsWith("N1") ) {
				if ( sscanf( s.latin1(), "N1 %x %s", &id, key) != 2 )
					continue;
				type='1';
			}
			else if ( s.startsWith("N2") ) {
				if ( sscanf( s.latin1(), "N2 %x %s", &id, key) != 2 )
					continue;
				type='2';
			}
			else if ( s.startsWith("W") ) {
				if ( sscanf( s.latin1(), "%c %x %x %x %x %s", &type, &id, &provider, &keytype, &keynr, key) == 6 ){
					keynr=keynrset(provider,keytype,keynr);
				}
				else if ( sscanf( s.latin1(), "%c %x %x %x %s", &type, &id, &keytype, &keynr, key) == 5 ){
					keynr=keynrset(provider,0xff,keynr);
				}
				else{
					continue;
				}
			}
			else
				if ( sscanf( s.latin1(), "%c %x %x %s", &type, &id, &keynr, key) != 4)
					continue;
			k = new Skey();
			k->type = type;
			k->tsid = tsid;
			k->id = id;
			k->keynr = keynr;
			c = key;
			if ( link==1 ) // LINK
				k->tsid = -1;
			else if ( c.length()==12 )
				k->key = c.toULongLong( 0, 16 );
			else if ( c.length()==16 )
				k->key = c.toULongLong( 0, 16 );
			else if ( c.length()==32 ) {
				k->key = c.left(16).toULongLong( 0, 16 );
				k->v2key = c.right(16).toULongLong( 0, 16 );
			}
			else if ( c.length()==128 ) {
				int i=0,j=0;
				char revkey[128];
				for (i=128-2;i>=0;i-=2) {
					revkey[j++]=key[i];
					revkey[j++]=key[i+1];
				}
				BN_hex2bn(&(k->bkey), revkey);
			}
			keys.append( k );
		}
	}

	f.close();
	return true;
}

#include "dvbscam.moc"
