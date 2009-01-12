// NewCS client

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#include <crypt.h>
#include <byteswap.h>
#include <time.h>

#include <qfile.h>
#include <qdir.h>
#include <qregexp.h>

#include "mgcam/misc.h"
#include "dvbscam.h"

#include "cardclient.h"
#include "cardclient.moc"

#define CON_TIMEOUT 5
#define READ_TIMEOUT 5
#define WRITE_TIMEOUT 5

#define GBOX_TIMEOUT 3



void cTripleDes::SetOddParity(unsigned char *key)
{
  DES_set_odd_parity((DES_cblock *)&key[0]); // set odd parity on both keys
  DES_set_odd_parity((DES_cblock *)&key[8]); //
}

void cTripleDes::ScheduleKey(void)
{
  DES_KEY_SCHED((DES_cblock *)&desKey[0], ks1);
  DES_KEY_SCHED((DES_cblock *)&desKey[8], ks2);
}

void cTripleDes::Expand(unsigned char *expand, const unsigned char *normal)
{
	expand[0] = normal[0] & 0xfe;
	for(int i = 1; i < 7; i++)
		expand[i] = ((normal[i-1] << (8 - i)) | (normal[i] >> i)) & 0xfe;
	expand[7] = normal[6] << 1;
	expand[8] = normal[7] & 0xfe;
	for(int i = 9; i < 15; i++)
		expand[i] = ((normal[i-2] << (16 - i)) | (normal[i-1] >> i-8)) & 0xfe;
	expand[15] = normal[13] << 1;
	SetOddParity(expand);
}

int cTripleDes::PadMessage(unsigned char *data, int len)
{
  DES_cblock padBytes;
  unsigned char noPadBytes;

  noPadBytes = (8 - ((len - 1) % 8)) % 8;
  if(len+noPadBytes+1 >= CWS_NETMSGSIZE-8) {
    fprintf( stderr,"cTripleDes::PadMessage : message overflow in cTripleDes::PadMessage\n");
    return -1;
    }

  srand(time(NULL)); // make sure the random generator is initialized
  DES_random_key((DES_cblock *)padBytes);
  memcpy(data+len,padBytes,noPadBytes); len+=noPadBytes;
  data[len]=XorSum(data+2,len-2);
  return len+1;
}

const unsigned char *cTripleDes::Encrypt(const unsigned char *data, int len, unsigned char *crypt)
{
  DES_cblock ivec;
  DES_random_key((DES_cblock *)ivec);
  memcpy(crypt+len,ivec,sizeof(ivec));
  DES_EDE2_CBC_ENCRYPT(data+2,crypt+2,len-2,ks1,ks2,(DES_cblock *)ivec,DES_ENCRYPT);
  return crypt;
}

void cTripleDes::Decrypt(unsigned char *data, int len)
{
  if((len-2) % 8 || (len-2)<16) {
    fprintf( stderr,"cTripleDes::Decrypt : warning, the encrypted data size mismatch\n");
    return;
    }
  DES_cblock ivec;
  len-=sizeof(ivec); memcpy(ivec, data+len, sizeof(ivec));
  DES_EDE2_CBC_ENCRYPT(data+2,data+2,len-2,ks1,ks2,(DES_cblock *)ivec,DES_DECRYPT);
}



CsSocket::CsSocket()
{
	sockfd = 0;
}



int CsSocket::connectFd()
{
	return sockfd;
}



bool CsSocket::Select( bool forRead, int timeout )
{
	if ( sockfd ) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET( sockfd, &fds );
		struct timeval tv;
		tv.tv_sec=timeout;
		tv.tv_usec=0;
		int r=select( sockfd+1, forRead ? &fds:0, forRead ? 0:&fds, 0, &tv );
		if ( r>0 )
			return true;
		else if ( r<0 ) {
			fprintf(stderr, "CsSocket : select failed: %s\n", strerror(errno) );
			return false;
		}
		else {
			if( timeout>0 )
				fprintf(stderr, "CsSocket : select timed out (%d secs)\n", timeout );
			return false;
		}
	}
	return false;
}



int CsSocket::Read( unsigned char *data, int len, int timeout )
{
	if ( !Select( true, timeout ) )
		return -1;
	int r = read( sockfd, data, len );
	if ( r<0 ) {
		fprintf(stderr, "CsSocket : read failed: %s\n", strerror(errno) );
		stopConnect();
	}

	return r;
}



int CsSocket::Write( const unsigned char *data, int len, int timeout )
{
	if ( !Select( false, timeout ) )
		return -1;
	int r = write( sockfd, data, len );
	if ( r<0 ) {
		fprintf(stderr, "CsSocket : write failed: %s\n", strerror(errno) );
		stopConnect();
	}

	return r;
}



bool CsSocket::startConnect( QString host, int port )
{
	int handle;
	int flags;
	bool connected = false;
	struct hostent *hostaddr;
	struct sockaddr_in socketAddr;

	fprintf( stderr, "CsSocket: connecting to %s %d ...\n", host.ascii(), port );

	if (!(hostaddr = gethostbyname(host.ascii()))) {
		fprintf(stderr, "CsSocket::start : Host lookup of %s failed\n", host.ascii());
		return false;
	}
	if ((handle = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "CsSocket::start : network make connection: couldn't create socket\n");
		return false;
	}
	flags = fcntl( handle, F_GETFL );
    	if ( flags<0) {
    		fprintf(stderr, "CsSocket::start : GETFL failed\n");
    		close(handle);
    		return false;
    	}
    	 if ( fcntl( handle, F_SETFL, flags | O_NONBLOCK )!=0 ) {
    	 	fprintf(stderr, "CsSocket::start : SETFL failed\n");
    		close(handle);
    		return false;
    	}
	socketAddr.sin_family = AF_INET;
	socketAddr.sin_port = htons(port);
	socketAddr.sin_addr.s_addr = ((struct in_addr *)hostaddr->h_addr)->s_addr;
	sockfd = handle;
	if ( connect(handle, (struct sockaddr *)&socketAddr, sizeof(socketAddr))!=0 ) {
		if ( errno==EINPROGRESS ) {
			if ( Select( false, CON_TIMEOUT ) ) {
				int r=-1;
				unsigned int l=sizeof(r);
				if ( getsockopt( handle, SOL_SOCKET, SO_ERROR, &r, &l)==0 ) {
					if(r==0)
						connected=true;
					else fprintf(stderr, "CsSocket::start : connect failed (late): %s\n", strerror(r) );
				}
				else fprintf(stderr, "CsSocket::start : getsockopt failed: %s\n", strerror(errno) );
			}
			else fprintf(stderr, "CsSocket::start : connect timed out\n");
		}
		else fprintf(stderr, "CsSocket::start : connect failed: %s\n", strerror(errno) );
	}
	else
		connected = true;

	if ( !connected ) {
		close(handle);
		sockfd = 0;
		return false;
	}
	return true;
}



void CsSocket::stopConnect()
{
	if ( sockfd ) {
		close( sockfd );
		fprintf(stderr, "CardClient : connection closed.\n");
	}
	sockfd = 0;
}



bool CsSocket::Bind( QString host, int port )
{
	int handle;
	int flags;
	bool connected = false;
	struct hostent *hostaddr;
	struct sockaddr_in socketAddr;

	fprintf( stderr, "CsSocket: binding to %s %d ...\n", host.ascii(), port );

	if (!(hostaddr = gethostbyname(host.ascii()))) {
		fprintf(stderr, "CsSocket::start : Host lookup of %s failed\n", host.ascii());
		return false;
	}
	if ((handle = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "CsSocket::start : network make connection: couldn't create socket\n");
		return false;
	}
	flags = fcntl( handle, F_GETFL );
    	if ( flags<0) {
    		fprintf(stderr, "CsSocket::start : GETFL failed\n");
    		close(handle);
    		return false;
    	}
    	 if ( fcntl( handle, F_SETFL, flags | O_NONBLOCK )!=0 ) {
    	 	fprintf(stderr, "CsSocket::start : SETFL failed\n");
    		close(handle);
    		return false;
    	}
	socketAddr.sin_family = AF_INET;
	socketAddr.sin_port = htons(port);
	socketAddr.sin_addr.s_addr = ((struct in_addr *)hostaddr->h_addr)->s_addr;
	sockfd = handle;
	if ( bind( handle, (struct sockaddr *)&socketAddr, sizeof(socketAddr) )==0 )
		connected=true;
	else
		fprintf(stderr, "CsSocket::start : bind failed: %s\n", strerror(errno) );

	if ( !connected ) {
		close(handle);
		sockfd = 0;
		return false;
	}
	return true;
}



int CsSocket::SendTo( const char *Host, int Port, const unsigned char *data, int len, int timeout )
{
	int r=Select( false, timeout );
	if ( r>0 ) {
		struct sockaddr_in saddr;
		const struct hostent * const hostaddr=gethostbyname(Host);
		if ( !hostaddr ) {
			fprintf( stderr, "CsSocket : name lookup error for %s\n", Host);
			return -1;
		}
		saddr.sin_family=AF_INET;
		saddr.sin_port=htons(Port);
		saddr.sin_addr.s_addr=((struct in_addr *)hostaddr->h_addr)->s_addr;
		r = sendto( sockfd, data, len, 0, (struct sockaddr *)&saddr, sizeof(saddr) );
		if ( r<0 )
			fprintf( stderr, "CsSocket : sendto %d.%d.%d.%d:%d failed: %s\n", (saddr.sin_addr.s_addr>>0)&0xff, (saddr.sin_addr.s_addr>>8)&0xff, (saddr.sin_addr.s_addr>>16)&0xff, (saddr.sin_addr.s_addr>>24)&0xff, Port, strerror(errno));
		else if ( r>0 )
			fprintf( stderr, "CsSocket : sendto %d.%d.%d.%d:%d\n", (saddr.sin_addr.s_addr>>0)&0xff, (saddr.sin_addr.s_addr>>8)&0xff, (saddr.sin_addr.s_addr>>16)&0xff, (saddr.sin_addr.s_addr>>24)&0xff, Port );
		else r=-1;
	}
	return r;
}



void CsSocket::Flush()
{
	int i;
	if ( sockfd ) {
		unsigned char buff[512];
		while ( read( sockfd, buff, sizeof(buff) )>0 )
			++i;
	}
}



EcmCache::EcmCache( int pn, int tp )
{
	cw = false;
	sid = pn;
	tsid = tp;
	memset( ecm, 0, 500 );
}



CardClient::CardClient( QString host, QString user, QString pwd, int p_ort, QString ckey, QString caid, QString prov )
{
	haveToDie = false;
	setCAID( caid );
	hostname = host;
	port = p_ort;
	username = user;
	password = pwd;
	memset( configKey, 0, 14 );
	setCkey( ckey );
	setProv( prov );

	ecmCache.setAutoDelete( true );

	connect( &connectionTimer, SIGNAL( timeout() ), this, SLOT( connectionTimeout() ) );
}



bool CardClient::canHandle( int caid, int prov )
{
	if ( caid==caID )
		return canHandleProv( prov );
	return false;
}



bool CardClient::canHandleProv( int prov )
{
	if ( prov ) {
		if ( provId.contains(prov) || provId.contains(0) )
			return true;
		else
			 return false;
	}
	return true;
}



void CardClient::setCAID( QString caid )
{
	bool ok;

	caID = caid.toInt( &ok, 16 );
}



QString CardClient::getCAID()
{
	QString s =  QString().setNum( caID, 16);
	return s.upper();
}



void CardClient::setHost( QString h )
{
	hostname = h;
}



void CardClient::setUser( QString u )
{
	username = u;
}



void CardClient::setPass( QString p )
{
	password = p;
}



void CardClient::setPort( int p )
{
	port = p;
}



void CardClient::setProv( QString prov )
{
	bool ok;
	int pos;
	QString s = prov;

	provId.clear();
	s = s.remove(" ");
	pos = s.find(",");
	while ( pos!=-1 ) {
		provId.append( s.left( pos ).toInt( &ok, 16 ) );
		s = s.right( s.length()-pos-1 );
		pos = s.find(",");
	}
	provId.append( s.toInt( &ok, 16 ) );
}



QString CardClient::getProv()
{
	QString s="";
	int i;

	for ( i=0; i<(int)provId.count(); i++ ) {
		if ( s!="" )
			s+=",";
		s+= QString().setNum( provId[ i ], 16 );
	}
	return s;
}



void CardClient::setCkey( QString key )
{
	int i;
	QString s = key;
	s = s.remove(" ");
	for ( i=0; i<14; i++ )
		configKey[i] = s.mid(2*i,2).toUShort(0,16);
}



QString CardClient::getCkey()
{
	int i;
	QString s="";
	for ( i=0; i<14; i++ )
		s+= QString().sprintf( "%02X", configKey[i] );
	return s.upper();
}



void CardClient::mustDie()
{
	bool unused=true;

	mutex.lock();
	haveToDie = true;
	if ( ecmCache.count() )
		unused = false;
	mutex.unlock();

	if ( unused ) {
		emit killMe( this );
	}
}




void CardClient::registerProgram( int sid, int tsid )
{
	int i;
	EcmCache *e;

	for ( i=0; i<(int)ecmCache.count(); i++ ) {
		e = ecmCache.at(i);
		if ( sid==e->sid && tsid==e->tsid )
			return;
	}
	ecmCache.append( new EcmCache( sid, tsid ) );
}



void CardClient::unregisterProgram( int sid, int tsid )
{
	int i;
	bool unused=true;
	EcmCache *e;

	mutex.lock();
	for ( i=0; i<(int)ecmCache.count(); i++ ) {
		e = ecmCache.at(i);
		if ( sid==e->sid && tsid==e->tsid ) {
			ecmCache.remove( e );
			break;
		}
	}
	if ( ecmCache.count() )
		unused = false;
	mutex.unlock();
	if ( unused && haveToDie )
		emit killMe( this );
}



bool CardClient::isInCache( int sid, int tsid, unsigned char *ECM, int len, bool &cw, unsigned char *CW )
{
	int i, j;
	EcmCache *e;

	for ( i=0; i<(int)ecmCache.count(); i++ ) {
		e = ecmCache.at(i);
		if ( sid==e->sid && tsid==e->tsid ) {
			for ( j=0; j<len; j++ ) {
				if ( ECM[j]!=e->ecm[j] )
					return false;
			}
			cw = e->cw;
			if ( cw )
				memcpy( CW, e->CW, 16 );
			return true;
		}
	}
	registerProgram( sid, tsid );
	return false;
}



void CardClient::setCache( int sid, int tsid, unsigned char *ECM, int len, bool cw, unsigned char *CW )
{
	int i;
	EcmCache *e;

	for ( i=0; i<(int)ecmCache.count(); i++ ) {
		e = ecmCache.at(i);
		if ( sid==e->sid && tsid==e->tsid ) {
			memcpy( e->ecm, ECM, len );
			e->cw = cw;
			if ( cw )
				memcpy( e->CW, CW, 16 );
			return ;
		}
	}
}



void CardClient::connectionTimeout()
{
	mutex.lock();
	connectionTimer.stop();
	stopConnect();
	mutex.unlock();
}



CardClient::~CardClient()
{
	fprintf( stderr, "Card Client destructor\n" );
	stopConnect();
	ecmCache.clear();
}



NewCSClient::NewCSClient( QString host, QString user, QString pwd, int p_ort, QString ckey, QString caid, QString prov )
	: CardClient( host, user, pwd, p_ort, ckey, caid, prov )
{
	cdLen = 8;
	netMsgId = 0;
}



void NewCSClient::InitCustomData(struct CustomData *cd, const unsigned short PrgId, const unsigned char *data)
{
	if(cd) {
		cd->sid = bswap_16(PrgId);
		if (data)
			memcpy(cd->data, data, sizeof(cd->data));
        	else
        		memset(cd->data, 0, sizeof(cd->data));
        }
}



void NewCSClient::prepareLoginKey(unsigned char *deskey, const unsigned char *rkey, const unsigned char *ckey)
{
	unsigned char tmpkey[14];
	for (int i=0; i<(int)sizeof(tmpkey); i++)
		tmpkey[i]=rkey[i]^ckey[i];
	Expand(deskey, tmpkey);
}



int NewCSClient::CmdReceive( comm_type_t commType )
{
	unsigned char buffer[CWS_NETMSGSIZE];
	if ( ReceiveMessage( buffer, false, 0, commType )!=3 )
		return -1;
	return buffer[0];
}



bool NewCSClient::CmdSend( net_msg_type_t cmd, comm_type_t commType )
{
	unsigned char buffer[3];
	buffer[0] = cmd;
	buffer[1] = buffer[2] = 0;
	return SendMessage( buffer,sizeof(buffer),false,0,commType);
}



int NewCSClient::ReceiveMessage( unsigned char *data, bool UseMsgId, struct CustomData *cd, comm_type_t commType )
{
	unsigned char netbuf[CWS_NETMSGSIZE];
	memset( netbuf, 0, CWS_NETMSGSIZE );
	int len=-1;

	len=Read( netbuf, 2, READ_TIMEOUT );
	if ( len<0  )
		fprintf( stderr,"NewCSClient::ReceiveMessage : can't read\n");
	if ( len!=2 ) {
		fprintf( stderr,"NewCSClient::ReceiveMessage : bad length %d != 2 on message length read\n",len);
		return 0;
	}
	const int mlen=WORD(netbuf,0,0xFFFF);
	if ( mlen>CWS_NETMSGSIZE-2 ) {
		fprintf( stderr,"NewCSClient::ReceiveMessage : error: buffer overflow\n");
		return 0;
	}
	len=Read( netbuf+2, mlen, READ_TIMEOUT );
	if ( len!=mlen ) {
		fprintf( stderr,"NewCSClient::ReceiveMessage : bad length %d != %d on message read\n",len,mlen);
		return 0;
	}
	len+=2;
	int i;
	fprintf( stderr,"\n");
	for ( i=0; i<len; i++) fprintf( stderr," %02x", netbuf[i] );
	fprintf( stderr,"\n");
	cTripleDes::Decrypt( netbuf, len );
	len-=sizeof(DES_cblock);
	if ( XorSum( netbuf+2, len-2 ) ) {
		fprintf( stderr,"NewCSClient::ReceiveMessage : checksum error\n");
		return 0;
	}

	int returnLen=WORD( netbuf, 5+cdLen, 0x0FFF )+3;
	if (cd) memcpy( cd, &netbuf[4], cdLen );
	if ( UseMsgId ) {
		switch( commType ) {
		case COMMTYPE_SERVER:
			netMsgId=WORD( netbuf, 2, 0xFFFF );
			break;
		case COMMTYPE_CLIENT:
			if ( netMsgId!=WORD( netbuf, 2, 0xFFFF )) {
				fprintf( stderr,"NewCSClient::ReceiveMessage : bad msgid %04x != %04x \n",netMsgId,WORD(netbuf,2,0xFFFF));
				return -1;
			}
			 break;
		default:
			fprintf( stderr,"NewCSClient::ReceiveMessage : unknown commType %x\n",commType);
			return -1;
		}
	}
	memcpy( data, netbuf+4+cdLen, returnLen );
	fprintf( stderr,"\n");
	for ( i=0; i<returnLen; i++) fprintf( stderr," %02x", data[i] );
	fprintf( stderr,"\n");
	fprintf( stderr, "NewCSClient::ReceiveMessage : Received message length: %d\n", returnLen );
	return returnLen;
}



bool NewCSClient::SendMessage( const unsigned char *data, int len, bool UseMsgId, const struct CustomData *cd, comm_type_t commType )
{
	int i;

	if ( len<3 || len+cdLen+4>CWS_NETMSGSIZE ) {
		fprintf( stderr,"NewCSClient::SendMessage : bad message size %d in SendMessage\n",len);
		return false;
	}
	unsigned char netbuf[CWS_NETMSGSIZE];
	memset(netbuf,0,CWS_NETMSGSIZE);
	memset(&netbuf[2],0,cdLen+2);
	memcpy(&netbuf[cdLen+4],data,len);
	netbuf[cdLen+4+1]=(data[1]&0xf0)|(((len-3)>>8)&0x0f);
	netbuf[cdLen+4+2]=(len-3)&0xff;
	len+=4;
	if (cd)
		memcpy(&netbuf[4],cd,cdLen);
	len+=cdLen;

	//NewCS Client detection : 0x5644 = VDR-SC
	// CL_KAFFEINE 0x6b61
	if ( data[0]==MSG_CLIENT_2_SERVER_LOGIN ) {
		netbuf[4]=0x6B;
		netbuf[5]=0x61;
	}

	if ( UseMsgId ) {
		if ( commType==COMMTYPE_CLIENT )
			netMsgId++;
		netbuf[2]=netMsgId>>8;
		netbuf[3]=netMsgId&0xff;
	}

	fprintf( stderr,"\n");
	for ( i=0; i<len; i++) fprintf( stderr," %02x", netbuf[i] );
	fprintf( stderr,"\n\n");

	if ( (len=cTripleDes::PadMessage(netbuf,len))<0 ) {
		fprintf( stderr,"NewCSClient::SendMessage : PadMessage failed\n");
		return false;
	}
	if((data=cTripleDes::Encrypt(netbuf,len,netbuf))==0) {
		fprintf( stderr,"NewCSClient::SendMessage : Encrypt failed\n");
		return false;
	}
	len+=sizeof(DES_cblock);
	netbuf[0]=(len-2)>>8;
	netbuf[1]=(len-2)&0xff;

	for ( i=0; i<len; i++) fprintf( stderr," %02x", netbuf[i] );
	fprintf( stderr,"\n\n");
	if ( (i=Write( netbuf, len, WRITE_TIMEOUT ))<len ) {
		fprintf( stderr, "NewCSClient::SendMessage : write failed - message length %d, sent %d\n", len, i );
		return false;
	}
	else
		fprintf( stderr, "NewCSClient::SendMessage : Sent message length: %d\n", i );
	return true;;
}



bool NewCSClient::login()
{
	stopConnect();
	if ( !startConnect( hostname, port ) )
		return false;
	fprintf(stderr, "NewCSClient: connected\n");

	netMsgId = 0;

	unsigned char randData[14];
	if ( Read( randData, sizeof(randData), READ_TIMEOUT )!=14 ) {
		fprintf( stderr, "NewCSClient::login : no connect answer from %s:%d\n", hostname.ascii(), port );
    		stopConnect();
    		return false;
    	}
    	fprintf(stderr, "NewCSClient::login : rand data received\n");

	char *crPasswd=crypt(password.ascii(),"$1$abcdefgh$");
	unsigned char buffer[CWS_NETMSGSIZE];
	const int userLen=username.length()+1;
	const int passLen=strlen(crPasswd)+1;

	// prepare the initial login message
	buffer[0] = MSG_CLIENT_2_SERVER_LOGIN;
	buffer[1] = 0;
	buffer[2] = userLen+passLen;
	memcpy(&buffer[3],username.ascii(),userLen);
	memcpy(&buffer[3]+userLen,crPasswd,passLen);

	// XOR configKey with randData and expand the 14 byte result -> 16 byte
	prepareLoginKey(desKey,randData,configKey);
	cTripleDes::ScheduleKey();

	if ( !SendMessage(buffer,buffer[2]+3,true) || sleep(3) || CmdReceive()!=MSG_CLIENT_2_SERVER_LOGIN_ACK) {
		fprintf( stderr,"NewCSClient::login : failed to login to cardserver for username %s\n", username.ascii() );
		stopConnect();
		return false;
	}

	// create the session key (for usage later)
	unsigned char tmpkey[14];
	memcpy(tmpkey, configKey, sizeof(tmpkey));
	const int passStrLen=strlen(crPasswd);
	for ( int i=0; i<passStrLen; ++i )
		tmpkey[i%14]^=crPasswd[i];

	cTripleDes::Expand(desKey,tmpkey); // expand 14 byte key -> 16 byte
	cTripleDes::ScheduleKey();

	if ( !CmdSend( MSG_CARD_DATA_REQ ) || (ReceiveMessage( buffer,false )<=0) ) {
		fprintf( stderr, "NewCSClient::login : failed to receive card data\n" );
		stopConnect();
		return false;
	}
	if ( buffer[0] == MSG_CARD_DATA ) {
		caID=(buffer[4]<<8)+buffer[5];
		fprintf( stderr, "NewCSClient::login : CA_ID: %X\n", caID );
	}
	else {
		fprintf( stderr, "NewCSClient::login : No card data\n" );
		stopConnect();
		return false;
	}
	return true;
}



bool NewCSClient::processECM( unsigned char *ECM, int len, unsigned char *cw, Ecm *e, bool& )
{
	bool cacheHasCw;

	if ( !canHandleProv( e->id ) ) {
		fprintf( stderr, "NewCSClient::processECM : do not handle prov %X\n", e->id );
		return false;
	}

	mutex.lock();
	cacheHasCw=false;
	if ( isInCache( e->sid, e->tsid, ECM, len, cacheHasCw, cw ) ) {
		fprintf( stderr, "NewCSClient::processECM : cached ecm %s\n", (cacheHasCw==true)?"decoded":"failed" );
		mutex.unlock();
		return cacheHasCw;
	}
	struct CustomData cd;
	unsigned char buffer[CWS_NETMSGSIZE];
	int serviceID = e->sid;

	if ( !connectFd() && !login() ) {
		mutex.unlock();
		return false;
	}
	connectionTimer.start( CONNECTIONTIMEOUT, true );
	InitCustomData( &cd, serviceID, 0 );
	if ( !SendMessage( ECM, len, true, &cd ) ) {
		fprintf( stderr, "NewCSClient::processECM : failed sending ecm\n" );
		mutex.unlock();
		return false;
	}
	switch( ReceiveMessage( buffer, true ) ) {
		case 19:
			fprintf( stderr, "NewCSClient::processECM : ecm decoded\n" );
			if ( !CheckNull( buffer+3, 8 ) )
				memcpy( cw, buffer+3, 8 );
			if ( !CheckNull( buffer+11, 8 ) )
				memcpy( cw+8, buffer+11, 8 );
			setCache( e->sid, e->tsid, ECM, len, true, cw );
			mutex.unlock();
			return true;
		case 3:
			fprintf( stderr, "NewCSClient::processECM : ecm decoding failed\n");
			setCache( e->sid, e->tsid, ECM, len, false, 0 );
			break;
		default:
			fprintf( stderr, "NewCSClient::processECM : unexpected error\n");
			stopConnect();
			break;
	}
	mutex.unlock();
	return false;
}



GboxClient::GboxClient( QString, QString, QString, int, QString, QString, QString )
	: CardClient( "127.0.0.1", "gbox_indirect", "gbox_indirect", 8003, "00", "0", "0" )
{
}



bool GboxClient::login()
{
	stopConnect();
	if ( !Bind( hostname, port ) )
		return false;
	return true;
}



int GboxClient::GetMsg( int cmd, unsigned char *buff, int len )
{
	int n;
	do {
		n=Read( buff, len, GBOX_TIMEOUT );
		if(n<=0) {
			if(n==0)
				fprintf( stderr, "GboxClient : timeout on GetMsg.\n" );
			break;
		}
	} while ( buff[0]!=cmd );
	return n;
}



bool GboxClient::haveShare( Ecm *e )
{
	QString s, c;
	bool ret = false;
	unsigned int ecp;

	//if ( !e->id )
	//	return true;

	QFile f( QDir::homeDirPath()+"/.kaffeine/gbox-share-info" );
	if ( !f.open(IO_ReadOnly) )
		return true;

	ecp = (e->system<<16) | e->id;
	c = QString().sprintf( "%08X", ecp ).upper();

	QTextStream t( &f );
	while ( !t.eof() ) {
		s = t.readLine();
		if ( s.startsWith("#") )
			continue;
		s.remove( " " );
		if ( s.upper()==c ) {
			ret = true;
			break;
		}
	}

	f.close();
	if ( !ret )
		fprintf(stderr,"GboxClient: No card sharing %s\n", c.ascii() );
	return ret;
}



bool GboxClient::sameCW( unsigned char *o, unsigned char *n )
{
	int i;

	for ( i=0; i<8; i++ ) {
		if ( o[i]!=n[i] )
			return false;
	}
	return true;
}



bool GboxClient::processECM( unsigned char *ECM, int len, unsigned char *cw, Ecm *e, bool &hack )
{
	bool cacheHasCw;

	if ( !haveShare(e) )
		return false;

	QMutexLocker locker( &mutex );
	cacheHasCw=false;
	if ( isInCache( e->sid, e->tsid, ECM, len, cacheHasCw, cw ) ) {
		fprintf( stderr, "GboxClient::processECM : cached ecm %s\n", (cacheHasCw==true)?"decoded":"failed" );
		return cacheHasCw;
	}

	if ( !connectFd() && !login() ) {
		return false;
	}
  	Flush();

	int caid=e->system;
	// FIX N*S Issue
	if ( caid==0x0960 )
		caid = 0x0961;
	int pid =e->pid;
	unsigned char buff[512];

	unsigned char buffer[8];
	unsigned char fakepmt[] = { 0x87, 0x02, 0xb0, 0xf6, 0x39, 0x09, 0xc3, 0x00, 0x00, 0xf7, 0x71, 0xf0, 0x16,
	0x09, 0x0f, 0x05, 0x00, 0xf7, 0xcc, 0x10, 0x01, 0x00, 0x13, 0x01, 0x20, 0x14, 0x03, 0x02, 0x29, 0x00, 0x0e,
	0x03, 0xc2, 0x25, 0x38, 0x02, 0xf7, 0x71, 0xf0, 0x0b, 0x0e, 0x03, 0xc0, 0x36, 0xe1, 0x06, 0x01, 0x04, 0x11,
	0x01, 0xff, 0x03, 0xf7, 0x7b, 0xf0, 0x05, 0x0e, 0x03, 0xc0, 0x36, 0xe1, 0x06, 0xf7, 0x99, 0xf0, 0x28, 0x0e, 0x03,
	0xc0, 0x36, 0xe1, 0x45, 0x1a, 0x01, 0x18, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf3,
	0xf4, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd3, 0xd4, 0x56, 0x05, 0x65, 0x6e, 0x67,
	0x09, 0x00, 0x06, 0xf7, 0x9a, 0xf0, 0x0f, 0x0e, 0x03, 0xc0, 0x36, 0xe1, 0x59, 0x08, 0x68, 0x65, 0x62, 0x10,
	0x00, 0x02, 0x00, 0x02, 0x06, 0xf7, 0x9b, 0xf0, 0x0f, 0x0e, 0x03, 0xc0, 0x36, 0xe1, 0x59, 0x08, 0x63, 0x7a,
	0x65, 0x10, 0x00, 0x02, 0x00, 0x02, 0x06, 0xf7, 0x9c, 0xf0, 0x0f, 0x0e, 0x03, 0xc0, 0x36, 0xe1, 0x59, 0x08,
	0x70, 0x6f, 0x6c, 0x10, 0x00, 0x02, 0x00, 0x02, 0x06, 0xf7, 0x9d, 0xf0, 0x0f, 0x0e, 0x03, 0xc0, 0x36, 0xe1,
	0x59, 0x08, 0x68, 0x75, 0x6e, 0x10, 0x00, 0x02, 0x00, 0x02, 0x06, 0xf7, 0x9e, 0xf0, 0x0f, 0x0e, 0x03, 0xc0,
	0x36, 0xe1, 0x59, 0x08, 0x72, 0x75, 0x6d, 0x10, 0x00, 0x02, 0x00, 0x02, 0x06, 0xf7, 0x9f, 0xf0, 0x0f, 0x0e,
	0x03, 0xc0, 0x36, 0xe1, 0x59, 0x08, 0x69, 0x74, 0x61, 0x10, 0x00, 0x02, 0x00, 0x02, 0x06, 0xf7, 0xa0, 0xf0,
	0x0f, 0x0e, 0x03, 0xc0, 0x36, 0xe1, 0x59, 0x08, 0x73, 0x63, 0x63, 0x10, 0x00, 0x02, 0x00, 0x02, 0x5c, 0x16,
	0x7a, 0x9a };

	buffer[0]= ((caid >> 8) & 0xFF);
	buffer[1]= (caid & 0xFF);
	buffer[2]= ((pid >> 8) & 0xFF);
	buffer[3]= (pid & 0xFF);

	buffer[4]= ((e->id >> 16 ) &0xFF);
	buffer[5]= ((e->id >> 8) & 0xFF);
	buffer[6]= (e->id & 0xFF);

	memcpy(&fakepmt[15], &buffer[0], 4);

	fakepmt[4] = ((e->sid>>8) & 0xFF);
	fakepmt[5] = (e->sid & 0xFF);

	if ( e->system == 0x0500 )
		memcpy(&fakepmt[27], &buffer[4], 3);
	else if ( e->system == 0x0100 )
		memcpy(&fakepmt[19], &buffer[5], 2);

	if ( SendTo( "127.0.0.1", 8004, fakepmt, sizeof(fakepmt), GBOX_TIMEOUT )==-1 ) {
		fprintf( stderr, "GboxClient : failed to send PMT data. GBOX running?\n" );
		return false;
	}

	int n;
	if ( (n=GetMsg(0x8a,buff,sizeof(buff)))<=0 ) {
		fprintf( stderr, "GboxClient : failed to get ECM port. GBOX unable to decode or not running.\n" );
		return false;
	}
	int pidnum=-1;
	if ( n>=2 ) {
		for ( int i=0 ; i<buff[1]; i++ ) {
			if ( WORD(buff,2+i*2,0x1FFF)==pid ) {
				pidnum=i;
				break;
			}
		}
	}
	if ( pidnum<0 ) {
		fprintf( stderr, "GboxClient : GBOX is unable to decode for CAID %04X/PID %04X\n",caid,pid );
		return false;
	}

	n=len;
	if ( n>=256 ) {
		fprintf( stderr, "GboxClient : ECM section too long %d > 255\n",n );
		return false;
	}
	buff[0]=0x88;
	buff[1]=(pid>>8)&0x1F;
	buff[2]=pid & 0xFF;
	buff[3]=n;
	memcpy( &buff[4], ECM, n );
	n+=4;
	if( SendTo( "127.0.0.1", 8005+pidnum, buff, n, GBOX_TIMEOUT )==-1 ) {
		fprintf( stderr, "GboxClient : failed to send ECM data. GBOX running?\n" );
		return false;
	}

	if ( GetMsg( 0x89, buff, sizeof(buff) )<=0 ) {
		fprintf( stderr, "GboxClient : failed to get CW. GBOX unable to decode or not running.\n" );
		return false;
	}
	if ( n<17 ) {
		fprintf( stderr, "GboxClient : bad CW answer from GBOX.?\n" );
		return false;
	}
	if ( !hack ) {
		if ( !CheckNull( buff+1, 8 ) )
			memcpy( cw, buff+1, 8 );
		if ( !CheckNull( buff+9, 8 ) )
			memcpy( cw+8, buff+9, 8 );
		hack = true;
	}
	else {
		if ( !sameCW( buff+9, cw+8 ) && !sameCW( buff+1, cw ) ) {
			if ( ECM[0]==0x80 ) {
				memcpy( cw, buff+1, 8 );
				if ( !sameCW( buff+9, cw+8 ) )
					hack = false;
			}
			else {
				memcpy( cw+8, buff+9, 8 );
				if ( !sameCW( buff+1, cw ) )
					hack = false;
			}
		}
		else {
			if ( !CheckNull( buff+1, 8 ) )
				memcpy( cw, buff+1, 8 );
			if ( !CheckNull( buff+9, 8 ) )
				memcpy( cw+8, buff+9, 8 );
			hack = true;
		}
	}
	fprintf( stderr, "GboxClient : ecm decoded.\n" );
	return true;
}



#define LIST_MORE 0x00
// CA application should append a 'MORE' CAPMT object the list and start receiving the next object
#define LIST_FIRST 0x01
// CA application should clear the list when a 'FIRST' CAPMT object is received, and start receiving the next object
#define LIST_LAST 0x02
// CA application should append a 'LAST' CAPMT object to the list, and start working with the list
#define LIST_ONLY 0x03
// CA application should clear the list when an 'ONLY' CAPMT object is received, and start working with the object
#define LIST_ADD 0x04
// CA application should append an 'ADD' CAPMT object to the current list, and start working with the updated list
#define LIST_UPDATE 0x05
// CA application should replace an entry in the list with an 'UPDATE' CAPMT object, and start working with the updated list
#define CMD_OK_DESCRAMBLING 0x01
// CA application should start descrambling the service in this CAPMT object, as soon as the list of CAPMT objects is complete



CCcamClient::CCcamClient( QString, QString, QString pwd, int p_ort, QString ckey, QString caid, QString prov ) :  CardClient( "127.0.0.1", "ccam_indirect", "ccam_indirect", 9000, "00", "0", "0" )
{
	cwccam_fd=-1;
	pmtversion=0;
	ccam_fd = -1;
}



CCcamClient::~CCcamClient()
{
	stopPortListener();
	if ( cwccam_fd!=-1 )
		close( cwccam_fd );
}



bool CCcamClient::haveShare( Ecm *e )
{
	QString s, c, p;
	bool ret = false;
	char caid[64];
	char provid[64];

	QFile f( QDir::homeDirPath()+"/.kaffeine/ccam-share-filter" );
	if ( !f.open(IO_ReadOnly) )
		return true;

	QTextStream t( &f );
	while ( !t.eof() ) {
		s = t.readLine();
		if ( s.startsWith("#") )
			continue;
		if ( sscanf( s.latin1(), "%s %s", caid, provid) != 2 )
			continue;
		c = caid;
		p = provid;
		if ( (e->system==c.toInt(0,16)) && (p=="*" || (e->id==p.toInt(0,16))) ) {
			ret = true;
			break;
		}
	}

	f.close();
	if ( !ret )
		fprintf(stderr,"CCcamClient: CAID=%04X ProvID=%04X filtered by ccam-share-filter\n", e->system, e->id );
	return ret;
}



bool CCcamClient::login()
{
	int rc;
	int so =0;
	sockaddr_un serv_addr_un;
	char camdsock[256];
	int res;

	struct sockaddr_in servAddr;
	fflush(NULL);
	close(ccam_fd);
	sprintf(camdsock,"/tmp/camd.socket");
	fprintf( stderr, "CCcamClient: socket = %s\n",camdsock);
	ccam_fd=socket(AF_LOCAL, SOCK_STREAM, 0);
	bzero(&serv_addr_un, sizeof(serv_addr_un));
	serv_addr_un.sun_family = AF_LOCAL;
	strcpy(serv_addr_un.sun_path, camdsock);
	res=::connect(ccam_fd, (const sockaddr*)&serv_addr_un, sizeof(serv_addr_un));
	if (res !=0) {
		fprintf( stderr, "CCcamClient: Couldnt open camd.socket..... errno = %d\n",errno);
		close(ccam_fd);
		ccam_fd = -1;
		return false;
	}
	fprintf( stderr, "CCcamClient: Opened camd.socket..... ccamd_fd  = %d\n",ccam_fd );
	if (cwccam_fd!=-1)
		return true;
	fprintf( stderr, "CCcamClient: logging in\n");
	so=socket(AF_INET, SOCK_DGRAM, 0);
	if(so<0) {
		close(so);
		fprintf( stderr, "CCcamClient: not logged in\n");
		return false;
	}
	bzero(&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servAddr.sin_port = htons(port);
	rc = bind (so, (struct sockaddr *) &servAddr,sizeof(servAddr));
	if(rc<0) {
		close(so);
		fprintf( stderr, "CCcamClient: not logged in\n");
		return false;
	}
	cwccam_fd =so;
	fprintf( stderr, "CCcamClient: logged in\n");

	return true;
}



bool CCcamClient::processECM( unsigned char *ECM, int len, unsigned char *cw, Ecm *e, bool &hack )
{
	if ( !haveShare( e ) )
		return false;

	QMutexLocker locker( &mutex );

	unsigned char capmt[4096];
	fprintf( stderr, "CCcamClient: Processing ECM....\n" );
	int pos;

	memcpy(capmt,"\x9f\x80\x32\x82\x00\x00", 6);
	capmt[6]=LIST_ONLY;
	capmt[7]=(e->sid>>8) & 0xff; // sid
	capmt[8]=e->sid & 0xff; // sid
	capmt[9]=pmtversion; //reserved - version - current/next
	pmtversion++;
	pmtversion%=32;

	if ( e->descriptor ) {
		capmt[12] = CMD_OK_DESCRAMBLING;
		unsigned short plen = e->descLength+1;
		capmt[10]= (plen>>8) & 0xff;
		capmt[11]= plen & 0xff;
		fprintf( stderr, "Descriptor: len =%d, caid=%d, pid=%d, sid=%d\n", e->descLength, e->system, e->pid, e->sid );
		memcpy( &capmt[13], e->descriptor, e->descLength );
		pos = 13+e->descLength;
	}
	else {
		fprintf( stderr, "NO DESCRIPTOR\n");
		return false;
	}

	capmt[pos++] = 0x02; // stream type
	capmt[pos++]= 0x00; capmt[pos++]= 0x64; // es_pid
	capmt[pos++]= 0x00; capmt[pos++]= 0x00; // es_info_len

	capmt[4] = ((pos-7)>>8) & 0xff;
	capmt[5] = (pos-7) & 0xff;

	if ( !login() )
		return false;
	fprintf( stderr, "CCcamClient: sending capmts\n");
	if ( !Writecapmt( capmt ) )
		return false;
	startPortListener();
	int u=0;
	while ( (newcw==0) && (u++<50) )
		usleep(100000);			 // give the card a chance to decode it...
	stopPortListener();
	close( ccam_fd );
	ccam_fd = -1;
	if ( newcw==0 ) {
		fprintf( stderr, "CCcamClient: FAILED ECM !!!!!!!!!!!!!!!!!!\n" );
		return false;
	}
	memcpy( cw,savedcw,16 );
	newcw=0;
	fprintf( stderr, "CCcamClient: GOT CW !!!!!!!!!!!!!!!!!!\n" );
	return true;
}



bool CCcamClient::Writecapmt( unsigned char *pmt )
{
	int len;
	int list_management ;
	list_management = LIST_ONLY;
	pmt[6] = list_management;
	len = pmt[4] << 8;
	len |= pmt[5];
	len += 6;
	fprintf( stderr, "CCcamClient: Writing capmt  ==============================\n" );
	int r = write( ccam_fd, pmt,len );
	if (r != len) {
		fprintf( stderr, "CCcamClient: CCcam probably has crashed or been killed...\n");
		close(ccam_fd);
		ccam_fd=-1;
		return false;
	}
	return true;
}



void CCcamClient::startPortListener()
{
	fprintf( stderr, "CCcamClient: starting UDP listener\n");
	isRunning = true;
	start();
}



void CCcamClient::stopPortListener()
{
	isRunning = false;
	wait();
}



void CCcamClient::run()
{
	int n;
	unsigned char cw[18];
	struct sockaddr cliAddr;
	socklen_t cliLen;
	cliLen = sizeof(cliAddr);
	struct pollfd pfd[1];
	pfd[0].fd = cwccam_fd;
	pfd[0].events = POLLIN;

	while ( isRunning ) {
		n=0;
		if ( poll( pfd, 1, 100 ) ) {
			fprintf(stderr,"CCcamClient: reading 127.0.0.1:9000\n");
			n = ::recvfrom(cwccam_fd, cw, 18, 0, (struct sockaddr *) &cliAddr, &cliLen);
		}
		if ( n==18 ) {
			memcpy( savedcw, cw+2, 16 );
			newcw =1;
		}
	}
}
