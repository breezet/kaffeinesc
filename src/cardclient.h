#ifndef CARDCLIENT_H
#define CARDCLIENT_H

#include <qstring.h>
#include <qtimer.h>
#include <qmutex.h>
#include <qobject.h>
#include <qptrlist.h>

#include <openssl/des.h>
#include "mgcam/openssl-compat.h"

#define WORD(buffer,index,mask) (((buffer[(index)]<<8) + buffer[(index)+1]) & mask)
#define CWS_NETMSGSIZE 240


#define CWS_FIRSTCMDNO 0xe0

typedef enum
{
	MSG_CLIENT_2_SERVER_LOGIN = CWS_FIRSTCMDNO,
	MSG_CLIENT_2_SERVER_LOGIN_ACK,
	MSG_CLIENT_2_SERVER_LOGIN_NAK,
	MSG_CARD_DATA_REQ,
	MSG_CARD_DATA,
	MSG_SERVER_2_CLIENT_NAME,
	MSG_SERVER_2_CLIENT_NAME_ACK,
	MSG_SERVER_2_CLIENT_NAME_NAK,
	MSG_SERVER_2_CLIENT_LOGIN,
	MSG_SERVER_2_CLIENT_LOGIN_ACK,
	MSG_SERVER_2_CLIENT_LOGIN_NAK,
	MSG_ADMIN,
	MSG_ADMIN_ACK,
	MSG_ADMIN_LOGIN,
	MSG_ADMIN_LOGIN_ACK,
	MSG_ADMIN_LOGIN_NAK,
	MSG_ADMIN_COMMAND,
	MSG_ADMIN_COMMAND_ACK,
	MSG_ADMIN_COMMAND_NAK,
	MSG_KEEPALIVE = CWS_FIRSTCMDNO + 0x1d
} net_msg_type_t;

typedef enum
{
	COMMTYPE_CLIENT,
	COMMTYPE_SERVER
} comm_type_t;

struct CustomData
{
        unsigned short sid;
        unsigned char data[6];
};



#define CONNECTIONTIMEOUT 300000

class CsSocket
{
public:
	CsSocket();
	bool startConnect( QString host, int port );
	bool Bind( QString host, int port );
	void stopConnect();
	int connectFd();

protected:
	bool Select( bool forRead, int timeout );
	void Flush();
	int Read( unsigned char *data, int len, int timeout );
	int Write( const unsigned char *data, int len, int timeout );
	int SendTo( const char *Host, int Port, const unsigned char *data, int len, int timeout );

private:
	int sockfd;
};



class cTripleDes
{
private:
	DES_key_schedule ks1,ks2;
	void SetOddParity(unsigned char *key); // key must be 16 bytes!
protected:
	unsigned char desKey[16];
	void ScheduleKey(void);
	int PadMessage(unsigned char *data, int len);
	void Expand(unsigned char *expanded, const unsigned char *normal); // 14 byte key input, 16 byte expanded output
	void Decrypt(unsigned char *data, int len);
	const unsigned char *Encrypt(const unsigned char *data, int len, unsigned char *crypt);
};



class EcmCache
{
public:
	EcmCache( int pn, int tp );
	~EcmCache() {}
	unsigned char ecm[500];
	unsigned char CW[16];
	int sid, tsid;
	bool cw;
};



class Ecm;



class CardClient : public QObject, public CsSocket
{
	Q_OBJECT
public:
	CardClient( QString host, QString user, QString pwd, int p_ort, QString ckey, QString caid, QString prov );
	virtual ~CardClient();
	virtual bool canHandle( int caid, int prov );
	QString getCAID();
	int getCaId() { return caID; }
	virtual void setCAID( QString caid );
	QString getHost() { return hostname; }
	virtual void setHost( QString h );
	QString getUser() { return username; }
	virtual void setUser( QString u );
	QString getPass() { return password; }
	virtual void setPass( QString p );
	int getPort() { return port; }
	virtual void setPort( int p );
	QString getCkey();
	virtual void setCkey( QString key );
	QString getProv();
	virtual void setProv( QString prov );
	void mustDie();
	virtual bool processECM( unsigned char*, int, unsigned char*, Ecm*, bool& ){return false;}
	void unregisterProgram( int sid, int tsid );
	void setCache( int sid, int tsid, unsigned char *ECM, int len, bool cw, unsigned char *CW );
	bool isInCache( int sid, int tsid, unsigned char *ECM, int len, bool &cw, unsigned char *CW );

protected slots:
	virtual void connectionTimeout();

protected:
	void registerProgram( int sid, int tsid );
	bool canHandleProv( int prov );

	bool haveToDie;
	QString hostname;
	QString username;
	QString password;
	int port;
	unsigned char configKey[14];
	int caID;
	QValueList<int> provId;
	QTimer connectionTimer;
	QMutex mutex;
	QPtrList<EcmCache> ecmCache;

signals:
	void killMe( CardClient * );

};



class NewCSClient : public CardClient, public cTripleDes
{
	Q_OBJECT
public:
	NewCSClient( QString host, QString user, QString pwd, int p_ort, QString ckey, QString caid, QString prov );
	virtual bool processECM( unsigned char *ECM, int len, unsigned char *cw, Ecm *e, bool& );

private:
	bool login();
	void prepareLoginKey(unsigned char *deskey, const unsigned char *rkey, const unsigned char *ckey);
	int CmdReceive( comm_type_t commType=COMMTYPE_CLIENT );
	bool CmdSend( net_msg_type_t cmd, comm_type_t commType=COMMTYPE_CLIENT );
	int ReceiveMessage( unsigned char *data, bool UseMsgId, struct CustomData *cd=0, comm_type_t commType=COMMTYPE_CLIENT );
	bool SendMessage( const unsigned char *data, int len, bool UseMsgId, const struct CustomData *cd=0, comm_type_t commType=COMMTYPE_CLIENT );
	void InitCustomData( struct CustomData *cd, const unsigned short PrgId, const unsigned char *data );

	int cdLen;
	unsigned short netMsgId;

};



class GboxClient : public CardClient
{
	Q_OBJECT
public:
	GboxClient( QString host, QString user, QString pwd, int p_ort, QString ckey, QString caid, QString prov );
	virtual bool canHandle( int, int ) {return true;}
	virtual void setCAID( QString ) {};
	virtual void setHost( QString ) {};
	virtual void setUser( QString ) {};
	virtual void setPass( QString ) {};
	virtual void setPort( int ) {};
	virtual void setCkey( QString ) {};
	virtual void setProv( QString ) {};
	virtual bool processECM( unsigned char *ECM, int len, unsigned char *cw, Ecm *e, bool &hack );

private:
	int GetMsg( int cmd, unsigned char *buff, int len );
	bool login();
	bool haveShare( Ecm *e );
	bool sameCW( unsigned char *o, unsigned char *n );

};
#endif
