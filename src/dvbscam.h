#ifndef DVBSCAM_H
#define DVBSCAM_H

#include <linux/dvb/ca.h>

#include <qstring.h>
#include <qmutex.h>
#include <qobject.h>
#include <qptrlist.h>
#include <qvaluelist.h>

#include "mgcam/mgcam.h"
#include "cardclient.h"
#include "dvbsection.h"



class Ecm
{

public :

	Ecm();
	~Ecm();

	int pid, id, system, sid, tsid;
	QString name;
	int csCAID, csPort;
	QString csHost;
	int chid;
	QValueList<int> counter;
};



class Skey
{

public :

	Skey();
	~Skey();

	char type;
	int id;
	int keynr;
	int tsid;
	BIGNUM * bkey; //for rsa nagra2
	unsigned long long key, v2key;
};



class DVBscam : public DVBsection
{
	Q_OBJECT
public:

	DVBscam( int anum, int tnum, QPtrList<CardClient> *list );
	~DVBscam();
	bool go( int sid );
	void stop();
	int caFd() { return cafd; }

	unsigned char CW[16];
	bool cw;
	unsigned char *tsbuf;
	int ntune;
	int tsbuf_seek;
	bool tsbuf_full;


protected:

	virtual void run();
	bool getSection( int pid, int tid, int timeout=5000, bool checkcrc=true, int sid=0 );
	bool parsePAT( unsigned char *buf, int sid, int &pmt, bool tsidOnly=false );
	bool parsePMT( unsigned char* buf );
	void caDesc( unsigned char *buf );
	void addCaDesc( Ecm *e );
	bool getKeys();
	bool getCachedEcms();
	void getFineTune();
	void saveCachedEcms();
	bool process( CardClient *cc, Ecm *e, int evod );
	bool Viaccess( unsigned char *source, int length, int id );
	bool Seca( unsigned char *source, int length, int id, int keynr );
	bool Irdeto( unsigned char *source, int length, int id );
	bool ConstantCW( Ecm *e, int sid, int biss );
	bool Nagra3( );
	bool Nagra2( unsigned char *source );
	bool Nagra1( unsigned char *data );
	bool Cryptoworks( unsigned char *source, int caid );
	bool FindKey( char type, int &id, int keynr, unsigned char *key, int keylen );
	bool FindKey( char type, int id, int keynr, BIGNUM **key );
	bool FindKey( char type, int id, BIGNUM **key );
	CardClient *getCardClient( Ecm *e );
	bool checkCHID( Ecm *e, int evod );

private:

	void printError( QString msg );
	void writeCw();

	int cafd;

	unsigned char sbuf[4096];
	int sbufLen;
	int programNumber;
	int tsID;
	QPtrList<Ecm> ecms;
	QPtrList<Ecm> cEcms;
	QPtrList<Skey> keys;
	QPtrList<CardClient> *csList;
	bool badcwhack;
	int naes;

signals:
	void needTpsAu( int anum, int tnum );
};
#endif
