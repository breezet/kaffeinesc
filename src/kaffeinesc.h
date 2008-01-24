#ifndef KAFFEINESC_H
#define KAFFEINESC_H

#include <qptrlist.h>
#include <qvaluelist.h>
#include <qwidget.h>
#include <qstringlist.h>
#include <qcheckbox.h>
#include <qtimer.h>

#include <kdialogbase.h>
#include <klistview.h>
#include <kaffeine/kaffeinedvbplugin.h>

#include "cardclient.h"
#include "tpsau.h"
#include "emm.h"



class ConfigLine
{
public:
	ConfigLine() {};
	ConfigLine( QString, QString, QString, int, QString, QString, QString );
	QString host, user, pass, key, caid, prov;
	int port;
};



class ScListViewItem : public KListViewItem
{
public:
	ScListViewItem( CardClient *c, KListView *parent, QString host, QString user, QString pass, QString port, QString key, QString caid, QString prov );

	CardClient *cc;
};



class KaffeineSc;

class ScConfigDialog : public KDialogBase
{
	Q_OBJECT

public:
	ScConfigDialog( KaffeineSc *k, QWidget *parent, QPtrList<CardClient> *cc );
	~ScConfigDialog() {};

	static QValueList<ConfigLine> getNewcsConf();
	void saveNewcsConf( QValueList<ConfigLine> list );

private:
	KListView *clientList;
	QPushButton *add, *del;
	QPtrList<CardClient> *csList;
	KaffeineSc *ksc;
	QCheckBox *gbox;

protected slots:
	void accept();
	void addEntry();
	void deleteEntry();
	void clientChanged( QListViewItem *it);
	void gboxEnabled( bool b );

signals:
	void removeCardClient( CardClient* );
};



 class KaffeineSc : public KaffeineDvbPlugin
{
	Q_OBJECT
public:

	KaffeineSc( QWidget*, const char*, QObject*, const char*, const QStringList& );
	~KaffeineSc();
	QString pluginName();

	void* init( int sid , int anum, int tnum, int fta );

	void process( void* handle, unsigned char* buf, int len );
	void close( void* handle );

	static KAboutData* createAboutData();

public slots:

	void configDialog();
	void killCardClient( CardClient *cc );
	void removeCardClient( CardClient *cc );

private slots:

	void runTpsAu( int anum, int tnum );
	void runTpsAu();
	void newKey( const QStringList & );

private:

	//void initActions();
	void descramble( unsigned char *cw, unsigned char *buf, int count );

	QMutex mutex, scMutex;
	QPtrList<CardClient> csList;
	QPtrList<CatParser> emmThreads;
	TpsAu tpsau;
	QTimer tpsauTimer;
};
#endif
