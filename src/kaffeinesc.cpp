#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <qdir.h>
#include <qfile.h>
#include <qlayout.h>
#include <qgroupbox.h>
#include <qpushbutton.h>
#include <qlabel.h>
#include <qregexp.h>
#include <qtextedit.h>

#include <klocale.h>
#include <kaction.h>
#include <kparts/genericfactory.h>

#include "FFdecsa/FFdecsa.h"
#include "dvbscam.h"
#include "kaffeinesc.h"
#include "kaffeinesc.moc"

#define SCVERSION "0.3.9-svn"



ConfigLine::ConfigLine( QString h, QString u, QString p, int pt, QString k, QString c, QString pr )
{
	host = h;
	user = u;
	pass = p;
	port = pt;
	key = k;
	caid = c;
	prov = pr;
}



ScListViewItem::ScListViewItem( CardClient *c, KListView *parent, QString host, QString user, QString pass, QString port, QString key, QString caid, QString prov ) : KListViewItem( parent, host, user, pass, port, key, caid, prov )
{
	cc = c;
}



ScConfigDialog::ScConfigDialog( KaffeineSc *k, QWidget *parent, QPtrList<CardClient> *cc ) :
	ScConfigDialogUI ( parent, "scconfigdialog", true )
{
	int i;
	QString s;
	CardClient *tc;

	ksc = k;

	clientList->setAllColumnsShowFocus( true );
	clientList->addColumn( i18n("Hostname") );
	clientList->addColumn( i18n("User name") );
	clientList->addColumn( i18n("Password") );
	clientList->addColumn( i18n("Port") );
	clientList->addColumn( i18n("Config key (hex)") );
	clientList->addColumn( i18n("CA id (hex)") );
	clientList->addColumn( i18n("ProvId (hex1,hex2...)") );
	clientList->setItemsRenameable( true );
	clientList->setRenameable( 0, true );
	clientList->setRenameable( 1, true );
	clientList->setRenameable( 2, true );
	clientList->setRenameable( 3, true );
	clientList->setRenameable( 4, true );
	clientList->setRenameable( 5, true );
	clientList->setRenameable( 6, true );

	connect( addBtn, SIGNAL(clicked()), this, SLOT(addEntry()) );
	connect( delBtn, SIGNAL(clicked()), this, SLOT(deleteEntry()) );
	connect( saveKeysBtn, SIGNAL(clicked()), this, SLOT(saveKeyFile()) );

	csList = cc;
	for ( i=0; i<(int)cc->count(); i++ ) {
		tc = cc->at(i);
		if ( tc->getHost()=="127.0.0.1" && tc->getUser()=="gbox_indirect" )
			gbox->setChecked( true );
		else
			new ScListViewItem( tc, clientList, tc->getHost(), tc->getUser(), tc->getPass(),
			s.setNum(tc->getPort()), tc->getCkey(), tc->getCAID(), tc->getProv() );
	}

	connect( clientList, SIGNAL(itemRenamed(QListViewItem*)), this, SLOT(clientChanged(QListViewItem*)) );
	connect( gbox, SIGNAL(toggled(bool)), this, SLOT(gboxEnabled(bool)) );

	textEditKeys->setFont( addBtn->font() );

        loadKeyFile();
}



void ScConfigDialog::gboxEnabled( bool b )
{
	int i;
	CardClient *tc=0;

	for ( i=0; i<(int)csList->count(); i++ ) {
		tc = csList->at(i);
		if ( tc->getHost()=="127.0.0.1" && tc->getUser()=="gbox_indirect" )
			break;
		else
			tc = 0;
	}

	if ( b ) {
		if ( tc )
			return;
		tc = new GboxClient( "", "", "", 0, "", "", "" );
		csList->append( tc );
		connect( tc, SIGNAL(killMe(CardClient*)), ksc, SLOT(killCardClient(CardClient*)) );
	}
	else {
		if ( !tc )
			return;
		emit removeCardClient( tc );
	}
}



void ScConfigDialog::clientChanged( QListViewItem *it )
{
	if ( !it )
		return;
	ScListViewItem *sc = (ScListViewItem*)(it);
	sc->cc->setHost( it->text(0) );
	sc->cc->setUser( it->text(1) );
	sc->cc->setPass( it->text(2) );
	sc->cc->setPort( it->text(3).toInt() );
	sc->cc->setCkey( it->text(4) );
	sc->cc->setCAID( it->text(5) );
	sc->cc->setProv( it->text(6) );
}



void ScConfigDialog::addEntry()
{
	CardClient *cc = new NewCSClient( "localhost", "user", "passwd", 1000, "AB01CD02....", "AABB", "00A,00B" );
	csList->append( cc );
	connect( cc, SIGNAL(killMe(CardClient*)), ksc, SLOT(killCardClient(CardClient*)) );
	new ScListViewItem( cc, clientList, "localhost", "user", "passwd", "1000", "AB01CD02....", "AABB", "00A,00B" );
}



void ScConfigDialog::deleteEntry()
{
	QListViewItem *it;
	ScListViewItem *sc;

	it = clientList->firstChild();
	while ( it!=0 ) {
		if ( it->isSelected() ) {
			sc = (ScListViewItem*)(it);
			emit removeCardClient( sc->cc );
			delete it;
			return;
		}
		it = it->nextSibling();
	}
}



void ScConfigDialog::accept()
{
	QValueList<ConfigLine> list;
	QListViewItem *it;
	QString c;

	it = clientList->firstChild();
	while ( it!=0 ) {
		list.append( ConfigLine( it->text(0), it->text(1), it->text(2), it->text(3).toInt(), it->text(4), it->text(5), it->text(6) ) );
		it = it->nextSibling();
	}
	if ( gbox->isChecked() )
		list.append( ConfigLine( "127.0.0.1", "gbox_indirect", "gbox_indirect", 0, "00", "00", "00" ) );
	saveNewcsConf( list );
	done( Accepted );
}



void ScConfigDialog::saveNewcsConf( QValueList<ConfigLine> list )
{
	QString s, c;
        const QString k(".kaffeine");
        const QString conf_name("/NewCS.conf");
	int i;

        // First create configuration directory, if it does not exists.
        QDir h = QDir::home();
        if(!h.exists(k)) {
                if(!h.mkdir(k)) {
                        fprintf( stderr, "Can't mkdir %s !!!\n", h.filePath(k).ascii());
                        return;
                }
        }

        // Then, create a new temporary configuration file.
        // This avoids potentially corrupting the current configuration file, if something goes wrong.
        QFile f( h.filePath(k+conf_name+"~") );
        if ( !f.open(IO_WriteOnly) ) {
                fprintf( stderr, "Can't open %s !!!\n", f.name().ascii() ); 
		return;

	}

	QTextStream t( &f );
	t<< "# Newcs servers list\n";
	for ( i=0; i<(int)list.count(); i++ ) {
		t<< list[i].host;
		t<< " ";
		t<< list[i].user;
		t<< " ";
		t<< list[i].pass;
		t<< " ";
		t<< c.setNum( list[i].port );
		t<< " ";
		t<< list[i].key;
		t<< " ";
		t<< list[i].caid;
		t<< " ";
		t<< list[i].prov;
		t<< "\n";
	}

	f.close();
 
        // Finally, replace the current configuration file (if any), with the new temp file.
        h.rename( f.name(), h.filePath(k+conf_name) );

}



QValueList<ConfigLine> ScConfigDialog::getNewcsConf()
{
	QString s, c;
	QValueList<ConfigLine> list;
	char host[128];
	char user[128];
	char pass[128];
	char key[128];
	char caid[128];
	char prov[128];
	int port;

	s = QDir::homeDirPath()+"/.kaffeine/NewCS.conf";
	QFile f( s );
	if ( !f.open(IO_ReadOnly) ) {
		fprintf( stderr, "Can't open %s !!!\n", s.ascii() );
		return list;
	}

	QTextStream t( &f );
	while ( !t.eof() ) {
		s = t.readLine();
		if ( !s.startsWith("#") ) {
			if ( sscanf( s.ascii(), "%s %s %s %d %s %s %s", host, user, pass, &port, key, caid, prov ) != 7)
				continue;
			list.append( ConfigLine( QString(host), QString(user), QString(pass), port, QString(key), QString(caid), QString(prov) ) );
		}
	}

	f.close();
	return list;
}



void ScConfigDialog::loadKeyFile()
{
	QString s;

	s = QDir::homeDirPath()+"/.kaffeine/SoftCam.Key";
	QFile f( s );
	if ( !f.open(IO_ReadOnly) ) {
		fprintf( stderr, "Can't open %s !!!\n", s.ascii() );
		return;
	}
	QTextStream t( &f );

	while ( !t.eof() ) {
		s = t.readLine();
		textEditKeys->append(s);
                 }
	f.close();
}



void ScConfigDialog::saveKeyFile()
{
	emit saveSoftcamKey( textEditKeys->text() );
}


K_EXPORT_COMPONENT_FACTORY (libkaffeinedvbsc, KParts::GenericFactory<KaffeineSc>)

KaffeineSc::KaffeineSc( QWidget*, const char*, QObject* parent, const char* name, const QStringList& )
	: KaffeineDvbPlugin(parent,name)
{
	int i;
	QString s;
	CardClient *cc;


	setInstance(KParts::GenericFactory<KaffeineSc>::instance());

	csList.setAutoDelete( true );
	emmThreads.setAutoDelete( true );


	QValueList<ConfigLine> list = ScConfigDialog::getNewcsConf();
	for ( i=0; i<(int)list.count(); i++ ) {
		if ( list[i].user=="gbox_indirect" && list[i].host=="127.0.0.1" )
			cc = new GboxClient( "", "", "", 0, "", "", "" );
		else
			cc = new NewCSClient( list[i].host, list[i].user, list[i].pass, list[i].port, list[i].key.ascii(), list[i].caid, list[i].prov );
		csList.append( cc );
		connect( cc, SIGNAL(killMe(CardClient*)), this, SLOT(killCardClient(CardClient*)) );
	}
	connect( &tpsauTimer, SIGNAL(timeout()), this, SLOT(runTpsAu()) );
}



KaffeineSc::~KaffeineSc()
{
	csList.clear();
	emmThreads.clear();
}



KAboutData *KaffeineSc::createAboutData()
{
	KAboutData* aboutData = new KAboutData( "kaffeinedvbsc", I18N_NOOP("KaffeineDvbSc"),
	                                        "0.1", I18N_NOOP("A DVB softcam for Kaffeine."),
	                                        KAboutData::License_GPL, "(c) 2006, Us and Them.", 0, "", "");
	aboutData->addAuthor("Someone.",0, "nowhere@noland.org");

	return aboutData;
}



QString KaffeineSc::pluginName()
{
	QString s = "Softcam";
	s+= " ";
	s+= SCVERSION;
	return s;
}



void KaffeineSc::configDialog()
{
	ScConfigDialog dlg( this, 0, &csList );
	connect( &dlg, SIGNAL(removeCardClient(CardClient*)), this, SLOT(removeCardClient(CardClient*)) );
	connect( &dlg, SIGNAL(saveSoftcamKey(const QString&)), this, SLOT(saveSoftcamKey(const QString&)) );
	dlg.exec();
}



void KaffeineSc::removeCardClient( CardClient *cc )
{
	cc->mustDie();
}



void KaffeineSc::killCardClient( CardClient *cc )
{
	csList.remove( cc );
}



void KaffeineSc::runTpsAu()
{
	int anum=-1, tnum=-1;
	QString s = QDir::homeDirPath()+"/.kaffeine/wantTpsAu";
	QFile f( s );
	if ( !f.exists() ) {
		tpsauTimer.stop();
		return;
	}

	if ( f.open(IO_ReadOnly) ) {
		QTextStream t( &f );
		t >> anum;
		t >> tnum;
		f.close();
	}
	if ( anum!=-1 && tnum!=-1 )
		runTpsAu( anum, tnum );
}



void KaffeineSc::runTpsAu( int anum, int tnum )
{
	QString s = QDir::homeDirPath()+"/.kaffeine/wantTpsAu";
	QString c;
	QFile f( s );
	if ( f.open(IO_WriteOnly|IO_Truncate) ) {
		QTextStream t( &f );
		t << c.setNum( anum )+"\n";
		t << c.setNum( tnum )+"\n";
		f.close();
	}
	tpsau.go( anum, tnum );
	tpsauTimer.start( 3000 );
}



void KaffeineSc::saveSoftcamKey( const QString &text )
{
	QString s;

	scMutex.lock();

	s = QDir::homeDirPath()+"/.kaffeine/SoftCam.Key";
	QFile f( s );
	if ( !f.open(IO_WriteOnly) ) {
		fprintf( stderr, "Can't open %s !!!\n", s.ascii() );
		scMutex.unlock();
		return;
	}
        QTextStream out( &f );
        out << text;
	fprintf( stderr, "SoftCam.Key Saved\n");
	scMutex.unlock();
}



void KaffeineSc::newKey( const QStringList &list )
{
	scMutex.lock();

	QString s, t, c, d;
	char type;
	unsigned int id, keynr;
	char key[500];
	QStringList fileList;
	int update=0; // -1=up to date, 0=add key, 1=update key
	bool ok;
	int i;

	s = QDir::homeDirPath()+"/.kaffeine/SoftCam.Key";
	QFile f( s );
	if ( !f.open(IO_ReadOnly) ) {
		scMutex.unlock();
		return;
	}
	QTextStream ts( &f );
	while ( !ts.eof() ) {
		t = ts.readLine();
		s = t.upper();
		if ( !s.startsWith(";") || !s.startsWith("#")) {
			s.remove( QRegExp(";.*") );
			if ( !s.startsWith(list[0]) )
				goto next;
			if ( list[0]=="I" || list[0]=="V" || list[0]=="S" || list[0]=="N" ) { // IRDETO, VIACCESS, SECA, NAGRA
				if ( sscanf( s.latin1(), "%c %x %x %s", &type, &id, &keynr, key) != 4)
					goto next;
				if ( id==list[1].toInt(&ok,16) && keynr==list[2].toInt(&ok,16) ) {
					c = key;
					if(list[4]=="kA") {
						d=list[3];
						d=d.replace(16,16,c.right(16));
					}
					else if(list[4]=="kB") {
						d=list[3];
						d=d.replace(0,16,c.left(16));
					}
					if(!d.isEmpty()) {
						if ( c==d.upper() ) {
							update = -1;
							break;
						}
						else {
							t = t.replace( c, d );
							update = 1;
						}
						d="";
					}
					else if ( c==list[3].upper() ) {
						update = -1;
						break;
					}
					else {
						t = t.replace( c, list[3] );
						update = 1;
					}
				}
			}
		}
		next:
		fileList.append( t );
	}
	f.close();

	if ( update!=-1 ) {
		s = QDir::homeDirPath()+"/.kaffeine/SoftCam.Key";
		f.setName( s );
		if ( !f.open(IO_WriteOnly) ) {
			scMutex.unlock();
			return;
		}
		QTextStream ts( &f );
		s = "";
		for ( i=0; i<(int)list.count(); i++ )
			s = s + list[i] + " ";
		if ( update==0 ) {
			ts << s;
			ts << ";kaffeine-sc AU, ";
			ts << QDate::currentDate().toString("yyyy-MMM-dd");
			ts << "\n";
			fprintf( stderr, "\n\nNEW KEY : %s\n\n", s.ascii() );
		}
		else
			fprintf( stderr, "\n\nUPDATED KEY : %s\n\n", s.ascii() );
		for ( i=0; i<(int)fileList.count(); i++ ) {
			ts << fileList[i];
			ts << "\n";
		}
		f.close();
	}
	else {
		s = "";
		for ( i=0; i<(int)list.count(); i++ )
			s = s + list[i] + " ";
		fprintf( stderr, "\n\nFOUND KEY : %s\n\n", s.ascii() );
	}

	scMutex.unlock();
}



void* KaffeineSc::init( int sid , int anum, int tnum, int fta )
{
	if ( !fta )
		return NULL;

	mutex.lock();

	CatParser *c=0;
	for ( int i=0; i<(int)emmThreads.count(); i++ ) {
		if ( emmThreads.at(i)->getAdapter()==anum && emmThreads.at(i)->getTuner()==tnum ) {
			c = emmThreads.at(i);
			break;
		}
	}
	if ( !c ) {
		c = new CatParser( anum, tnum );
		connect( c, SIGNAL(newKey(const QStringList&)), this, SLOT(newKey(const QStringList&)) );
		emmThreads.append( c );
		c->go();
	}
	else {
		c->reset();
	}

	DVBscam *sc = new DVBscam( anum, tnum, &csList );
	connect( sc, SIGNAL(needTpsAu(int,int)), this, SLOT(runTpsAu(int,int)) );
	sc->go( sid );
	mutex.unlock();
	return (void*)(sc);
}



void KaffeineSc::process( void* handle, unsigned char* buf, int len )
{
	int i;

	if ( handle==NULL )
		return;

	mutex.lock();

	DVBscam *sc = (DVBscam*)(handle);
	if ( !sc->cw || (sc->caFd()==-1) ) {
		mutex.unlock();
		return;
	}
	if ( sc->caFd()>0 ) {
		for ( i=0; i<len; i+=188 )
			buf[i+3]&=0x3F;
	}
	else{
		if ( sc->ntune ) {
			memcpy( sc->tsbuf+sc->tsbuf_seek, buf, len );
			sc->tsbuf_seek+=len;
			if ( sc->tsbuf_seek>=(sc->ntune*64*188) ) {
				sc->tsbuf_full = true;
				sc->tsbuf_seek = 0;
			}
			if ( sc->tsbuf_full ) {
				descramble( sc->CW, sc->tsbuf+sc->tsbuf_seek, 64*188 );
				memcpy( buf, sc->tsbuf+sc->tsbuf_seek, len );
			}
		}
		else
			descramble( sc->CW, buf, len );
	}
	mutex.unlock();
}



void KaffeineSc::close( void* handle )
{
	if ( handle==NULL )
		return;

	mutex.lock();

	DVBscam *sc = (DVBscam*)(handle);
	sc->stop();
	delete sc;
	mutex.unlock();
}




void KaffeineSc::descramble( unsigned char *cw, unsigned char *buf, int count )
{
	int dd;
	unsigned char* cluster[10];

	set_control_words(cw, cw+8);
	dd=0;
	while ( dd<(count/188) ) {
		cluster[0]=buf+188*dd;cluster[1]=buf+count;cluster[2]=NULL;
		dd+= decrypt_packets(cluster);
	}
}
