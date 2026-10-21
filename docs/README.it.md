# Certificate Manager — guida italiana

[English overview](../README.md) · [Workflow spiegato](WORKFLOW.it.md) · [Licenza MIT](../LICENSE) · [Pubblicazione su GitHub](PUBLISHING.md)

Programma in C con interfaccia web e archivio SQLite locale. Importa certificati X.509, estrae i dati utili, segue le scadenze e gestisce più referenti per ogni certificato. I promemoria sono previsti a **45, 30, 15 e 2 giorni**, più un avviso alla scadenza.

La pagina **Coda email** consente di configurare SMTP, verificare la connessione e attivare o mettere in pausa l’invio. Alla prima installazione il trasporto è disabilitato: i messaggi restano in coda e possono essere scaricati come `.eml`.

L’interfaccia è disponibile in **inglese, italiano, francese, spagnolo, cinese semplificato e giapponese**. Scegli la lingua dal selettore nell’interfaccia. I dati dei certificati, i nomi dei referenti e gli altri contenuti inseriti dall’utente mantengono la propria forma originale. I comandi da terminale e i testi dei messaggi email generati rimangono in italiano.

Il progetto usa la licenza **MIT** ed è predisposto per la pubblicazione del codice sorgente su GitHub come **Certificate Manager**. Il server resta uno strumento locale senza autenticazione utenti: ascolta su `127.0.0.1` e non è pronto per l’esposizione diretta in rete. Vedi [SECURITY.md](../SECURITY.md) e la [guida alla pubblicazione](PUBLISHING.md).

## Workflow

Il percorso operativo è: **acquisizione del certificato → registro e referenti → controlli di scadenza e degli URL → rinnovo → distribuzione ai tecnici → installazione sul servizio e verifica**.

Il browser dialoga con le API del backend C, che legge e aggiorna SQLite. Il backend esegue i controlli periodici, interroga i servizi HTTPS e prepara la coda email. Le scadenze producono messaggi per i referenti; i rinnovi producono allegati PEM per i tecnici; le anomalie dei servizi restano visibili nell’interfaccia. I tecnici installano il certificato sul servizio esternamente al programma.

La [spiegazione completa del workflow](WORKFLOW.it.md) contiene i diagrammi dei componenti e del rinnovo, le frequenze, i ruoli e un esempio operativo. È disponibile anche [in inglese](WORKFLOW.md).

## Installazione e avvio

Su Ubuntu/Debian:

```sh
sudo apt install build-essential pkg-config libssl-dev libsqlite3-dev libcurl4-openssl-dev openssl python3 nodejs
make
./certificati
```

Su macOS, con gli strumenti da riga di comando di Xcode e Homebrew:

```sh
brew install openssl sqlite pkg-config python3 node
make
./certificati
```

La compilazione usa `pkg-config` per trovare `openssl`, `sqlite3` e `libcurl`. Su macOS può usare libcurl di sistema se disponibile tramite `pkg-config`. Se `pkg-config --exists libcurl` fallisce, installa la variante Homebrew e indica il suo percorso durante la compilazione:

```sh
brew install curl
PKG_CONFIG_PATH="$(brew --prefix curl)/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" make
```

Apri [http://127.0.0.1:8080](http://127.0.0.1:8080) e carica i file `.pem`, `.crt`, `.cer` o `.der`, anche più file insieme. Il formato viene riconosciuto dal contenuto; il limite è 16 MiB per file. Il server ascolta esclusivamente su `127.0.0.1`.

Per scegliere un altro archivio o un'altra porta:

```sh
./certificati --db archivio.db serve --port 8090
```

L'archivio predefinito è `certificati.db` nella cartella da cui avvii il programma. Le cartelle del percorso scelto devono già esistere. I dati rimangono disponibili dopo il riavvio. Premi `Ctrl+C` nel terminale per arrestare il programma.

## Navigazione dell’interfaccia

L’interfaccia è suddivisa in **sette pagine**, ciascuna con il proprio indirizzo e soltanto i controlli della funzione scelta. Il menu laterale apre la pagina corrispondente; su schermi piccoli mantiene le etichette e scorre orizzontalmente.

| Pagina | Indirizzo | Contenuto |
| --- | --- | --- |
| Panoramica | `/` | Contatori, scadenze entro 45 giorni e anomalie dei servizi. |
| Certificati | `/certificati` | Registro, ricerca, filtri e dettagli con referenti e rinnovo. |
| Servizi monitorati | `/servizi` | Configurazione degli URL, ultimi esiti e avvisi periodici. |
| Importa certificati | `/importa` | Caricamento dei file PEM, DER, CRT e CER. |
| Verifica endpoint | `/verifica` | Recupero e confronto del certificato esposto da un servizio. |
| Promemoria | `/promemoria` | Scadenze registrate e preferenze delle notifiche desktop. |
| Coda email | `/email` | Messaggi preparati, stato degli invii e download `.eml`. |

Ogni indirizzo può essere aperto direttamente, aggiunto ai preferiti o ricaricato. Puoi usare Indietro e Avanti del browser. Ricerca e filtri del registro vengono ricordati nella stessa scheda. Salva le modifiche ai referenti e ai monitor prima di cambiare pagina; il cambio pagina carica un documento nuovo.

## Registro, ricerca e catena

Il registro mostra subito dopo il dominio la **Scadenza**, i **Referenti** e i **Referenti tecnici**, con nomi ed email. I pulsanti **Gestisci** aprono il dettaglio direttamente nella sezione dei destinatari. Sono inoltre disponibili stato, Root CA, CA intermedie, inizio validità e giorni residui. Su schermi stretti ogni riga diventa una scheda con gli stessi dati, senza scorrimento orizzontale. I dettagli comprendono anche SAN, emittente, numero di serie, impronta SHA-256, chiave pubblica e algoritmo di firma.

La ricerca comprende dominio, CA, date, referente e nome del file. I filtri consentono di vedere tutti i certificati, quelli validi nel tempo, gli scaduti e quelli non ancora validi. **Referente** e **Referente tecnico** mostrano le persone assegnate, identificate dall'email e distinte per ruolo: scegli una persona per vedere i suoi certificati. Puoi combinare i due filtri con stato e ricerca; ogni risultato deve rispettare tutte le selezioni. **Azzera filtri** ripristina il registro completo delle voci attive. Le selezioni restano memorizzate nella stessa scheda del browser, anche cambiando pagina. I certificati sostituiti da un rinnovo sono nascosti: seleziona **Mostra sostituiti** per consultarli. Le schede riepilogative escludono i sostituiti.

I filtri **CA principale (Root CA)** e **CA intermedia** si combinano con tutti gli altri filtri. Le autorità sono identificate dal nome completo presente nella catena ricostruita; ciascuna CA intermedia è selezionabile anche nelle catene che ne contengono più di una. **Non disponibile** individua i dati mancanti o le catene incomplete; **Nessuna CA intermedia** individua le catene complete senza intermedie. Anche le selezioni delle CA restano memorizzate nella scheda e vengono cancellate da **Azzera filtri**.

**In scadenza entro** restringe i risultati ai certificati già validi che scadono entro **45, 30, 15 o 2 giorni** a partire dall'ora del controllo, includendo il limite esatto della soglia. Le soglie sono cumulative: entro 15 giorni include anche quelli entro 2 giorni. Sono esclusi quelli già scaduti e quelli non ancora validi. Il filtro usa gli istanti effettivi di validità, si combina con tutte le altre selezioni e viene ricordato nella scheda e ripristinato da **Azzera filtri**. **Tutte le scadenze** rimuove solo questo vincolo.

**Emissione / valido dal** indica `notBefore`, cioè l'inizio del periodo di validità, non l'istante effettivo di firma. Un certificato è valido nel tempo quando `notBefore ≤ ora < notAfter`. Le date web usano il fuso orario del browser; quelle da terminale sono in UTC. I giorni positivi sono arrotondati per eccesso: a 25 ore dalla scadenza la tabella mostra 2 giorni.

Root CA e intermedie vengono ricostruite dai certificati caricati, verificando i collegamenti e le firme della catena. Se manca una CA, il campo resta non disponibile: il solo nome dell'emittente non dimostra la presenza di una Root CA. Carica un bundle PEM con il certificato del servizio e le CA disponibili per completare i dati.

La ricostruzione della catena dei file caricati è distinta dal controllo di un servizio in rete descritto sotto. La sola presenza di una Root CA nel registro non la rende fidata. Il programma non verifica la revoca e non richiede né firma nuovi certificati.

## Recuperare un certificato da URL o CN

Nella pagina **Verifica endpoint** (`/verifica`), inserisci un URL HTTPS oppure il nome effettivo del servizio, per esempio `https://servizio.example.it`, `servizio.example.it` o `servizio.example.it:8443`. Sono accettati anche IPv4 e IPv6 tra parentesi quadre, come `https://[::1]:8443`. Senza porta esplicita viene usata la 443. Il CN è utilizzabile come destinazione solo se è un nome concreto risolvibile: sostituisci un wildcard come `*.example.it` con un host reale. Un certificato senza CN può comunque essere controllato indicando uno dei suoi nomi DNS SAN o l'indirizzo corretto.

La verifica risolve il nome DNS, apre la connessione TCP e negozia TLS per leggere il certificato e la catena presentata dal server. **Non invia una richiesta HTTP**: percorso, query e contenuto della pagina non vengono scaricati. Uno schema diverso da HTTPS, credenziali nell'URL, porte non valide o caratteri di controllo vengono respinti.

L'esito distingue raggiungibilità DNS, collegamento TCP, negoziazione TLS, fiducia della catena, corrispondenza del nome e validità temporale. L'indicatore temporale riguarda il certificato finale; la verifica della catena può fallire anche per una CA intermedia scaduta. Un errore di rete non dimostra che il certificato sia scaduto: può dipendere da DNS, firewall, porta o servizio. Quando TLS consente di leggere il certificato, questo rimane disponibile per la diagnosi anche se non è fidato, è scaduto o appartiene a un altro nome; l'esito complessivo segnala comunque che la verifica non è riuscita.

La fiducia usa le CA disponibili a OpenSSL per il processo. In una rete aziendale puoi rendere disponibile un file PEM di CA tramite `CERTIFICATI_TLS_CA_FILE` all'avvio del programma; questa opzione riguarda il controllo HTTPS e non modifica l'archivio CA del sistema né la configurazione SMTP. Non è impostata automaticamente dal progetto. Non vengono recuperate CA aggiuntive dagli indirizzi AIA: una Root CA spesso non viene inviata dal server, mentre le intermedie dovrebbero essere presenti nella catena offerta.

Il controllo online **non aggiunge righe al registro**. Puoi prima consultare il risultato e scaricare il bundle pubblico ricevuto, quindi scegliere **Aggiungi al registro**. Download e importazione usano la stessa acquisizione, conservata in memoria per 10 minuti nella sessione del programma, senza ricontattare il server; vengono mantenute al massimo 8 acquisizioni recenti. Dopo la scadenza della sessione o il riavvio ripeti la verifica. Il bundle contiene il certificato finale e la catena effettivamente presentata: non include chiavi private e non aggiunge una Root CA che il server non ha inviato.

Avviando il controllo dal dettaglio di un certificato, il confronto dell'impronta indica se il certificato esposto è **uguale** o **cambiato** rispetto alla voce selezionata. L'importazione di un duplicato conserva referenti e storico. Importare un certificato diverso crea una nuova voce; per registrarlo come sostituzione e trasferire i referenti usa il flusso di rinnovo del vecchio certificato.

## Monitoraggio periodico dei servizi

Puoi associare a ogni certificato finale attivo uno o più indirizzi HTTPS da controllare periodicamente, fino a **100 URL totali nel registro**. Ogni configurazione comprende URL o hostname, frequenza e stato attivo o in pausa. La frequenza predefinita è **15 minuti**, modificabile da 1 a 1440 minuti. I controlli partono dal backend mentre resta attivo il comando `serve` (avvio normale) oppure `watch`, anche con il browser chiuso; i comandi singoli non mantengono il monitoraggio. Le acquisizioni TLS sono eseguite in processi separati per mantenere disponibile l'interfaccia durante l'attesa di rete.

Importando un certificato dalla verifica online viene predisposto automaticamente un monitor sullo stesso indirizzo, con frequenza di 15 minuti. Se esiste già un monitor per quel certificato e indirizzo, la configurazione resta invariata, anche quando è in pausa. L'importazione manuale da file non avvia monitor: aggiungi gli indirizzi che vuoi sorvegliare. **Controlla ora** anticipa la verifica di un monitor attivo; un monitor in pausa deve prima essere riattivato.

Il confronto usa l'impronta del certificato associato nel registro. Il monitor distingue servizio non raggiungibile, errore TLS, certificato differente ed errori di verifica. L'errore ripetuto nelle stesse condizioni non crea nuovi avvisi a ogni controllo; un ulteriore cambiamento dell'impronta genera un nuovo evento. Quando il servizio torna regolare, viene registrato un evento di ripristino. Il primo controllo riuscito non crea un avviso di errore.

Configurazioni, ultimo esito e avvisi sono conservati in SQLite e rimangono disponibili dopo il riavvio. Puoi segnare gli avvisi come letti senza modificare il monitor. Gli eventi sono visibili nella dashboard e possono comparire nelle notifiche desktop facoltative con la pagina aperta; **non alimentano la coda email**. La configurazione SMTP riguarda i promemoria di scadenza e la distribuzione dei certificati ai referenti.

Registrando un rinnovo dal vecchio certificato, i monitor vengono associati alla nuova voce e il confronto usa la nuova impronta. Questa operazione **non installa il certificato sul servizio**: finché il sito espone il precedente, il monitor può correttamente segnalarlo come differente. L'installazione e la verifica operativa restano a carico del referente tecnico.

## Referenti e promemoria

Apri il dettaglio di un certificato e aggiungi le persone nelle due sezioni:

- **Referenti**: ricevono i promemoria di scadenza.
- **Referenti tecnici**: ricevono il certificato pubblico firmato e la catena disponibile dopo il rinnovo.

Puoi inserire più destinatari per ogni ruolo. L'email è obbligatoria; il nome è facoltativo. Premi **Salva referenti** per applicare aggiunte e rimozioni, anche quando vuoi svuotare entrambe le liste. Per ricevere entrambi i tipi di messaggio, assegna la persona a entrambi i ruoli. La rimozione di un destinatario elimina i suoi messaggi in attesa o non riusciti dalla coda pertinente.

Il server controlla scadenze e coda ogni 60 secondi, anche con la scheda del browser chiusa. Gli avvisi restano visibili nella dashboard. Le notifiche desktop sono facoltative, richiedono il consenso e funzionano con questa pagina aperta. Il programma deve rimanere in esecuzione; al riavvio recupera la soglia più urgente raggiunta.

Le soglie sono durate esatte di 24 ore: l'avviso dei 30 giorni scatta quando mancano al massimo `30 × 24` ore. Se il primo controllo avviene a 10 giorni dalla scadenza, viene registrato l'avviso dei 15 giorni; quelli dei 45 e 30 giorni sono superati. Alla scadenza viene creato un ultimo avviso. I controlli successivi e i riavvii non ripetono le soglie già registrate.

Le email di scadenza sono preparate per ciascun referente, con prevenzione dei duplicati per certificato, destinatario e soglia. Se più soglie vengono superate mentre l'invio è inattivo, la coda conserva quella più urgente pertinente, evitando di accumulare vecchi promemoria da inviare in seguito.

## Registrare un rinnovo

Il rinnovo viene prima ottenuto dalla propria autorità di certificazione. Nel dettaglio del vecchio certificato:

1. Aggiungi e salva i referenti, inclusi quelli tecnici.
2. Premi **Carica certificato rinnovato** e scegli il nuovo certificato firmato, in PEM o DER. Un bundle PEM può includere la sua catena.
3. Il programma verifica il rinnovo, conserva i referenti sulla nuova voce e contrassegna la vecchia come sostituita. I suoi messaggi in attesa o non riusciti vengono rimossi; non genera altri promemoria di scadenza.
4. Per ogni referente tecnico viene preparata un'email con il certificato pubblico rinnovato e la catena disponibile in allegato PEM. Con SMTP non configurato le email restano in attesa.

Il file di rinnovo deve contenere un solo certificato finale, oltre alle eventuali CA. Deve essere già valido, non scaduto, avere una scadenza successiva a quella precedente e mantenere lo stesso insieme di identità DNS/IP dei SAN; in assenza di tali identità si usa il CN come confronto. Non è consentito rinnovare una voce CA o già sostituita con questo flusso.

Il rinnovo riesce anche senza referenti tecnici. Aggiungili e salvali successivamente, poi usa **Prepara email ai tecnici**. La distribuzione manuale evita nuovi duplicati per lo stesso certificato e destinatario. **Scarica certificato e catena** consente di ottenere direttamente il bundle pubblico disponibile.

Importare il nuovo file dalla normale area di caricamento lo aggiunge al registro; per collegarlo al vecchio certificato e sostituirlo usa il pulsante di rinnovo nel dettaglio.

## Coda email e configurazione SMTP

La sezione **Coda email** mostra destinatario, oggetto, tipo, stato, tentativi ed eventuale errore. Puoi scaricare ogni messaggio con **Scarica .eml** per esaminarlo. Senza mittente configurato, l'anteprima usa l'indirizzo segnaposto `certificati@localhost.invalid`.

Gli stati sono **In attesa**, **Invio in corso**, **Inviata** e **Non riuscita**. Solo una risposta positiva del server SMTP produce lo stato Inviata; indica l'accettazione da parte del server, non la consegna nella casella del destinatario. Gli errori vengono ritentati con attese crescenti, fino a 5 tentativi automatici. **Rimetti in coda** azzera i tentativi di un messaggio non riuscito. Un'interruzione dopo l'accettazione SMTP ma prima del salvataggio dell'esito può comportare un duplicato: non è garantito l'invio esattamente una volta.

Nella pagina **Coda email**, apri **Configurazione server SMTP** e indica host, porta, modalità di sicurezza, indirizzo mittente e le eventuali credenziali. Le modalità ammesse sono **STARTTLS** (di solito porta 587) e **TLS implicito** (di solito porta 465). Non è disponibile l’invio in chiaro. Username e password devono essere entrambi presenti oppure entrambi assenti, per i relay che non richiedono autenticazione.

**Verifica connessione** prova i dati attualmente inseriti: verifica il collegamento TLS e l’autenticazione, quando configurata, senza salvare le modifiche, senza inviare email e senza elaborare la coda. **Salva configurazione** conserva i dati. Se selezioni **Abilita invio automatico**, i messaggi in coda potranno essere inviati dal ciclo del programma; deselezionalo e salva per sospendere gli invii senza perdere le impostazioni.

La password non viene restituita dalle API né precompilata nel browser. Lascia il campo vuoto per conservarla quando server, porta, sicurezza e username restano invariati; se modifichi uno di questi dati, reinseriscila. Per cancellarla usa **Rimuovi password memorizzata** e lascia vuoto anche lo username se non vuoi autenticazione. Non vengono salvate password nello storage del browser.

I dati risiedono nell’archivio SQLite; la password è cifrata con AES-256-GCM. La chiave locale di 32 byte è conservata accanto al database nel file `<archivio>.smtp.key`, leggibile e scrivibile soltanto dal suo proprietario (permessi 0600). Nei backup conserva database e chiave, proteggendoli entrambi: la cifratura non protegge da chi può accedere a entrambi i file. Se la chiave manca, è alterata o ha permessi troppo ampi, il programma segnala l’errore e non la sostituisce per tentare la decifratura.

Le variabili seguenti restano supportate per gli avvii da terminale. Vengono usate soltanto finché nell’archivio non esiste una configurazione salvata dalla UI. Anche una configurazione salvata disabilitata prevale sulle variabili, così la pausa è rispettata.

| Variabile | Significato |
| --- | --- |
| `CERTIFICATI_SMTP_URL` | Endpoint, per esempio `smtp://host:587` oppure `smtps://host:465`, senza credenziali nell’URL. |
| `CERTIFICATI_SMTP_FROM` | Indirizzo email del mittente. |
| `CERTIFICATI_SMTP_USERNAME` | Nome utente per l’autenticazione, se richiesta. |
| `CERTIFICATI_SMTP_PASSWORD` | Password corrispondente, insieme allo username. |
| `CERTIFICATI_SMTP_CA_FILE` | File PEM di CA fidate per SMTP aziendali, opzionale; distinto da `CERTIFICATI_TLS_CA_FILE`, usato per le verifiche HTTPS. |

Le variabili devono essere disponibili al processo all’avvio. Per `smtp://` STARTTLS è obbligatorio; per `smtps://` viene usato TLS implicito. Il certificato e il nome del server vengono verificati e TLS deve essere almeno 1.2. Il progetto usa le API libcurl per [SMTP con TLS](https://curl.se/libcurl/c/smtp-tls.html) e per [provare un collegamento senza trasferire messaggi](https://curl.se/libcurl/c/CURLOPT_CONNECT_ONLY.html).

Una volta configurato il trasporto, la coda viene elaborata dal ciclo automatico, dal pulsante **Elabora coda** o dai comandi `check` e `watch`. Senza configurazione non avvengono tentativi SMTP e i messaggi restano disponibili per la revisione.

## Comandi da terminale

```sh
./certificati import sito.pem
./certificati import sito.pem altro.der catena.pem
./certificati list
./certificati show 1
./certificati check
./certificati watch --interval 60
./certificati remove 1
./certificati help
```

L'opzione `--db PERCORSO` precede il comando. `list` mostra le voci non sostituite; `show ID` permette di consultare una voce specifica. `check` esegue un controllo di scadenze e coda; `watch` lo ripete e controlla anche gli URL configurati, senza aprire il server web. L'opzione `watch --interval` stabilisce la frequenza dei promemoria e della coda email; ogni monitor URL mantiene il proprio intervallo salvato nel registro. I nuovi promemoria sono scritti nel terminale e salvati nello stesso archivio della dashboard. Gestione referenti e rinnovo sono disponibili dall'interfaccia web.

## Dati, migrazione e backup

Sono accettati certificati X.509 PEM, bundle PEM contenenti esclusivamente certificati e singoli certificati DER. Un bundle viene importato interamente oppure respinto. Sono rifiutati chiavi private, PKCS#12/PFX e dati estranei. Il database conserva i metadati, i certificati **pubblici** in PEM, i referenti, i promemoria e la coda email; non conserva chiavi private. Il download PEM e gli allegati usano soltanto materiale pubblico.

I duplicati sono riconosciuti tramite impronta SHA-256. Reimportare un certificato aggiorna la sorgente e rende disponibile il PEM senza perdere i suoi riferimenti o lo storico degli avvisi.

Un archivio delle versioni precedenti viene migrato automaticamente allo schema v4 mantenendo metadati, referenti e storico già disponibili. La migrazione aggiunge le tabelle dei monitor, dei relativi eventi e della configurazione SMTP; non avvia controlli periodici sulle vecchie voci finché non vengono configurati. Le vecchie voci prive di PEM sono indicate come legacy: reimporta i file originali, insieme alle CA disponibili, per abilitare ricostruzione della catena, download e distribuzione.

L'eliminazione di un certificato rimuove anche referenti, storico dei promemoria e messaggi della coda associati; non cancella il file originale sul computer. Per un backup arresta tutti i processi che usano l'archivio e copia il file `.db` prima di riavviare. È consigliabile fare una copia anche prima di aggiornare una versione precedente.

## Compilazione e verifiche

Richiede un compilatore C11, OpenSSL, SQLite almeno 3.24, libcurl con supporto SMTP/TLS, `pkg-config` e Python 3. Python incorpora l'interfaccia nell'eseguibile durante la compilazione e viene usato dai test insieme al comando `openssl`; le verifiche dell'interfaccia usano anche Node.js. L'eseguibile compilato non richiede Python, Node.js né file web esterni.

```sh
make test
```

La suite comprende test C sulle soglie, i destinatari e la coda, e test di integrazione Python su importazione PEM/DER/bundle, migrazione, catene CA, referenti multipli, rinnovo e sostituzione, distribuzione pubblica, deduplicazione, anteprime `.eml`, eliminazione e API HTTP con controlli CSRF e Host. La suite online avvia server TLS locali con CA temporanee e controlla fiducia, nomi, scadenze, errori TCP/TLS e importazione della stessa acquisizione scaricabile. I test dei monitor verificano controlli automatici, cambiamenti, ripristini, deduplicazione degli avvisi, persistenza, rinnovo e disponibilità dell'interfaccia durante un collegamento TLS bloccato. I test delle pagine verificano i sette indirizzi diretti, la separazione dei contenuti, la navigazione e le intestazioni di sicurezza. I test SMTP verificano cifratura e conservazione delle password, migrazione, configurazione via API, priorità sulla configurazione ambiente e collegamenti TLS autenticati senza invio durante la prova. I test usano database e certificati temporanei, non richiedono SMTP reale e non contattano siti pubblici.

Per provare un eseguibile alternativo:

```sh
CERTIFICATI_BIN=/percorso/certificati python3 tests/integration.py
CERTIFICATI_BIN=/percorso/certificati python3 tests/remote_integration.py
CERTIFICATI_BIN=/percorso/certificati python3 tests/monitor_integration.py
CERTIFICATI_BIN=/percorso/certificati python3 tests/ui_pages.py
CERTIFICATI_BIN=/percorso/certificati python3 tests/smtp_integration.py
```

Riferimenti delle librerie: [date ASN.1 di OpenSSL, inclusa `ASN1_TIME_to_tm`](https://docs.openssl.org/3.0/man3/ASN1_TIME_set/), [lettura PEM di OpenSSL](https://docs.openssl.org/3.0/man3/PEM_read_bio_PrivateKey/) e [vincoli di chiave esterna SQLite](https://sqlite.org/foreignkeys.html).
