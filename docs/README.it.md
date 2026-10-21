# Certificate Manager — guida italiana

[English overview](../README.md) · [Workflow spiegato](WORKFLOW.it.md) · [Licenza MIT](../LICENSE) · [Pubblicazione su GitHub](PUBLISHING.md)

Programma in C con interfaccia web e archivio SQLite locale. Importa certificati X.509, estrae i dati utili, segue le scadenze e gestisce più referenti per ogni certificato. I promemoria predefiniti sono a **45, 30, 15 e 2 giorni**, più un avviso alla scadenza; le soglie sono personalizzabili per certificato. Il rinnovo mantiene attivi insieme il certificato precedente e quello nuovo durante la distribuzione.

La pagina **Coda email** consente di configurare SMTP, verificare la connessione e attivare o mettere in pausa l’invio. Alla prima installazione il trasporto è disabilitato: i messaggi restano in coda e possono essere scaricati come `.eml`.

L’interfaccia è disponibile in **inglese, italiano, francese, spagnolo, cinese semplificato e giapponese**. Scegli la lingua dal selettore nell’interfaccia. I dati dei certificati, i nomi dei referenti e gli altri contenuti inseriti dall’utente mantengono la propria forma originale. I comandi da terminale e i testi dei messaggi email generati rimangono in italiano.

Il progetto usa la licenza **MIT** ed è predisposto per la pubblicazione del codice sorgente su GitHub come **Certificate Manager**. Il server resta uno strumento locale senza autenticazione utenti: per impostazione predefinita ascolta su `127.0.0.1`; Docker Compose pubblica la porta soltanto sull’indirizzo locale del computer. Non è pronto per l’esposizione diretta in rete. Vedi [SECURITY.md](../SECURITY.md) e la [guida alla pubblicazione](PUBLISHING.md).

## Workflow

Il percorso operativo è: **acquisizione del certificato → registro e referenti → controlli di scadenza e degli URL → rinnovo → distribuzione ai tecnici → installazione sul servizio e verifica**.

Il browser dialoga con le API del backend C, che legge e aggiorna SQLite. Il backend esegue i controlli periodici, interroga i servizi HTTPS e prepara la coda email. Le scadenze producono messaggi per i referenti; i rinnovi producono allegati PEM per i tecnici; le anomalie e i ripristini dei servizi compaiono nell’interfaccia e, se abilitato per il monitor, producono email per i destinatari scelti. I tecnici installano il certificato sul servizio esternamente al programma.

La pagina **Workflow** (`/workflow`) presenta i diagrammi e la spiegazione direttamente nell’interfaccia, in tutte e sei le lingue e senza dipendenze esterne. La [spiegazione completa del workflow](WORKFLOW.it.md) contiene i diagrammi dei componenti e del rinnovo, le frequenze, i ruoli e un esempio operativo. È disponibile anche [in inglese](WORKFLOW.md).

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

Apri [http://127.0.0.1:8080](http://127.0.0.1:8080) e carica i file `.pem`, `.crt`, `.cer` o `.der`, anche più file insieme. Il formato viene riconosciuto dal contenuto; il limite è 16 MiB per file. Il server nativo ascolta su `127.0.0.1` per impostazione predefinita.

Per scegliere un altro archivio o un'altra porta:

```sh
./certificati --db archivio.db serve --port 8090
```

L'archivio predefinito è `certificati.db` nella cartella da cui avvii il programma. Le cartelle del percorso scelto devono già esistere. I dati rimangono disponibili dopo il riavvio. Premi `Ctrl+C` nel terminale per arrestare il programma.

## Avvio con Docker Compose

Installa Docker Engine con il [plugin Compose](https://docs.docker.com/compose/gettingstarted/) oppure Docker Desktop. Dalla cartella del progetto clonato esegui:

```sh
docker compose up --build -d
docker compose logs -f certificate-manager
```

Apri [http://127.0.0.1:8080](http://127.0.0.1:8080). Se il programma nativo sta già usando la porta 8080, avvia il container su un’altra porta:

```sh
CERTIFICATI_PORT=8081 docker compose up --build -d
```

In questo caso apri [http://127.0.0.1:8081](http://127.0.0.1:8081). Usa lo stesso valore di `CERTIFICATI_PORT` quando ricompili o ricrei il servizio. Compose mantiene uguale la porta interna e quella del computer per rispettare i controlli Host/Origin dell’interfaccia.

Il Dockerfile compila il programma in uno stadio dedicato e lo esegue con utente senza privilegi, UID/GID `10001:10001`. Il filesystem del container è in sola lettura, con `/tmp` temporanea e `/data` persistente. Il volume nominato `certificate-data` conserva insieme `/data/certificati.db` e la sua chiave `.smtp.key`. Al primo avvio il registro è vuoto: il database del programma nativo non viene importato automaticamente.

```sh
# Ricompila e applica gli aggiornamenti, conservando il volume dei dati.
docker compose up --build -d

# Arresta e rimuove container e rete, conservando il volume dei dati.
docker compose down
```

Se usi una porta diversa, indica `CERTIFICATI_PORT` anche nel comando di aggiornamento, come nell’esempio precedente. Anche `docker compose stop` conserva i dati. **`docker compose down -v` elimina il volume e tutti i dati del registro**: usalo soltanto per cancellare intenzionalmente l’installazione.

Configura SMTP dalla pagina **Coda email**. Dentro il container, `localhost` indica il container stesso: usa il nome di un server SMTP raggiungibile dalla sua rete. Per le CA aziendali aggiungi al servizio un mount in sola lettura e la variabile `CERTIFICATI_TLS_CA_FILE` o `CERTIFICATI_SMTP_CA_FILE` appropriata; vedi [verifica HTTPS](#recuperare-un-certificato-da-url-o-cn) e [configurazione SMTP](#coda-email-e-configurazione-smtp).

Il server ascolta su `0.0.0.0` dentro il container per ricevere le connessioni inoltrate da Docker; Compose pubblica la porta **soltanto su 127.0.0.1 del computer**. Mantieni questo indirizzo: l’interfaccia continua a non avere autenticazione utenti. Vedi [SECURITY.md](../SECURITY.md).

### Backup dei dati del container

Arresta il servizio e archivia il volume completo, comprendendo database e chiave della password SMTP:

```sh
docker compose stop certificate-manager
umask 077
docker compose run -T --rm --no-deps --entrypoint /bin/sh certificate-manager -c 'tar -C /data -czf - .' > certificate-manager-backup.tar.gz
docker compose start certificate-manager
```

Conserva l’archivio in un luogo privato. In caso di ripristino mantieni proprietario `10001:10001` e permessi `0600` sulla chiave `.smtp.key`. Esegui un backup prima degli aggiornamenti e non aggiungere l’archivio a Git.

## Navigazione dell’interfaccia

L’interfaccia è suddivisa in **dieci pagine**, ciascuna con il proprio indirizzo e soltanto i controlli della funzione scelta. Il menu laterale apre la pagina corrispondente; su schermi piccoli mantiene le etichette e scorre orizzontalmente.

| Pagina | Indirizzo | Contenuto |
| --- | --- | --- |
| Panoramica | `/` | Contatori, scadenze entro 45 giorni e anomalie dei servizi. |
| Certificati | `/certificati` | Registro, ricerca, filtri e dettagli con referenti e rinnovo. |
| Servizi monitorati | `/servizi` | Configurazione degli URL, ultimi esiti e avvisi periodici. |
| Importa certificati | `/importa` | Anteprima dei file PEM, DER, CRT e CER e inventario di URL da CSV. |
| Rinnovi | `/rinnovi` | Agenda delle pratiche, filtri per fase, responsabile e ritardo. |
| Verifica endpoint | `/verifica` | Recupero e confronto del certificato esposto da un servizio. |
| Promemoria | `/promemoria` | Scadenze registrate e preferenze delle notifiche desktop. |
| Coda email | `/email` | Messaggi preparati, stato degli invii e download `.eml`. |
| Workflow | `/workflow` | Diagrammi e spiegazione di acquisizione, controlli, rinnovo e invii. |
| Rubrica | `/rubrica` | Persone, gruppi e assegnazioni riutilizzabili sui certificati. |

Ogni indirizzo può essere aperto direttamente, aggiunto ai preferiti o ricaricato. Puoi usare Indietro e Avanti del browser. Ricerca e filtri del registro vengono ricordati nella stessa scheda. Salva le modifiche ai referenti e ai monitor prima di cambiare pagina; il cambio pagina carica un documento nuovo.

## Caricamento guidato e inventario CSV

In **Importa certificati**, seleziona uno o più file per vedere un’anteprima di dominio, SAN, CA, date, impronta SHA-256, duplicati e possibili rinnovi. Il salvataggio richiede una conferma. I candidati al rinnovo devono avere identità DNS/IP compatibili e scadenza precedente: la sola uguaglianza del CN non basta. Gli avvisi sulle catene incomplete mostrano l’emittente da cercare e permettono di tornare al caricamento per aggiungere le CA disponibili; non vengono scaricate CA automaticamente.

La stessa pagina permette di incollare un CSV o caricare un file fino a **1 MiB**, con al massimo **100 righe di dati**. La colonna `url` è obbligatoria; quelle dei referenti sono facoltative:

```csv
url,business_name,business_email,technical_name,technical_email
https://servizio.example.test,Responsabile,referente@example.test,Operazioni,tecnico@example.test
```

Per più destinatari nella stessa cella, separa nomi e indirizzi email con punto e virgola, mantenendo lo stesso ordine. Sono supportate le virgolette CSV. Scegli il separatore del file fra virgola, punto e virgola e tabulazione; con **Associa colonne** puoi collegare intestazioni diverse ai cinque campi previsti o ignorare colonne aggiuntive.

1. Usa **Valida CSV** per vedere una tabella con numeri di riga originali, valori ed errori per campo. Puoi correggere una riga direttamente nell’anteprima e scaricare il CSV corretto o il report degli esiti.
2. Seleziona tutte le righe oppure soltanto quelle valide. **Verifica URL** salva un lotto persistente: il backend verifica gli indirizzi e prepara un piano, senza importare automaticamente.
3. Apri il riepilogo e controlla nuovo certificato o duplicato, CA, date, monitor e referenti aggiunti/conservati. Per la stessa email con nomi diversi scegli esplicitamente se mantenere il nome della rubrica o aggiornarlo; il riepilogo mostra i certificati collegati alla persona.
4. Approva le righe pronte da importare. Il worker ripete l’acquisizione e richiede l’impronta esaminata. Cambiamenti incompatibili nel registro richiedono un nuovo piano e una nuova approvazione.
5. Per ciascuna riga, certificati, monitor, persone, assegnazioni, audit e ricevuta contro i duplicati vengono salvati insieme. Un errore annulla quella riga; non annulla quelle già riuscite.

Il lotto prosegue anche chiudendo la scheda, purché il processo `serve` o `watch` rimanga attivo; dopo un riavvio può riprendere le righe in sospeso. La sezione dei lotti salvati permette di consultare avanzamento ed esiti, mettere in pausa, ripianificare e scaricare report o sole righe da correggere. Pianificare non equivale ad approvare l’importazione. La guida ai [20 miglioramenti dei flussi](WORKFLOW-IMPROVEMENTS.it.md) descrive i passaggi e i limiti.

## Registro, ricerca e catena

Il registro mostra subito dopo il dominio la **Scadenza**, i **Referenti** e i **Referenti tecnici**, con nomi ed email. I pulsanti **Gestisci** aprono il dettaglio direttamente nella sezione dei destinatari. Sono inoltre disponibili stato, Root CA, CA intermedie, inizio validità e giorni residui. Su schermi stretti ogni riga diventa una scheda con gli stessi dati, senza scorrimento orizzontale. I dettagli comprendono anche SAN, emittente, numero di serie, impronta SHA-256, chiave pubblica e algoritmo di firma.

La ricerca comprende dominio, CA, date, referente e nome del file. I filtri consentono di vedere tutti i certificati, quelli validi nel tempo, gli scaduti e quelli non ancora validi. **Referente** e **Referente tecnico** mostrano le persone assegnate, identificate dall'email e distinte per ruolo: scegli una persona per vedere i suoi certificati. Puoi combinare i due filtri con stato e ricerca; ogni risultato deve rispettare tutte le selezioni. **Azzera filtri** ripristina il registro completo delle voci attive. Le selezioni restano memorizzate nella stessa scheda del browser, anche cambiando pagina. I certificati archiviati dopo la chiusura del rinnovo o il ritiro manuale sono nascosti: seleziona **Mostra sostituiti** per consultarli. Il caricamento del rinnovo mantiene visibili e attivi sia il precedente sia il nuovo, anche con lo stesso CN; le schede riepilogative escludono soltanto gli archiviati.

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

Configurazioni, ultimo esito e avvisi sono conservati in SQLite e rimangono disponibili dopo il riavvio. Puoi segnare gli avvisi come letti senza modificare il monitor. Gli eventi sono visibili nella dashboard e possono comparire nelle notifiche desktop facoltative con la pagina aperta. Per ciascun monitor puoi inoltre **abilitare gli avvisi email** e scegliere i destinatari: nuovi eventi di anomalia e ripristino entrano nella coda, senza ripetere errori identici. L’opzione inizialmente è disabilitata e la sua attivazione non reinvia lo storico.

Per ciascun monitor puoi impostare da **1 a 10 errori di raggiungibilità consecutivi** prima dell’avviso email; il valore predefinito è uno. Gli esiti tecnici sono comunque visibili subito. Errori TLS e impronte inattese non attendono questa soglia. Una finestra di manutenzione sospende i nuovi avvisi email di anomalia/ripristino, conserva i controlli e gli eventi e richiede un controllo fresco alla fine. Un monitor in pausa deve comunque essere riattivato.

Puoi prendere in carico un evento indicando responsabile, note, termine e stato aperto/in analisi/risolto. Questo stato organizzativo non modifica il risultato tecnico. Per un certificato cambiato, il dettaglio dell’evento conduce alla verifica online: acquisisci nuovamente, confronta e importa esplicitamente, poi collega un rinnovo solo se compatibile. Nessun evento approva automaticamente un’impronta.

Il caricamento o collegamento di un rinnovo **lascia i monitor associati al precedente**. Durante la transizione vengono riconosciute sia la sua impronta sia quelle dei rinnovi esplicitamente approvati nelle fasi firmato, consegnato o installazione. La verifica di fiducia, nome e validità TLS resta obbligatoria per tutti. Un certificato diverso e non approvato rimane un cambiamento inatteso. Soltanto la chiusura verificata del rinnovo trasferisce i monitor al nuovo certificato.

## Referenti e promemoria

Apri il dettaglio di un certificato e aggiungi le persone nelle due sezioni:

- **Referenti**: ricevono i promemoria di scadenza.
- **Referenti tecnici**: ricevono il certificato pubblico firmato e la catena disponibile dopo il rinnovo.

Puoi inserire più destinatari per ogni ruolo. L'email è obbligatoria; il nome è facoltativo. Premi **Salva referenti** per applicare aggiunte e rimozioni, anche quando vuoi svuotare entrambe le liste. Per ricevere entrambi i tipi di messaggio, assegna la persona a entrambi i ruoli. La rimozione di un destinatario elimina i suoi messaggi in attesa o non riusciti dalla coda pertinente.

La pagina **Rubrica** (`/rubrica`) centralizza persone e gruppi. Prima di una modifica condivisa mostra i certificati interessati, i messaggi in attesa e i destinatari dei monitor collegati: puoi esaminarli prima di continuare, insieme a dati e appartenenze prima/dopo e all’impatto proposto sui certificati. Puoi assegnarli a più certificati con il ruolo desiderato. La modifica di un indirizzo email o dei membri di un gruppo si riflette sulle assegnazioni collegate e sui destinatari degli invii ancora in attesa; lo storico degli invii conclusi viene conservato.

Nel dettaglio del certificato puoi cambiare le soglie con numeri distinti da **0 a 3650 giorni**, includendo sempre `0` per la scadenza, oppure sospendere la regola. Le soglie dei filtri di ricerca restano 45/30/15/2 giorni. Puoi indicare un destinatario di escalation e un ritardo da **0 a 365 giorni dal primo promemoria registrato**. L’escalation non si ripete per lo stesso certificato e destinatario; continua finché il certificato resta attivo, anche se è già stato caricato un rinnovo.

**Simula promemoria** mostra il calendario previsto, le soglie già registrate o superate, i destinatari e l’escalation usando i dati del modulo, senza salvare regole né creare email. Nella pagina **Promemoria** puoi salvare modelli riutilizzabili: seleziona i certificati attivi, indica le eccezioni e approva il riepilogo prima/dopo. Se la regola o il registro cambiano, rigenera l’anteprima prima di applicare.

Il server controlla scadenze e coda ogni 60 secondi, anche con la scheda del browser chiusa. Gli avvisi restano visibili nella dashboard. Le notifiche desktop sono facoltative, richiedono il consenso e funzionano con questa pagina aperta. Il programma deve rimanere in esecuzione; al riavvio recupera la soglia più urgente raggiunta.

Con le impostazioni predefinite, le soglie sono durate esatte di 24 ore: l'avviso dei 30 giorni scatta quando mancano al massimo `30 × 24` ore. Se il primo controllo avviene a 10 giorni dalla scadenza, viene registrato l'avviso dei 15 giorni; quelli dei 45 e 30 giorni sono superati. Alla scadenza viene creato un ultimo avviso. I controlli successivi e i riavvii non ripetono le soglie già registrate.

Le email di scadenza sono preparate per ciascun referente, con prevenzione dei duplicati per certificato, destinatario e soglia. Se più soglie vengono superate mentre l'invio è inattivo, la coda conserva quella più urgente pertinente, evitando di accumulare vecchi promemoria da inviare in seguito.

## Pianificare e completare un rinnovo

Per uno stesso CN possono esserci **due o più certificati validi contemporaneamente**, ciascuno con la propria impronta SHA-256. Validità X.509 e impiego operativo sono separati: il precedente può essere **In uso** mentre il nuovo è **Pronto** o **In distribuzione**. **Ritirato** indica una voce archiviata, anche se non ancora scaduta.

La pagina **Rinnovi** (`/rinnovi`) raccoglie tutte le pratiche nell’agenda, filtrabili per fase, responsabile e ritardo operativo. Nel dettaglio del certificato scegli fra tutte le pratiche aperte e concluse. Il confronto fra precedente e candidato mostra CN, SAN, CA, date, impronta e algoritmi prima del collegamento.

Nel dettaglio del certificato apri la pratica di rinnovo e registra data della richiesta, rinnovo previsto, installazione prevista, responsabile e note. Sono scadenze organizzative: non cambiano le date X.509 del certificato. Le fasi della pratica sono **Da richiedere → In attesa della CA → Firmato → Consegnato → In installazione → Verificato**. Cambiare una fase descrittiva non richiede un certificato alla CA, non invia un’email e non dimostra l’installazione.

1. Aggiungi e salva referenti e referenti tecnici, anche dalla rubrica.
2. Ottieni il certificato firmato dalla CA. Usa **Carica certificato rinnovato**, conferma un candidato proposto nell’anteprima oppure collega una voce compatibile già presente nel registro.
3. Il nuovo certificato deve essere già valido, non scaduto, con scadenza successiva e lo stesso insieme di identità DNS/IP nei SAN; in loro assenza si usa il CN. Il file di rinnovo contiene un solo certificato finale, oltre alle eventuali CA. Le voci CA o già archiviate non sono ammesse come predecessori.
4. Il backend collega le voci, riusa una pratica aperta senza sostituto e copia referenti, origini delle assegnazioni ai gruppi ed eventuale regola promemoria. Prepara per i tecnici un’email con certificato pubblico e catena disponibile. **Il precedente resta attivo con i suoi monitor e promemoria.** Con SMTP disabilitato i messaggi restano in coda.
5. Il tecnico installa il nuovo certificato sui servizi con gli strumenti previsti per l’infrastruttura. Gli endpoint possono essere aggiornati in giorni diversi: la pratica mostra la verifica separata di ciascuno.
6. Dopo l’installazione, richiedi la verifica di un singolo endpoint oppure di tutti. Un’osservazione automatica precedente alla richiesta non basta. I servizi in pausa devono essere riattivati.
7. Consulta la **checklist prima della chiusura**, che spiega per ogni endpoint pause, richieste o prove mancanti/vecchie, TLS fallito, impronta errata, associazioni cambiate e URL duplicati. La checklist e la chiusura usano le stesse condizioni del server. Aggiornare la checklist non avvia una verifica TLS. **Completa pratica** riesce soltanto quando ogni endpoint associato presenta l’impronta nuova, supera tutte le verifiche TLS e ha richiesta ed esito positivo negli ultimi **15 minuti**. Se la prova è vecchia, richiedila di nuovo. La chiusura trasferisce i monitor verificati al nuovo certificato e archivia il precedente soltanto se non conserva altre associazioni; a quel punto cessano i suoi promemoria e vengono rimossi gli invii ancora in attesa o non riusciti.

Se non esistono endpoint, la pratica non può dichiarare un’installazione verificata. È disponibile un **ritiro manuale** distinto, con responsabile e nota esplicita, solo quando il precedente non ha più monitor associati, compresi quelli in pausa. Lo stato finale è **Ritirato**, non **Verificato**. Lo stesso principio mantiene distinguibili gli archivi storici migrati.

La pratica include un pannello di consegna per destinatario tecnico, con stato, tentativi, errori, download `.eml` e ritentativo dei soli messaggi non riusciti. L’accettazione SMTP non dimostra ricezione né installazione. Puoi scaricare un verbale JSON con dati correnti e, dopo la chiusura, la prova catturata prima di trasferire i monitor o ritirare il precedente. La prova catturata non cambia con le osservazioni successive; l’eliminazione della pratica può rimuoverla. La cronologia della pagina Workflow registra operazioni locali senza identità autenticata né garanzia antimanomissione.

Il rinnovo riesce anche senza referenti tecnici. Puoi aggiungerli in seguito e usare **Prepara email ai tecnici**; la distribuzione evita duplicati per certificato e destinatario. **Scarica certificato e catena** restituisce il bundle pubblico disponibile. Il programma non emette, firma o installa certificati e non conserva chiavi private TLS.

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

Un archivio delle versioni precedenti viene migrato automaticamente allo schema **v6**, mantenendo metadati, referenti e storico disponibili. Sono conservati pratiche, prove per endpoint, rubrica, gruppi e regole delle versioni precedenti; sono aggiunti lotti CSV persistenti, ricevute per riga, modelli di regole, gestione delle anomalie/manutenzioni, verbali di chiusura e audit. La cronologia registra nuove operazioni dalla migrazione, senza ricostruire azioni precedenti. Le sostituzioni già archiviate rimangono nello storico come ritiri pregressi, senza attribuire loro una verifica di installazione mai eseguita. La migrazione non avvia monitor sulle vecchie voci finché non vengono configurati. Le vecchie voci prive di PEM sono indicate come legacy: reimporta i file originali, insieme alle CA disponibili, per abilitare ricostruzione della catena, download e distribuzione.

L'eliminazione di un certificato rimuove anche referenti, storico dei promemoria e messaggi della coda associati; non cancella il file originale sul computer. Per un backup arresta tutti i processi che usano l’archivio e copia il file `.db` e la chiave `<archivio>.smtp.key`, quando presente, prima di riavviare. Proteggi entrambi e conserva la chiave con permessi `0600`. È consigliabile fare una copia anche prima di aggiornare una versione precedente.

## Compilazione e verifiche

Richiede un compilatore C11, OpenSSL, SQLite almeno 3.24, libcurl con supporto SMTP/TLS, `pkg-config` e Python 3. Python incorpora l'interfaccia nell'eseguibile durante la compilazione e viene usato dai test insieme al comando `openssl`; le verifiche dell'interfaccia usano anche Node.js. L'eseguibile compilato non richiede Python, Node.js né file web esterni.

```sh
make test
```

Le suite aggiuntive coprono rollback completo della riga CSV, conflitti dei piani, lotti persistenti, simulazione/modelli di regole, checklist condivisa, prove di chiusura conservate, prese in carico, manutenzioni e soglie degli errori. La suite comprende test C sulle soglie, i destinatari e la coda, e test di integrazione Python su importazione PEM/DER/bundle, migrazione, catene CA, referenti multipli, rinnovi sovrapposti, verifica fresca per endpoint, rubrica e gruppi, regole di escalation, avvisi email dei monitor, distribuzione pubblica, deduplicazione, anteprime `.eml`, eliminazione e API HTTP con controlli CSRF e Host. La suite online avvia server TLS locali con CA temporanee e controlla fiducia, nomi, scadenze, errori TCP/TLS e importazione della stessa acquisizione scaricabile. I test dei monitor verificano controlli automatici, cambiamenti, ripristini, deduplicazione degli avvisi, persistenza, rinnovo e disponibilità dell'interfaccia durante un collegamento TLS bloccato. I test delle pagine verificano i dieci indirizzi diretti, la separazione dei contenuti, la navigazione e le intestazioni di sicurezza. I test SMTP verificano cifratura e conservazione delle password, migrazione, configurazione via API, priorità sulla configurazione ambiente e collegamenti TLS autenticati senza invio durante la prova. I test usano database e certificati temporanei, non richiedono SMTP reale e non contattano siti pubblici.

Per provare un eseguibile alternativo:

```sh
CERTIFICATI_BIN=/percorso/certificati python3 tests/integration.py
CERTIFICATI_BIN=/percorso/certificati python3 tests/remote_integration.py
CERTIFICATI_BIN=/percorso/certificati python3 tests/monitor_integration.py
CERTIFICATI_BIN=/percorso/certificati python3 tests/lifecycle_integration.py
CERTIFICATI_BIN=/percorso/certificati python3 tests/ui_pages.py
CERTIFICATI_BIN=/percorso/certificati python3 tests/smtp_integration.py
```

Riferimenti delle librerie: [date ASN.1 di OpenSSL, inclusa `ASN1_TIME_to_tm`](https://docs.openssl.org/3.0/man3/ASN1_TIME_set/), [lettura PEM di OpenSSL](https://docs.openssl.org/3.0/man3/PEM_read_bio_PrivateKey/) e [vincoli di chiave esterna SQLite](https://sqlite.org/foreignkeys.html).
