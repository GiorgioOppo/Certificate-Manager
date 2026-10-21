# Workflow di Certificate Manager

[Panoramica del progetto](../README.md) · [Guida italiana](README.it.md) · [English version](WORKFLOW.md)

Certificate Manager segue i certificati pubblici dall’acquisizione al rinnovo, alla consegna e alla verifica dell’installazione. Per uno stesso CN possono restare validi più certificati: tra la firma del rinnovo e la sua installazione possono passare giorni. Ogni impronta SHA-256 identifica una voce distinta del registro.

La pagina **Workflow** (`/workflow`) presenta diagrammi dei componenti, del ciclo operativo e del rinnovo nelle sei lingue dell’interfaccia. Le dieci pagine comprendono anche **Rubrica** (`/rubrica`) per persone e gruppi condivisi e **Rinnovi** (`/rinnovi`) per l’agenda operativa. La [guida ai 20 miglioramenti](WORKFLOW-IMPROVEMENTS.it.md) raccoglie i flussi introdotti. L’eseguibile continua a chiamarsi `certificati`; vedi [installazione e Docker Compose](README.it.md#installazione-e-avvio).

## Come dialogano i componenti

```mermaid
flowchart TD
    User["Operatore nel browser"] <-->|HTTP locale e JSON| Backend["Backend C"]
    Files["File pubblici PEM o DER"] -->|Anteprima e conferma| Backend
    CSV["Inventario URL da CSV"] -->|Mappatura, correzione e selezione| Backend
    Backend <-->|Piani salvati e approvazione esplicita| Batch["Worker CSV persistente"]
    Batch <-->|Nuove verifiche TLS| Services
    Backend <-->|Lettura e scrittura| DB[("Registro e coda SQLite")]
    Backend -->|Lettura certificati e catene| X509["OpenSSL"]
    Backend <-->|Pianificazione ed esiti| Monitor["Processo di monitoraggio TLS"]
    Monitor <-->|DNS, TCP, TLS| Services["Servizi HTTPS"]
    Backend --> Rules["Regole scadenze ed escalation"]
    Rules --> DB
    Monitor -->|Email nuovi eventi se abilitate| DB
    DB --> Mail["Invio email con libcurl"]
    Mail -->|TLS verificato| SMTP["Server SMTP configurato"]
    SMTP --> Contacts["Referenti e referenti tecnici"]
```

Il browser invia richieste e aggiorna lo stato salvato ogni 30 secondi. Il backend gestisce validazione, pianificazione e persistenza in SQLite. Le operazioni di rete dei monitor avvengono in un processo separato, così un servizio TLS lento non occupa il gestore delle richieste web. Chiudere il browser lascia attivi i controlli del backend e i lotti CSV persistenti. Entrambi richiedono `serve` o `watch` in esecuzione; i lotti salvati possono riprendere dopo un riavvio. Pianificare un lotto non ne autorizza l’importazione.

| Parte | Responsabilità | Sorgente |
| --- | --- | --- |
| Interfaccia web | Dieci pagine, mappatura/correzione/report CSV, rubrica, agenda, checklist e gestione anomalie. | [`web/app.js`](../web/app.js), [`web/extensions.js`](../web/extensions.js), [`web/operations-ui.js`](../web/operations-ui.js), [`web/incidents-ui.js`](../web/incidents-ui.js) |
| Server HTTP | Pagine e API con controlli Host, Origin e token CSRF. | [`src/server.c`](../src/server.c) |
| Certificati e catene | Lettura X.509, importazione del materiale pubblico e ricostruzione delle CA disponibili. | [`src/app.c`](../src/app.c), [`src/certificate.c`](../src/certificate.c), [`src/chain.c`](../src/chain.c) |
| Ciclo del rinnovo | Collegamenti fra certificati sovrapposti, pianificazione, prove per endpoint e condizioni di chiusura. | [`src/lifecycle.c`](../src/lifecycle.c) |
| Rubrica e regole | Persone, gruppi, assegnazioni riutilizzabili, promemoria e anteprime senza modificare il registro. | [`src/workspace.c`](../src/workspace.c) |
| Worker CSV | Conserva piani e approvazioni, salva atomicamente ogni riga e riprende i lavori salvati. | [`src/inventory.c`](../src/inventory.c) |
| Operazioni dei flussi | Confronto certificati, impatto rubrica, simulazione regole, modelli e verbali di chiusura. | [`src/operations.c`](../src/operations.c), [`src/workflow_support.c`](../src/workflow_support.c) |
| Anomalie | Presa in carico, manutenzione e soglia degli errori consecutivi di raggiungibilità. | [`src/incident.c`](../src/incident.c) |
| Registro | Schema v6: certificati pubblici, piani, referenti, promemoria, eventi dei monitor, prove di installazione e coda. | [`src/store.c`](../src/store.c) |
| Verifiche degli endpoint | Recupero dei certificati e controlli di raggiungibilità, fiducia, nome, date e impronte approvate. | [`src/remote.c`](../src/remote.c), [`src/remote_service.c`](../src/remote_service.c), [`src/monitor.c`](../src/monitor.c) |
| Email | Messaggi per destinatario, deduplicazione degli eventi, tentativi e configurazione SMTP. | [`src/delivery.c`](../src/delivery.c), [`src/smtp_settings.c`](../src/smtp_settings.c) |

## 1. Esaminare, acquisire e registrare i certificati

**File di certificati.** Seleziona file PEM/DER o bundle PEM in **Importa certificati**. Prima di salvare, consulta CN, SAN, emittente, date di validità, impronta, Root CA e intermedie disponibili, duplicati e possibili predecessori. Gli avvisi sulla catena indicano l’emittente mancante e rimandano all’importazione per aggiungere i file CA disponibili. Non vengono recuperate CA automaticamente e caricare una Root CA non la rende fidata per le verifiche di rete.

L’anteprima usa un database temporaneo e non cambia il registro. Conferma l’importazione ordinaria oppure un collegamento di rinnovo proposto. Il candidato deve avere le stesse identità DNS/IP e una scadenza precedente; il CN viene usato quando mancano identità DNS/IP nei SAN. La sola presenza dello stesso CN non unisce automaticamente due voci. I duplicati di impronta conservano referenti e storico esistenti.

**Endpoint online.** Inserisci un URL HTTPS o un hostname risolvibile, eventualmente con porta. Per un CN wildcard serve un nome concreto. Il backend risolve DNS, apre TCP, negozia TLS con SNI dove applicabile e recupera la catena pubblica. Riporta separatamente fiducia, nome e validità; non richiede una pagina HTTP. Consulta o scarica il risultato, poi scegli esplicitamente di importarlo. Le acquisizioni temporanee durano fino a 10 minuti e ne restano disponibili al massimo otto. L’importazione online predispone un monitor a 15 minuti quando ammesso; quella da file non crea monitor.

**Inventario CSV.** Carica un file CSV fino a 1 MiB oppure incolla il testo, con al massimo 100 righe di dati. `url` è obbligatoria; le colonne facoltative sono `business_name`, `business_email`, `technical_name` e `technical_email`:

```csv
url,business_name,business_email,technical_name,technical_email
https://servizio.example.test,Responsabile,referente@example.test,Operazioni,tecnico@example.test
```

Separa più nomi e indirizzi nella stessa cella con punto e virgola, mantenendo lo stesso ordine. Scegli il separatore del file fra virgola, punto e virgola e tabulazione; associa esplicitamente intestazioni diverse ai campi previsti o ignora quelle inutili. L’anteprima conserva il numero di riga del file e segnala gli errori per campo. Correggi le righe nel modulo di modifica, seleziona quelle valide e scarica CSV corretto o report degli esiti.

```mermaid
flowchart LR
    CSV["CSV"] --> Map["Mappatura e validazione"]
    Map --> Correct["Correzione e selezione righe"]
    Correct --> Plan["Salva lotto e verifica URL"]
    Plan --> Review["Riepilogo delle modifiche"]
    Review -->|Approvazione esplicita| Work["Backend riacquisisce e salva ogni riga"]
    Work -->|Successo| Done["Salvataggio atomico della riga"]
    Work -->|Impronta o piano incompatibili| Again["Nuova revisione richiesta"]
    Work -->|Errore nel salvataggio| Rollback["Annulla questa riga"]
```

**Verifica URL** salva il contenuto selezionato in un lotto persistente e fa preparare il piano da un worker del backend. Esamina certificato nuovo/esistente, CA, date, monitor e modifiche ai referenti. Se una stessa email ha nomi diversi, scegli esplicitamente di conservare il nome salvato o aggiornarlo nelle assegnazioni condivise. L’approvazione è legata al piano esaminato; nei lotti con errori serve selezionare esplicitamente le righe pronte.

Prima dell’importazione il worker riacquisisce il certificato, controlla TLS e impronta attesa e rivede lo stato del registro. Sono ammesse aggiunte compatibili delle righe precedenti; modifiche incompatibili richiedono un’altra revisione. Certificati della catena, monitor, persone, assegnazioni, audit e ricevuta contro i duplicati sono salvati insieme per riga. Un errore annulla quella riga e conserva le precedenti già riuscite. Il worker CSV non invia email.

I lotti salvati offrono consultazione, pausa, ripianificazione e report, comprese le sole righe da correggere. Restano disponibili dopo chiusura del browser e riavvio; per elaborarli serve `serve` o `watch` attivo. Una preview senza approvazione non diventa un’importazione automatica.

## 2. Assegnare le persone e cercare i certificati

| Ruolo | Riceve | Responsabilità |
| --- | --- | --- |
| Referente | Promemoria email alle soglie configurate. | Coordinare il rinnovo con CA e tecnici. |
| Referente tecnico | Nuovo certificato pubblico firmato e catena disponibile in allegato PEM. | Installare il rinnovo esternamente e richiedere la verifica. |
| Destinatario escalation | Email dopo il ritardo configurato dal primo promemoria registrato. | Sollecitare il completamento mentre il certificato resta attivo. |
| Destinatario avvisi monitor | Email dei nuovi eventi di anomalia e ripristino, se abilitate per il monitor. | Esaminare il servizio e l’esito del certificato. |

Una persona può avere entrambi i ruoli sul certificato. **Rubrica** centralizza persone e gruppi: assegnali a più certificati e propaga le modifiche a indirizzi email e membri attraverso le assegnazioni. Prima di cambiare una persona o un gruppo condiviso, consulta certificati interessati, messaggi in attesa e destinatari dei monitor collegati. Per le modifiche mostra anche dati e appartenenze proposti e l’impatto risultante sui certificati. È una revisione senza identità autenticata. Le origini dei gruppi vengono conservate nei rinnovi. La rimozione di un destinatario cancella i relativi messaggi in attesa/non riusciti, conservando lo storico degli invii conclusi. Per recapitare la coda serve un trasporto SMTP abilitato.

I filtri del registro combinano testo, validità temporale, referente, referente tecnico, Root CA, CA intermedia e scadenza entro una soglia con logica **AND**. Le soglie di ricerca 45/30/15/2 giorni includono soltanto certificati già validi che scadono entro la durata scelta e restano indipendenti dalle soglie personalizzate dei promemoria. `notBefore` X.509 indica l’inizio della validità, non necessariamente la firma; la sola validità nel tempo non dimostra fiducia né installazione.

## 3. Pianificare le date ed eseguire i controlli periodici

L’agenda **Rinnovi** raccoglie le pratiche, filtra fase, responsabile e ritardi e apre il dettaglio del certificato. Il selettore delle pratiche permette di consultare tutti i casi aperti e conclusi del certificato. La pratica registra data della richiesta, rinnovo previsto, installazione prevista, responsabile e note. Sono date operative: non sostituiscono mai `notBefore` e `notAfter` del certificato. Aiutano a organizzare il lavoro; modificarle non richiede l’emissione alla CA e non distribuisce un certificato.

| Flusso | Frequenza | Risultato |
| --- | --- | --- |
| Regole di scadenza | All’avvio e ogni 60 secondi in `serve`. | Promemoria alle soglie raggiunte e messaggi in coda per i referenti. |
| Escalation | Nei controlli di scadenza, dopo il ritardo dal primo promemoria registrato. | Una escalation per certificato attivo e destinatario. |
| Monitor degli endpoint | Quando ciascun monitor attivo è dovuto; predefinita 15 minuti, configurabile da 1 a 1440 minuti. | Ultimo esito di rete/TLS/impronta, eventi di anomalia e ripristino deduplicati, email facoltative. |
| Elaborazione email | All’avvio e ogni 60 secondi, oppure con l’azione sulla coda. | Tentativi sui messaggi idonei quando SMTP è configurato e abilitato. |

Le soglie predefinite sono 45, 30, 15, 2 e 0 giorni. Per certificato puoi scegliere soglie distinte da **0 a 3650 giorni**, includendo `0`, oppure sospendere i promemoria. Le durate sono esatte, di 24 ore: con le impostazioni predefinite, un primo controllo a 10 giorni dalla scadenza registra i 15 giorni e salta i superati 45/30. Lo storico evita ripetizioni dopo il riavvio; i vecchi messaggi in attesa lasciano posto alla soglia più urgente.

L’escalation facoltativa usa **da 0 a 365 giorni dal primo promemoria registrato**, non dal caricamento o da una data pianificata. La firma di un rinnovo non interrompe promemoria ed escalation del precedente finché resta attivo.

**Simula promemoria** esamina il calendario della regola nel modulo, le soglie registrate/superate, i destinatari e l’escalation, senza scrivere notifiche né email. Salva modelli riutilizzabili in **Promemoria**, seleziona certificati ed eccezioni e approva il piano prima/dopo. Una modifica al modello o alle regole interessate invalida la conferma.

I monitor distinguono irraggiungibilità, errore TLS, certificato cambiato e verifica fallita. Gli errori identici ripetuti sono deduplicati; il ripristino viene registrato dopo un’anomalia. L’opzione email per monitor prepara i nuovi eventi di anomalia e ripristino per i destinatari scelti. Inizialmente è disabilitata e attivarla non reinvia gli eventi storici. Segnare un evento come letto non modifica le attese né approva un certificato.

Una soglia di **1–10 errori consecutivi di raggiungibilità** ritarda l’email per guasti DNS/TCP; il valore predefinito è uno. Le osservazioni tecniche sono visibili subito; errori TLS e impronte inattese non attendono questa soglia. La manutenzione sospende i nuovi avvisi email di anomalia/ripristino, conservando controlli ed eventi. Alla fine richiede una nuova verifica; un servizio in pausa deve comunque essere riattivato.

Prendi in carico un evento con responsabile, nota, termine e stato aperto/in analisi/risolto. Risolverlo organizzativamente non cambia il risultato tecnico. Per un’impronta inattesa trovi il collegamento ad acquisizione e confronto freschi, poi importazione esplicita ed eventuale rinnovo compatibile.

Durante un rinnovo collegato vengono riconosciuti il precedente e i rinnovi validi esplicitamente approvati nelle fasi firmato, consegnato o installazione. **Fiducia, nome e validità TLS restano obbligatori.** Un’impronta estranea è comunque inattesa; il monitor non importa né approva automaticamente certificati diversi.

Ogni attività periodica richiede un processo attivo. `serve` offre l’interfaccia; `watch` esegue promemoria, invii e monitor senza HTTP. Il suo intervallo regola promemoria e invii, mentre i monitor mantengono il proprio. `check` elabora una volta promemoria e coda. Le notifiche desktop richiedono inoltre una pagina aperta e il consenso del browser.

## 4. Preparare il rinnovo firmato e verificare l’installazione

```mermaid
sequenceDiagram
    actor Operatore
    participant App as UI e backend C
    participant DB as Registro SQLite
    participant SMTP as Server SMTP
    actor Tecnico
    participant Servizi as Endpoint HTTPS
    participant Monitor as Monitor TLS
    Operatore->>App: Carica o collega il rinnovo firmato
    App->>DB: Collega la pratica, copia referenti e regola
    Note over DB,Monitor: Il precedente resta attivo con i suoi monitor
    App->>DB: Prepara PEM pubblico in coda per i tecnici
    alt Invio SMTP abilitato
        App->>SMTP: Invia con TLS verificato
        SMTP-->>Tecnico: Certificato pubblico e catena
    else SMTP non disponibile o in pausa
        App->>DB: Mantiene i messaggi in coda
    end
    Tecnico->>Servizi: Installa esternamente, un endpoint alla volta
    Operatore->>App: Richiede verifica installazione
    App->>Monitor: Invalida il controllo precedente e ne richiede uno nuovo
    Monitor->>Servizi: Connessione TLS
    Servizi-->>Monitor: Certificato esposto
    Monitor->>DB: Salva nuova impronta e prova TLS
    Operatore->>App: Completa pratica
    App->>DB: Richiede esito recente per ogni endpoint
    App->>DB: Trasferisce monitor e archivia il precedente inutilizzato
```

Puoi aprire la pratica prima dell’emissione. Le fasi sono **Da richiedere → In attesa della CA → Firmato → Consegnato → In installazione → Verificato**, con l’esito separato **Ritirato** per il ritiro manuale. Cambiare una fase descrittiva non emette certificati, non invia email e non prova l’installazione.

Prima del collegamento usa il confronto per esaminare CN, SAN, emittente, Root/intermedie, validità, impronte e algoritmi di chiave/firma. L’esito indica se identità e validità consentono il rinnovo. Ottieni dalla CA il rinnovo firmato. Carica un certificato finale con le eventuali CA dall’azione di rinnovo del precedente, accetta un candidato nell’anteprima o collega una voce compatibile già presente. Il rinnovo deve essere già valido, avere scadenza successiva e mantenere le stesse identità DNS/IP; in assenza di SAN DNS/IP viene usato il CN. Voci CA e predecessori già archiviati sono respinti.

Il collegamento crea o riusa una pratica aperta senza rinnovo, copia referenti, origini dei gruppi ed eventuale regola promemoria e prepara gli allegati PEM per i tecnici. **Non archivia il precedente, non cancella i suoi promemoria e non sposta i monitor.** Riesce anche senza tecnici; puoi aggiungerli e preparare i messaggi in seguito. Emissione, firma e installazione effettiva rimangono esterne al programma.

| Voce nel registro | Validità X.509 | Stato operativo nella transizione |
| --- | --- | --- |
| Precedente | Può essere ancora valido | In uso fino al ritiro. |
| Nuovo firmato | Valido | Pronto prima dell’installazione. |
| Nuovo osservato durante la distribuzione | Valido | In distribuzione mentre la pratica resta aperta. |
| Precedente archiviato | Può essere ancora valido | Ritirato dopo chiusura o ritiro esplicito. |

Più rinnovi approvati possono coesistere per lo stesso CN, ognuno con impronta e collegamento distinti. I servizi possono essere aggiornati in giorni diversi. Il monitor ordinario può riconoscere un rinnovo approvato senza dichiarare verificata la pratica.

Dopo l’installazione richiedi la verifica per un endpoint o tutti. La richiesta invalida i controlli partiti prima; i servizi in pausa devono essere riattivati. **La chiusura richiede che ogni endpoint associato esponga l’impronta del rinnovo di quella pratica e superi le verifiche TLS dopo la richiesta. Sia la richiesta sia l’esito positivo devono risalire agli ultimi 15 minuti.** Un’osservazione automatica precedente, una prova vecchia o un errore TLS non bastano. Ripeti il controllo quando la prova non è più recente.

La checklist mostra impronta attesa/osservata, ultimo controllo e ogni blocco per servizio: pausa, richiesta/prova mancante o vecchia, TLS fallito, associazione cambiata e URL duplicati. Usa la stessa funzione del backend che autorizza la chiusura. Aggiornare la checklist legge le prove; quando serve, richiedi separatamente una nuova verifica TLS. L’interfaccia disabilita la chiusura quando la prova mostrata supera 900 secondi e il server ricontrolla sempre.

La chiusura trasferisce atomicamente i monitor verificati al nuovo certificato. Archivia il precedente solo se non conserva altre associazioni, interrompe i suoi promemoria futuri e rimuove i suoi messaggi in attesa/non riusciti. Eventuali URL duplicati già associati al nuovo certificato devono essere risolti prima della chiusura.

Con **zero endpoint** il programma non può dimostrare l’installazione. Il ritiro manuale richiede responsabile, nota esplicativa e nessun monitor ancora associato al precedente, inclusi quelli in pausa. L’esito è **Ritirato**, mai **Verificato**. Anche gli archivi migrati restano ritiri storici, senza inventare prove di distribuzione.

Durante la chiusura verificata o il ritiro manuale, la stessa transazione conserva un verbale JSON **prima** di trasferire monitor o archiviare. Il report scaricabile separa la prova catturata dai dati correnti della pratica. Le osservazioni successive non sostituiscono la prova. Eliminando la pratica si può eliminare anche il report; la cronologia locale non è un audit autenticato o antimanomissione. **Workflow** mostra le ultime 500 operazioni registrate, compresi cambi ai referenti, aggiornamenti pratiche ed esiti SMTP. L’audit inizia con lo schema v6 e non inventa azioni pregresse.

## 5. Controllare e inviare le email

**Coda email** contiene promemoria di scadenza, escalation, distribuzione di certificati pubblici e avvisi dei monitor abilitati. Configura host, porta, mittente, sicurezza ed eventuali credenziali. **Verifica connessione** prova TLS e autenticazione del modulo senza salvare né inviare email. Abilita l’invio quando vuoi procedere; altrimenti consulta e scarica i messaggi `.eml`.

Ogni pratica ha un pannello per destinatario tecnico con stato, tentativi ed errori, download `.eml` e ritentativo dei messaggi non riusciti. Aggiornalo dopo aver elaborato la coda.

Gli stati sono **In attesa → Invio in corso → Inviata**, oppure **Non riuscita**. Gli errori vengono ritentati con attese crescenti, fino a cinque tentativi automatici; il reinserimento manuale azzera il conteggio. “Inviata” significa accettazione SMTP; non dimostra consegna nella casella né installazione del certificato. Un’interruzione dopo l’accettazione può causare duplicati.

SMTP usa STARTTLS obbligatorio o TLS implicito con verifica del certificato e del nome. La password è cifrata con la chiave locale `<archivio>.smtp.key`: proteggi e conserva nei backup sia questa sia SQLite. Vedi [configurazione SMTP](README.it.md#coda-email-e-configurazione-smtp) e [sicurezza](../SECURITY.md). Il database non contiene chiavi private TLS.

## Esempio: due servizi aggiornati in giorni diversi

1. Importa il certificato, assegna responsabile e gruppo operativo e configura due monitor. Se serve, abilita gli avvisi email dei monitor.
2. Alla soglia configurata viene preparato un promemoria. Apri una pratica con date operative ed eventuale destinatario di escalation.
3. Ricevi e collega il rinnovo firmato. Entrambe le voci restano valide e visibili. Le email PEM per i tecnici entrano in coda; monitor e promemoria del precedente restano attivi.
4. Lunedì installa il rinnovo sul primo servizio. Il monitor riconosce l’impronta approvata, mentre il secondo servizio usa ancora il precedente valido. La pratica resta aperta.
5. Mercoledì installa sul secondo servizio, richiedi una nuova verifica di tutti gli endpoint e consulta entrambi gli esiti.
6. Completa entro 15 minuti dai controlli richiesti e riusciti. I monitor passano al nuovo certificato, il precedente entra nello storico e i suoi promemoria cessano. SMTP può restare in pausa durante le prove: i messaggi sono consultabili senza inviarli.

## Aggiornamento e ripristino

Lo schema v6 aggiunge lotti CSV e ricevute persistenti, modelli di regole, impostazioni/prese in carico delle anomalie, verbali di chiusura e audit locale. Prima di aggiornare conserva il database arrestato **e** la chiave `.smtp.key`, quando presente, in un archivio privato con la chiave a `0600`. L’applicazione resta locale senza autenticazione utenti: il nome del responsabile è un dato inserito dall’operatore, non un’identità verificata.
