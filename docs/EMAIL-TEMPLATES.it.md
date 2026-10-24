# Modelli email per avviso e destinatario

La pagina **Coda email** (`/email`) permette di cambiare oggetto e testo di ogni avviso senza modificare il codice. I modelli sono salvati nello stesso archivio SQLite del registro. Non occorre configurare SMTP per prepararli o provarli.

## Preparare un modello

1. In **Il mio destinatario personale**, salva **Il mio nome** e **La mia email**. Questo è il destinatario del gruppo **A me**, distinto dal mittente SMTP.
2. Scegli il tipo di avviso e il gruppo destinatario.
3. Modifica l’oggetto e il corpo in testo semplice. Inserisci le variabili con la sintassi esatta `{{nome_variabile}}`.
4. Consulta l’anteprima con un certificato o un evento disponibile, oppure con i dati dimostrativi indicati dall’interfaccia. L’anteprima non scrive nel registro, non prepara messaggi e non invia email.
5. Salva. Il modello sarà usato quando verranno preparati nuovi messaggi per quella combinazione.

**Ripristina predefinito** ripristina soltanto l’avviso e il gruppo selezionati, disabilitando le relative copie aggiuntive. I messaggi già preparati, inclusi quelli non ancora inviati, mantengono oggetto e corpo originari: puoi verificarli con **Scarica .eml**. Un ritentativo di un messaggio non riuscito usa lo stesso contenuto già presente in coda.

## Avvisi disponibili

| Avviso | Quando viene usato |
| --- | --- |
| Scadenza entro 45, 30, 15 o 2 giorni | Soglia corrispondente raggiunta nella regola del certificato. |
| Certificato scaduto | Soglia `0` della regola promemoria. |
| Scadenza con soglia personalizzata | Altre soglie, come 60, 21 o 7 giorni. |
| Escalation | Ritardo della regola raggiunto dal primo promemoria registrato. |
| Certificato firmato | Distribuzione del rinnovo pubblico e della catena disponibile. |
| Servizio non raggiungibile | Anomalia DNS/TCP confermata secondo la soglia del monitor. |
| Errore TLS | Connessione TLS non completata. |
| Certificato cambiato | Impronta inattesa rispetto al registro e ai rinnovi approvati. |
| Errore di verifica | Verifica di fiducia, nome o validità TLS non riuscita. |
| Altro errore | Altro errore tecnico del controllo. |
| Servizio ripristinato | Rientro dell’anomalia tecnica. |

La personalizzazione non cambia quando scatta l’avviso. Le soglie e la sospensione dei promemoria restano nelle regole del certificato; frequenza, conferma degli errori e manutenzione restano nelle impostazioni del monitor. Una modifica del modello non reinvia eventi storici e non genera immediatamente un avviso.

## Gruppi e copie aggiuntive

| Gruppo | Destinatari |
| --- | --- |
| A me | L’indirizzo personale salvato in questa pagina. Per abilitare una copia personale occorre prima salvare un indirizzo valido. Svuotarlo successivamente sospende le copie personali. |
| Referenti | Persone assegnate al certificato con il ruolo referente, anche tramite gruppi della rubrica. |
| Referenti tecnici | Persone assegnate al certificato con il ruolo tecnico. |
| Altri destinatari | Indirizzi espliciti di escalation o monitor che non corrispondono ai gruppi precedenti. |

I destinatari già previsti dal flusso continuano a ricevere i loro messaggi: i referenti ricevono le scadenze, i tecnici il certificato firmato, l’escalation il destinatario della regola e i monitor la propria lista email. Il modello selezionato determina il testo per ciascuna persona.

Per aggiungere A me, Referenti o Referenti tecnici agli altri avvisi, abilita **Invia anche una copia a questo gruppo** sul modello pertinente. Ogni combinazione avviso/gruppo è indipendente; inizialmente le copie sono tutte disabilitate. Il gruppo Altri destinatari non crea copie: personalizza soltanto gli indirizzi già esplicitamente configurati.

Esempio: abilita la copia **A me** per Scadenza entro 15 giorni e Certificato cambiato; abilita **Referenti tecnici** per Scadenza entro 2 giorni. Le altre scadenze continuano a seguire i percorsi preesistenti. Una persona che compare in più gruppi riceve un solo messaggio per lo stesso evento, confrontando l’indirizzo senza distinzione fra maiuscole e minuscole.

Per gli avvisi di scadenza e la distribuzione prevale il ruolo del destinatario originale. Per monitor ed escalation viene scelto prima A me se l’indirizzo coincide con il profilo personale, poi Referenti, Referenti tecnici e infine Altri destinatari. Tra sole copie aggiuntive la precedenza è A me, Referenti, Referenti tecnici; un invio originale ha sempre precedenza sulle copie.

Prima di prendere un messaggio in carico per l’invio, il server ricontrolla i destinatari e l’abilitazione delle copie. Disabilitare una copia o rimuovere la relativa assegnazione impedisce l’invio di quella copia ancora in attesa. Le copie rispettano anche la regola promemoria abilitata, il certificato attivo e valido per la distribuzione e, per gli avvisi dei servizi, l’abilitazione email e le finestre di manutenzione del monitor. Questo controllo può rimuovere dalla coda un messaggio non più pertinente; non riscrive il testo dei messaggi conservati.

## Variabili

| Variabile | Dato inserito |
| --- | --- |
| `{{app_name}}` | Nome Certificate Manager. |
| `{{common_name}}` | CN del certificato. |
| `{{fingerprint}}` | Impronta del certificato. |
| `{{not_before}}`, `{{not_after}}` | Inizio e fine validità, espressi in UTC. |
| `{{serial}}`, `{{issuer}}` | Numero di serie ed emittente. |
| `{{root_ca}}`, `{{intermediate_ca}}` | CA ricostruite con i certificati disponibili nel registro. |
| `{{sans}}` | Identità SAN. |
| `{{recipient_name}}`, `{{recipient_email}}` | Nome e indirizzo del singolo destinatario. |
| `{{recipient_role}}` | Gruppo del destinatario: `self`, `business`, `technical` o `other`. |
| `{{threshold}}` | Soglia del promemoria; `0` indica la scadenza. |
| `{{days_remaining}}` | Giorni residui del certificato al momento della preparazione. |
| `{{service_url}}` | URL del monitor nell’avviso di servizio. |
| `{{event_type}}`, `{{event_message}}` | Tipo tecnico e descrizione dell’evento. |
| `{{expected_fingerprint}}`, `{{observed_fingerprint}}` | Impronte prevista e osservata nell’evento. |

Un dato non applicabile al tipo di avviso può essere vuoto. Le CA mancanti non vengono inventate; il CN non individua da solo una versione del certificato, quindi includi l’impronta per distinguere rinnovi contemporaneamente validi. Nomi, indirizzi e valori dei certificati restano dati dell’utente; il programma non li traduce.

Esempio per i referenti, scadenza entro 15 giorni:

```text
Oggetto: Rinnovo da pianificare: {{common_name}}

Ciao {{recipient_name}},

il certificato {{common_name}} scade il {{not_after}}.
Restano {{days_remaining}} giorni. Conferma la pianificazione del rinnovo.
Impronta: {{fingerprint}}
```

Esempio per i tecnici, certificato firmato:

```text
Oggetto: Certificato pronto per l'installazione: {{common_name}}

Ciao {{recipient_name}},

il bundle pubblico è allegato. Pianifica l'installazione e poi richiedi
la verifica degli endpoint nella pratica di rinnovo.
Nuova impronta: {{fingerprint}}
Fine validità: {{not_after}}
```

L’allegato del messaggio Certificato firmato resta il bundle PEM pubblico disponibile. Il testo non può aggiungere allegati arbitrari né chiavi private. Gli altri avvisi non allegano il certificato. I modelli sono testo semplice; non vengono interpretati HTML, codice o espressioni. Le variabili sconosciute, malformate, i caratteri non validi e i ritorni a capo nell’oggetto sono rifiutati. I limiti sono **998 byte** per l’oggetto e **16 KiB** per il corpo, anche dopo la sostituzione delle variabili.

Controlla l’anteprima anche con i dati del registro: un modello breve può produrre un messaggio troppo lungo dopo l’espansione. In tal caso la preparazione viene rifiutata con tipo di avviso, gruppo e ID del certificato da correggere; nessun testo incompleto viene inviato. Gli avvisi già preparati non vengono rielaborati dal nuovo modello.

## Invio e conservazione

L’anteprima e il salvataggio dei modelli non abilitano SMTP. Gli invii richiedono una configurazione SMTP abilitata nella stessa pagina; senza di essa i messaggi restano in coda. Lo stato Inviata indica accettazione da parte del server SMTP, non ricezione né installazione del certificato.

I modelli e l’indirizzo personale sono compresi nel backup del database. Lo schema **v7** migra automaticamente la versione 6, conservando la coda e lo storico e senza abilitare copie aggiuntive. Prima dell’aggiornamento arresta tutti i processi dell’applicazione e salva database e chiave `<archivio>.smtp.key`, se presente. L’interfaccia mantiene il modello di accesso locale esistente: non offre utenti autenticati o ruoli di autorizzazione.

## Compatibilità SMTP verificata

La suite nativa usa Ubuntu **24.04**; il container distribuito usa Debian **12**. I test locali sono eseguiti anche su macOS. L’ambiente del job Docker rimane `ubuntu-latest`, mentre quello della suite nativa è fissato per rendere riproducibili le dipendenze.

Su Ubuntu **26.04**, con libcurl **8.18.0-1ubuntu2.8**, il test locale della verifica di connessione SMTP termina immediatamente prima del saluto del server. Lo stesso risultato è stato riprodotto [sulla versione precedente ai template](https://github.com/GiorgioOppo/Certificate-Manager/actions/runs/39662622964), oltre che [nella prova con diagnostica](https://github.com/GiorgioOppo/Certificate-Manager/actions/runs/40076923232). Questo ambiente non è validato per SMTP; per l’esecuzione Linux usa il container fornito o Ubuntu 24.04. La causa nella combinazione di librerie rimane da approfondire.
