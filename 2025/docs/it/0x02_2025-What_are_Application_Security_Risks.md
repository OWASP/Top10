# Cosa sono i Rischi di Sicurezza delle Applicazioni?
Gli attaccanti possono potenzialmente sfruttare molti percorsi diversi attraverso la tua applicazione per danneggiare la tua azienda o organizzazione. Ognuno di questi percorsi rappresenta un potenziale rischio che deve essere esaminato.

![Calculation diagram](../assets/2025-algorithm-diagram.png)

<table>
  <tr>
   <td>
    <strong>Agenti di Minaccia</strong>
   </td>
   <td>
    <strong>Vettori di \
Attacco</strong>
   </td>
   <td>
    <strong>Sfruttabilità</strong>
   </td>
   <td>
    <strong>Probabilità di Assenza di Controlli</strong>
<p style="text-align: center">

    <strong>di Sicurezza</strong>
   </td>
   <td>
    <strong>Impatti</strong>
<p style="text-align: center">

    <strong>Tecnici</strong>
   </td>
   <td>
    <strong>Impatti</strong>
<p style="text-align: center">

    <strong>sul Business</strong>
   </td>
  </tr>
  <tr>
   <td>
    <strong>In base all'ambiente, \
dinamico in base alla situazione</strong>
   </td>
   <td>
    <strong>In base all'esposizione dell'applicazione (per ambiente)</strong>
   </td>
   <td>
    <strong>Exploit Medio Ponderato</strong>
   </td>
   <td>
    <strong>Controlli Mancanti \
per tasso medio di incidenza \
ponderato per copertura</strong>
   </td>
   <td>
    <strong>Impatto Medio Ponderato</strong>
   </td>
   <td>
    <strong>Per Business</strong>
   </td>
  </tr>
</table>


Nella nostra valutazione del rischio abbiamo tenuto conto dei parametri universali di sfruttabilità, probabilità media di assenza di controlli di sicurezza per una debolezza e i suoi impatti tecnici.

Ogni organizzazione è unica, e così lo sono gli attori delle minacce per quella organizzazione, i loro obiettivi e l'impatto di qualsiasi violazione. Se un'organizzazione di interesse pubblico utilizza un sistema di gestione dei contenuti (CMS) per informazioni pubbliche e un sistema sanitario utilizza lo stesso identico CMS per cartelle cliniche sensibili, gli attori delle minacce e gli impatti sul business possono essere molto diversi per lo stesso software. È fondamentale comprendere il rischio per la propria organizzazione in base all'esposizione dell'applicazione, agli agenti di minaccia applicabili per situazione (per attacchi mirati e non diretti per business e ubicazione) e agli impatti individuali sul business.


## Come vengono utilizzati i dati per selezionare le categorie e classificarle

Nel 2017 abbiamo selezionato le categorie in base al tasso di incidenza per determinare la probabilità, e poi le abbiamo classificate tramite discussione del team basata su decenni di esperienza per Sfruttabilità, Rilevabilità (anche probabilità) e Impatto Tecnico. Per il 2021 abbiamo utilizzato dati per Sfruttabilità e Impatto (Tecnico) dai punteggi CVSSv2 e CVSSv3 nel National Vulnerability Database (NVD). Per il 2025 abbiamo continuato la stessa metodologia creata nel 2021.

Abbiamo scaricato OWASP Dependency Check ed estratto i punteggi CVSS di Exploit e Impact raggruppati per CWE correlate. Ha richiesto una discreta ricerca e sforzo poiché tutti i CVE hanno punteggi CVSSv2, ma ci sono difetti in CVSSv2 che CVSSv3 dovrebbe correggere. Dopo un certo punto nel tempo, a tutti i CVE viene assegnato anche un punteggio CVSSv3. Inoltre, gli intervalli di punteggio e le formule sono stati aggiornati tra CVSSv2 e CVSSv3.

In CVSSv2, sia Exploit che Impatto (Tecnico) potevano arrivare fino a 10,0, ma la formula li abbassava al 60% per Exploit e al 40% per Impact. In CVSSv3, il massimo teorico era limitato a 6,0 per Exploit e 4,0 per Impact. Con la ponderazione considerata, il punteggio di Impact è aumentato, quasi un punto e mezzo in media in CVSSv3, e la sfruttabilità è diminuita di quasi mezzo punto in media quando abbiamo condotto l'analisi per il Top Ten 2021.

Ci sono circa 175k record (rispetto ai 125k del 2021) di CVE mappati a CWE nel National Vulnerability Database (NVD), estratti da OWASP Dependency Check. Inoltre, ci sono 643 CWE uniche mappate a CVE (rispetto alle 241 del 2021). Nell'ambito dei quasi 220k CVE estratti, 160k avevano punteggi CVSS v2, 156k avevano punteggi CVSS v3 e 6k avevano punteggi CVSS v4. Molti CVE hanno più punteggi, motivo per cui il totale supera i 220k.

Per il Top Ten 2025 abbiamo calcolato i punteggi medi di exploit e impact raggruppando tutti i CVE con punteggi CVSS per CWE e ponderando entrambi i punteggi in base alla percentuale della popolazione con CVSSv3 e alla restante popolazione con CVSSv2, ottenendo una media complessiva. Abbiamo mappato queste medie alle CWE nel dataset da usare come punteggi di Exploit e Impatto (Tecnico) per l'altra metà dell'equazione del rischio.

Perché non usare CVSS v4.0? Perché l'algoritmo di punteggio è stato modificato in modo sostanziale e non fornisce più facilmente i punteggi di *Exploit* o *Impact* come fanno CVSSv2 e CVSSv3. Tenteremo di trovare un modo per utilizzare il punteggio CVSS v4.0 nelle versioni future del Top Ten, ma non siamo riusciti a determinare un modo tempestivo per farlo per l'edizione 2025.

Per il tasso di incidenza abbiamo calcolato la percentuale di applicazioni vulnerabili a ciascuna CWE dalla popolazione testata da un'organizzazione per un determinato periodo. Come promemoria, non utilizziamo la frequenza (ovvero quante volte un problema appare in un'applicazione), ma siamo interessati a quale percentuale della popolazione di applicazioni è risultata avere ciascuna CWE.

Per la copertura guardiamo la percentuale di applicazioni testate da tutte le organizzazioni per una determinata CWE. Maggiore è la copertura calcolata, più forte è la garanzia che il tasso di incidenza sia accurato poiché la dimensione del campione è più rappresentativa della popolazione.

La formula che abbiamo utilizzato per questa iterazione è simile a quella del 2021, con alcune modifiche alla ponderazione:
(Tasso Massimo di Incidenza % * 1000) + (Copertura Massima % * 100) + (Exploit Medio * 10) + (Impatto Medio * 20) + (Totale Occorrenze / 10000) = Punteggio di Rischio

I punteggi calcolati variavano da 621,60 per la categoria Broken Access Control a 271,08 per Memory Management Errors.

Non è un sistema perfetto, ma è utile per classificare le categorie di rischio.

Una sfida aggiuntiva in crescita è la definizione di "applicazione". Con lo spostamento del settore verso architetture diverse composte da micro-servizi e altre implementazioni più piccole di un'applicazione tradizionale, i calcoli diventano più difficili. Ad esempio, se un'organizzazione sta testando repository di codice, cosa considera un'applicazione? Analogamente alla crescita di CVSSv4, la prossima edizione del Top Ten potrebbe dover adeguare l'analisi e il punteggio per tenere conto di un settore in costante evoluzione.

## Fattori dei dati

Ci sono fattori dei dati elencati per ciascuna delle categorie del Top Ten, ecco cosa significano:

**CWE Mappate:** Il numero di CWE mappate a una categoria dal team del Top Ten.

**Tasso di Incidenza:** Il tasso di incidenza è la percentuale di applicazioni vulnerabili a quella CWE dalla popolazione testata dall'organizzazione per quell'anno.

**Exploit Ponderato:** Il sotto-punteggio Exploit dai punteggi CVSSv2 e CVSSv3 assegnati ai CVE mappati alle CWE, normalizzato e posto su una scala a 10 punti.

**Impatto Ponderato:** Il sotto-punteggio Impact dai punteggi CVSSv2 e CVSSv3 assegnati ai CVE mappati alle CWE, normalizzato e posto su una scala a 10 punti.

**Copertura (Testing):** La percentuale di applicazioni testate da tutte le organizzazioni per una determinata CWE.

**Totale Occorrenze:** Numero totale di applicazioni in cui sono state trovate le CWE mappate a una categoria.

**Totale CVE:** Numero totale di CVE nel DB NVD mappati alle CWE di una categoria.

**Formula:** (Tasso Massimo di Incidenza % * 1000) + (Copertura Massima % * 100) + (Exploit Medio * 10) + (Impatto Medio * 20) + (Totale Occorrenze / 10000) = Punteggio di Rischio
