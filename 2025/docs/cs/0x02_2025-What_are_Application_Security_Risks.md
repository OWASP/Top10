# Co jsou bezpečnostní rizika aplikací?
Útočníci mohou využít mnoho různých cest prostřednictvím vaší aplikace k poškození vašeho byznysu či organizace. Každý z těchto způsobů představuje potenciální riziko, které je nutné prověřit.

![Výpočetní diagram](../assets/2025-algorithm-diagram.png)

<table>
  <tr>
   <td>
    <strong>Aktéři hrozeb</strong>
   </td>
   <td>
    <strong>Vektory útoku</strong>
   </td>
   <td>
    <strong>Zneužitelnost</strong>
   </td>
   <td>
    <strong>Pravděpodobnost chybějících bezpečnostních kontrol</strong>
   </td>
   <td>
    <strong>Technické dopady</strong>
   </td>
   <td>
    <strong>Byznysové dopady</strong>
   </td>
  </tr>
  <tr>
   <td>
    <strong>Podle prostředí, dynamicky podle situačního obrazu</strong>
   </td>
   <td>
    <strong>Podle expozice aplikace (podle prostředí)</strong>
   </td>
   <td>
    <strong>Průměrná vážená zneužitelnost</strong>
   </td>
   <td>
    <strong>Chybějící kontroly podle průměrné míry výskytu vážené podle pokrytí</strong>
   </td>
   <td>
    <strong>Průměrný vážený dopad</strong>
   </td>
   <td>
    <strong>Podle byznysu</strong>
   </td>
  </tr>
</table>


V našem hodnocení rizik jsme zohlednili univerzální parametry zneužitelnosti, průměrné pravděpodobnosti chybějících bezpečnostních kontrol u dané slabiny a její technické dopady. 

Každá organizace je jedinečná, stejně jako aktéři hrozeb pro danou organizaci, jejich cíle a dopady případného narušení. Pokud organizace poskytující veřejné informace používá systém pro správu obsahu (CMS) k publikaci obsahu pro veřejnost a zdravotnický systém používá tentýž CMS pro práci s citlivými zdravotními záznamy, mohou se aktéři hrozeb i dopady na organizaci u stejného softwaru výrazně lišit. Je zásadní porozumět riziku pro vaši organizaci na základě expozice aplikace, relevantních aktérů hrozeb v daném situačním obrazu (u cílených i necílených útoků podle byznysu a lokality) a konkrétních byznysových dopadů. 


## Způsob použití dat pro výběr kategorií a jejich hodnocení

V roce 2017 byly kategorie vybírány podle míry výskytu za účelem určení pravděpodobnosti, a následně byly seřazeny na základě týmové diskuse vycházející z desítek let zkušeností v oblastech zneužitelnosti, detekovatelnosti (také pravděpodobnosti) a technického dopadu. Pro rok 2021 jsme použili data zneužitelnosti a (technického) dopadu ze skóre CVSSv2 a CVSSv3 v National Vulnerability Database (NVD). Pro rok 2025 jsme pokračovali ve stejné metodice, kterou jsme vytvořili v roce 2021.

Stáhli jsme OWASP Dependency Check a extrahovali skóre CVSS pro zneužitelnost a dopad, seskupená podle souvisejících CWE. Tento proces vyžadoval značné množství výzkumu a úsilí, protože všechny CVE mají skóre CVSSv2, avšak CVSSv2 obsahuje nedostatky, které má řešit CVSSv3. Od určitého okamžiku jsou všem CVE přiřazována také skóre CVSSv3. Kromě toho byly mezi CVSSv2 a CVSSv3 aktualizovány rozsahy skórování i výpočetní vzorce. 

V CVSSv2 mohly hodnoty zneužitelnosti i (technického) dopadu dosahovat až 10,0, avšak výpočetní vzorec je snižoval na 60 % pro zneužitelnost a 40 % pro dopad. V CVSSv3 je teoretické maximum omezeno na 6,0 pro zneužitelnost a 4,0 pro dopad. Po zohlednění vážení se hodnocení dopadu v CVSSv3 posunulo výše, v průměru téměř o jeden a půl bodu, zatímco hodnocení zneužitelnosti se při analýze pro Top Ten 2021 v průměru posunulo téměř o půl bodu níže.

V National Vulnerability Database (NVD) se nachází přibližně 175 tisíc záznamů CVE mapovaných na CWE (nárůst ze 125 tisíc v roce 2021), extrahovaných z OWASP Dependency Check. Dále je evidováno 643 jedinečných CWE mapovaných na CVE (nárůst z 241 v roce 2021). Z téměř 220 tisíc extrahovaných CVE mělo 160 tisíc skóre CVSS v2, 156 tisíc skóre CVSS v3 a 6 tisíc skóre CVSS v4. Mnoho CVE má více skóre, což vysvětluje, proč jejich celkový počet přesahuje 220 tisíc.

Pro Top Ten 2025 jsme průměrná skóre zneužitelnosti a dopadu vypočítali následujícím způsobem. Všechny CVE se známým CVSS skóre jsme seskupili podle CWE a jak skóre zneužitelnosti, tak i dopadu jsme vážili podle podílu záznamů hodnocených pomocí CVSSv3 a zbývajícího podílu hodnoceného pomocí CVSSv2, abychom získali celkový vážený průměr. Tyto průměrné hodnoty jsme následně namapovali na jednotlivé CWE v datové sadě a použili je jako skóre zneužitelnosti a (technického) dopadu pro druhou polovinu rovnice rizika.

Proč nebylo použito CVSS v4.0? Důvodem je, že skórovací algoritmus byl zásadně změněn a již neposkytuje skóre zneužitelnosti nebo dopadu tak přímo, jako je tomu u CVSSv2 a CVSSv3. V budoucích vydáních Top Ten se pokusíme nalézt způsob, jak skórování CVSS v4.0 využít, avšak pro vydání 2025 se nepodařilo nalézt časově proveditelné řešení.

Pro míru výskytu (incidence rate) jsme vypočítali procento aplikací zranitelných vůči jednotlivým CWE z populace aplikací testovaných organizací v určitém časovém období. Připomínáme, že nepoužíváme četnost (tedy kolikrát se problém v aplikaci vyskytuje), ale zajímá nás, jaké procento populace aplikací mělo dané CWE. 

Pro pokrytí (coverage) sledujeme procento aplikací testovaných napříč všemi organizacemi pro konkrétní CWE. Čím vyšší je vypočtené pokrytí, tím větší je jistota, že míra výskytu je přesná, protože velikost vzorku je reprezentativnější pro populaci.

Vzorec použitý v tomto vydání je podobný vydání z roku 2021, s některými změnami ve vážení:
(Maximální míra výskytu % * 1000) + (Maximální pokrytí % * 100) + (Průměrná zneužitelnost * 10) + (Průměrný dopad * 20) + (Součet výskytů / 10 000) = Skóre rizika

Vypočtená skóre se pohybovala od 621,60 u kategorie Nedostatečné řízení přístupu (Broken Access Control) až po 271,08 u kategorie Chyby správy paměti (Memory Management Errors).

Nejde o dokonalý systém, ale je užitečný pro řazení kategorií rizik.

Další výzvou, jejíž význam roste, je vymezení pojmu „aplikace“. S tím, jak se odvětví posouvá k odlišným architekturám založeným na mikroslužbách a dalších implementacích, které jsou menší než tradiční aplikace, jsou související výpočty stále obtížnější. Například pokud organizace testuje repozitáře zdrojového kódu, vyvstává otázka, co je v takovém případě považováno za aplikaci. Podobně jako s nástupem CVSSv4 může být v příštím vydání OWASP Top 10 nutné upravit analýzu a skórování tak, aby zohledňovaly neustále se měnící charakter odvětví.

## Datové faktory

Pro každou kategorii OWASP Top Ten jsou uvedeny datové faktory; jejich význam je následující:

**Mapované CWE (CWEs Mapped):** Počet CWE přiřazených ke kategorii týmem Top Ten.

**Míra výskytu (Incidence Rate):** Procento aplikací zranitelných vůči danému CWE z populace aplikací testovaných danou organizací v daném roce.

**Vážená zneužitelnost (Weighted Exploit):** Dílčí skóre zneužitelnosti ze skóre CVSSv2 a CVSSv3 přiřazených k CVE mapovaným na CWE, normalizované a převedené na desetibodovou škálu.

**Vážený dopad (Weighted Impact):** Dílčí skóre dopadu ze skóre CVSSv2 a CVSSv3 přiřazených k CVE mapovaným na CWE, normalizované a převedené na desetibodovou škálu.

**(Testovací) pokrytí ((Testing) Coverage):** Procento aplikací testovaných všemi organizacemi pro daný CWE.

**Celkový počet výskytů (Total Occurrences):** Celkový počet aplikací, u nichž byly nalezeny CWE mapované na danou kategorii.

**Celkový počet CVE (Total CVEs):** Celkový počet CVE v databázi NVD, které byly mapovány na CWE mapované k dané kategorii.

**Vzorec (Formula):** (Maximální míra výskytu % * 1000) + (Maximální pokrytí % * 100) + (Průměrná zneužitelnost * 10) + (Průměrný dopad * 20) + (Součet výskytů / 10 000) = Skóre rizika
