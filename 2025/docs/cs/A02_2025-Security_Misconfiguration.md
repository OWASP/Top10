# A02:2025 Chybná bezpečnostní konfigurace (Security Misconfiguration) ![icon](../assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}


## Pozadí

Tato kategorie se oproti předchozímu vydání posunula z 5. místa na vyšší 2. pozici. U 100 % testovaných aplikací byla zjištěna nějaká forma chybné konfigurace, s průměrnou mírou výskytu 3,00 % a s více než 719 tisíci výskyty slabin klasifikovaných podle Common Weakness Enumeration (CWE) v této rizikové kategorii. S rostoucím rozšířením vysoce konfigurovatelného softwaru není překvapivé, že tato kategorie v žebříčku stoupá. Mezi významné zjištěné slabiny patří zejména *CWE-16: Configuration* a *CWE-611: Improper Restriction of XML External Entity Reference (XXE)*.

## Tabulka skóre


<table>
  <tr>
   <td>Počet mapovaných CWE 
   </td>
   <td>Max míra výskytu
   </td>
   <td>Průměrná míra výskytu
   </td>
   <td>Max pokrytí
   </td>
   <td>Průměrné pokrytí
   </td>
   <td>Průměrná vážená zneužitelnost
   </td>
   <td>Průměrný vážený dopad
   </td>
   <td>Celkový počet výskytů
   </td>
   <td>Celkový počet CVE
   </td>
  </tr>
  <tr>
   <td>16
   </td>
   <td>27,70 %
   </td>
   <td>3,00 %
   </td>
   <td>100,00 %
   </td>
   <td>52,35 %
   </td>
   <td>7,96
   </td>
   <td>3,97
   </td>
   <td>719 084
   </td>
   <td>1 375
   </td>
  </tr>
</table>



## Popis

Chybná bezpečnostní konfigurace znamená, že systém, aplikace nebo cloudová služba jsou nakonfigurovány nesprávně z hlediska bezpečnosti, což vede ke vzniku zranitelností.

Aplikace je zranitelná, pokud například:



* Chybí odpovídající bezpečnostní hardening v některé části aplikačního stacku nebo jsou nesprávně nakonfigurována oprávnění cloudových služeb.
* Jsou povoleny nebo nainstalovány nepotřebné funkce, například nevyužívané porty, služby, stránky, účty, testovací frameworky nebo oprávnění.
* Výchozí účty a jejich hesla zůstávají aktivní a nezměněná.
* Chybí centrální konfigurace pro zachytávání příliš informativních chybových zpráv. Zpracování chyb odhaluje uživatelům výpisy zásobníku (stack trace) nebo jiné příliš informativní chybové zprávy.
* U aktualizovaných systémů jsou nejnovější bezpečnostní funkce deaktivovány nebo nejsou nakonfigurovány bezpečně.
* Přílišné upřednostňování zpětné kompatibility vedoucí k nezabezpečené konfiguraci.
* Bezpečnostní nastavení aplikačních serverů, aplikačních frameworků (např. Struts, Spring, ASP.NET), knihoven, databází apod. nejsou nastavena na bezpečné hodnoty.
* Server neodesílá bezpečnostní hlavičky nebo direktivy, nebo nejsou nastaveny na bezpečné hodnoty.


Bez koordinovaného a opakovatelného procesu bezpečnostního hardeningu konfigurace aplikací jsou systémy vystaveny zvýšenému riziku.


## Jak tomu zabránit 

Měly by být implementovány bezpečné instalační procesy, včetně:

* Opakovatelný proces hardeningu umožňující rychlé a snadné nasazení dalšího prostředí s odpovídajícím zabezpečením. Vývojové, testovací (QA) a produkční prostředí by měla být konfigurována shodně, přičemž v každém prostředí by se měly používat odlišné přihlašovací údaje. Tento proces by měl být automatizován, aby se minimalizovalo úsilí potřebné k nastavení nového bezpečného prostředí.
* Minimální platforma bez zbytečných funkcí, komponent, dokumentace nebo ukázek. Odstraňte nebo neinstalujte nepoužívané funkce a frameworky.
* Revize a aktualizace konfigurací v návaznosti na všechna bezpečnostní upozornění, aktualizace a záplaty jako součást procesu správy záplat (viz [A03:2025 Selhání dodavatelského řetězce softwaru](A03_2025-Software_Supply_Chain_Failures.md)). Kontrola oprávnění cloudových úložišť (např. oprávnění S3 bucketů).
* Segmentovanou architekturu aplikace, která zajišťuje účinné a bezpečné oddělení komponent nebo tenantů pomocí segmentace, kontejnerizace nebo cloudových bezpečnostních skupin (ACL).
* Zasílání bezpečnostních direktiv klientům, např. bezpečnostních hlaviček (Security Headers).
* Automatizovaný proces ověřování účinnosti konfigurací a nastavení ve všech prostředích.
* Proaktivní zavedení centrální konfigurace pro zachytávání příliš informativních chybových hlášení jako záložního opatření.
* Pokud tyto kontroly nejsou automatizované, měly by být alespoň jednou ročně prováděny manuálně.
* Využívání federace identit, krátkodobě platných přihlašovacích údajů nebo mechanismů řízení přístupu založených na rolích poskytovaných podkladovou platformou namísto ukládání statických klíčů nebo tajných údajů (secrets) do zdrojového kódu, konfiguračních souborů nebo CI/CD pipeline.



## Příklady scénářů útoků 

**Scénář #1:** Na aplikačním serveru zůstaly nasazeny ukázkové aplikace, které nebyly z produkčního prostředí odstraněny. Tyto aplikace obsahují známé bezpečnostní chyby, které mohou útočníci zneužít ke kompromitaci serveru. Pokud je jednou z těchto aplikací administrační konzole a výchozí účty nebyly změněny, útočník se přihlásí pomocí výchozích přihlašovacích údajů a převezme kontrolu.

**Scénář #2:** Na serveru není zakázán výpis adresářů. Útočník zjistí, že může zobrazit seznam adresářů, nalezne a stáhne zkompilované třídy Java, které následně dekompiluje a analyzuje. Na základě toho odhalí závažnou chybu v řízení přístupu aplikace.

**Scénář #3:** Konfigurace aplikačního serveru umožňuje zobrazování detailních chybových informací, například výpisů zásobníku (stack trace). Tím může dojít ke zpřístupnění citlivých informací nebo vnitřních nedostatků, například verzí použitých komponent, o nichž je známo, že jsou zranitelné.

**Scénář #4:** Poskytovatel cloudových služeb (CSP) má ve výchozím nastavení povolena oprávnění ke sdílení otevřená do Internetu. To umožňuje přístup k citlivým datům uloženým v cloudovém úložišti.


## Reference

* [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
* [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
* [Application Security Verification Standard V13 Configuration](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
* ScienceDirect: Security Misconfiguration

## Seznam mapovaných CWE

* [CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption](https://cwe.mitre.org/data/definitions/5.html)

* [CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

* [CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

* [CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

* [CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

* [CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

* [CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

* [CWE-489 Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

* [CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

* [CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

* [CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

* [CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

* [CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

* [CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

* [CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

* [CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
