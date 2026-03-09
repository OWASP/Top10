# A05:2025 Injekce ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Pozadí

Injekce (Injection) klesá o dvě pozice z 3. na 5. v pořadí a zachovává relativní pozici vůči A04:2025-Kryptografická selhání (Cryptographic Failures) a A06:2025-Nezabezpečený návrh (Insecure Design). Injekce je jednou z nejvíce testovaných kategorií, přičemž 100 % aplikací je testováno na nějakou formu injekce. Má největší počet CVE ze všech kategorií, přičemž zahrnuje 37 CWE. Injekce zahrnuje Cross-site Scripting (vysoká četnost / nízký dopad) s více než 30 000 CVE a SQL Injection (nízká četnost / vysoký dopad) s více než 14 000 CVE. Masivní počet nahlášených CVE pro CWE-79 Improper Neutralization of Input During Web Page Generation („Cross-site Scripting“) snižuje průměrný vážený dopad této kategorie. 


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
   <td>37
   </td>
   <td>13,77 %
   </td>
   <td>3,08 %
   </td>
   <td>100,00 %
   </td>
   <td>42,93 %
   </td>
   <td>7,15
   </td>
   <td>4,32
   </td>
   <td>1 404 249
   </td>
   <td>62 445
   </td>
  </tr>
</table>



## Popis

Zranitelnost typu injekce je chyba aplikace, která umožňuje odeslat nedůvěryhodný uživatelský vstup do interpretu (např. prohlížeči, databázi nebo příkazové řádce) a způsobuje, že interpret provede části tohoto vstupu jako příkazy. 

Aplikace je zranitelná vůči útoku, pokud:

* Uživatelem dodaná data nejsou aplikací validována, filtrována ani sanitizována.
* Dynamické dotazy nebo volání bez parametrizace a bez kontextově závislého escapování jsou používány přímo v interpretu.
* Neočištěná (nesanitizovaná) data jsou použita v parametrech vyhledávání ORM (objektově-relační mapování) k získání dalších citlivých záznamů.
* Potenciálně nepřátelská data jsou přímo použita nebo zřetězena. Výsledný SQL dotaz nebo příkaz pak obsahuje jak strukturu, tak i škodlivá data – v dynamických dotazech, příkazech nebo uložených procedurách.

Mezi nejčastější typy injekcí patří SQL, NoSQL, OS command, Object Relational Mapping (ORM), LDAP a Expression Language (EL) nebo Object Graph Navigation Library (OGNL) injekce. Princip je napříč interpretry stejný. Detekce se nejlépe provádí kombinací kontroly zdrojového kódu a automatizovaného testování (včetně fuzzingu) všech vstupů: parametrů, hlaviček, URL, cookies a datových vstupů ve formátech JSON, SOAP a XML. Zařazení nástrojů SAST, DAST a IAST do CI/CD pipeline může pomoci odhalit injekční zranitelnosti ještě před nasazením do produkce.

V souvislosti s LLM se rozšířila i příbuzná třída injekčních zranitelností. Těm se samostatně věnuje [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/), konkrétně [LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).


## Jak tomu zabránit

Nejlepší způsob, jak zabránit injekci, vyžaduje oddělit data od příkazů a dotazů:

* Preferovanou možností je použití bezpečného API, které se zcela vyhne použití interpretu, poskytuje parametrizované rozhraní nebo umožní migraci na nástroje pro objektově-relační mapování (ORM). 
**Poznámka:** I když jsou uložené procedury parametrizované, mohou stále vést k SQL injekci, pokud PL/SQL nebo T-SQL zřetězí dotazy a data nebo vykoná nepřátelská data pomocí EXECUTE IMMEDIATE nebo exec().

Pokud není možné oddělit data od příkazů, můžete hrozby snížit pomocí následujících technik. 

* Používejte pozitivní validaci vstupů na straně serveru. Nejedná se o úplnou ochranu, protože mnoho aplikací vyžaduje speciální znaky, například v textových polích nebo v API pro mobilní aplikace.
* U všech zbývajících dynamických dotazů escapujte speciální znaky pomocí konkrétní escape syntaxe daného interpretu. 
**Poznámka:** SQL struktury, jako jsou názvy tabulek, názvy sloupců apod., nelze escapovat, a proto jsou názvy struktur dodané uživatelem nebezpečné. Jde o běžný problém v softwaru pro tvorbu reportů.

**Upozornění:** Tyto techniky zahrnují parsování a escapování složitých řetězců, což je činí náchylnými k chybám a málo odolnými vůči drobným změnám v základním systému. 

## Příklady scénářů útoků

**Scénář #1:** Aplikace používá nedůvěryhodná data při sestavování následujícího zranitelného SQL volání:

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

Útočník upraví hodnotu parametru id ve svém prohlížeči tak, aby odeslal: `' OR '1'='1`. Například:

```
http://example.com/app/accountView?id=' OR '1'='1
```

Tím se změní význam dotazu tak, že vrátí všechny záznamy z tabulky accounts. Nebezpečnější útoky by mohly upravit nebo smazat data, nebo dokonce vyvolat uložené procedury.

**Scénář #2:** Slepá důvěra aplikace frameworkům může vést k dotazům, které jsou stále zranitelné. Například Hibernate Query Language (HQL):

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Útočník zadá: `' OR custID IS NOT NULL OR custID='`. Tím obejde filtr a vrátí všechny účty. Přestože HQL obsahuje méně nebezpečných funkcí než „čisté“ SQL, při konkatenaci (zřetězení) uživatelského vstupu do dotazů stále umožňuje neoprávněný přístup k datům.

**Scénář #3:** Aplikace předává uživatelský vstup přímo do příkazu operačního systému:

```
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
```

Útočník zadá příkaz `example.com; cat /etc/passwd`, aby provedl libovolné příkazy na serveru.

## Reference

* [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection), and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
* [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)
* [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing) 



## Seznam mapovaných CWE

* [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

* [CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

* [CWE-76 Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)

* [CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

* [CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

* [CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

* [CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

* [CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

* [CWE-86 Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html)

* [CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

* [CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

* [CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

* [CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

* [CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

* [CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

* [CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

* [CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

* [CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

* [CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

* [CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

* [CWE-103 Struts: Incomplete validate() Method Definition](https://cwe.mitre.org/data/definitions/103.html)

* [CWE-104 Struts: Form Bean Does Not Extend Validation Class](https://cwe.mitre.org/data/definitions/104.html)

* [CWE-112 Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)

* [CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

* [CWE-114 Process Control](https://cwe.mitre.org/data/definitions/114.html)

* [CWE-115 Misinterpretation of Output](https://cwe.mitre.org/data/definitions/115.html)

* [CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

* [CWE-129 Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)

* [CWE-159 Improper Handling of Invalid Use of Special Elements](https://cwe.mitre.org/data/definitions/159.html)

* [CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

* [CWE-493 Critical Public Variable Without Final Modifier](https://cwe.mitre.org/data/definitions/493.html)

* [CWE-500 Public Static Field Not Marked Final](https://cwe.mitre.org/data/definitions/500.html)

* [CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

* [CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

* [CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

* [CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

* [CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
