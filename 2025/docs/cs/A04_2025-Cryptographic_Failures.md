# A04:2025 Kryptografická selhání ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}



## Pozadí

Tato slabina, která se v žebříčku posunula o dvě pozice níže na 4. místo, se zaměřuje na selhání související s nepoužitím kryptografie, použitím nedostatečně silné kryptografie, únikem kryptografických klíčů a dalšími souvisejícími chybami. Tři z nejčastějších CWE (Common Weakness Enumerations) v rámci tohoto rizika souvisely s použitím slabého pseudonáhodného generátoru čísel: *CWE-327 Use of a Broken or Risky Cryptographic Algorithm, CWE-331: Insufficient Entropy*, *CWE-1241: Use of Predictable Algorithm in Random Number Generator*, a *CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)*.



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
   <td>32
   </td>
   <td>13,77 %
   </td>
   <td>3,80 %
   </td>
   <td>100,00 %
   </td>
   <td>47,74 %
   </td>
   <td>7,23
   </td>
   <td>3,90
   </td>
   <td>1 665 348
   </td>
   <td>2 185
   </td>
  </tr>
</table>



## Popis

Obecně řečeno by všechna přenášená data měla být šifrována na [transportní vrstvě](https://en.wikipedia.org/wiki/Transport_layer) (vrstva 4 [modelu OSI](https://en.wikipedia.org/wiki/OSI_model)). Dřívější překážky, jako je výkon CPU a správa soukromých klíčů a certifikátů, jsou dnes řešeny jednak procesory s instrukcemi určenými k urychlení šifrování (např. [podpora AES](https://en.wikipedia.org/wiki/AES_instruction_set)) jednak zjednodušenou správou soukromých klíčů a certifikátů prostřednictvím služeb, jako je [LetsEncrypt.org](https://LetsEncrypt.org), přičemž hlavní poskytovatelé cloudových služeb nabízejí pro své konkrétní platformy ještě těsněji integrované služby správy certifikátů. 

Kromě zabezpečení transportní vrstvy je důležité určit, která data vyžadují šifrování v klidu a která data vyžadují dodatečné šifrování při přenosu (na [aplikační vrstvě](https://en.wikipedia.org/wiki/Application_layer), 7. vrstvě modelu OSI). Například hesla, čísla kreditních karet, zdravotní záznamy, osobní údaje a obchodní tajemství vyžadují zvláštní ochranu, zejména pokud se na tato data vztahují právní předpisy na ochranu soukromí, např. obecné nařízení EU o ochraně osobních údajů (GDPR), nebo standardy jako PCI Data Security Standard (PCI DSS). Pro všechna taková data (je třeba posoudit následující skutečnosti):

* Nejsou používány zastaralé nebo slabé kryptografické algoritmy či protokoly, a to buď ve výchozím nastavení, nebo ve starším kódu?
* Nejsou používány výchozí kryptografické klíče, nejsou generovány slabé kryptografické klíče, nejsou klíče znovu používány a nechybí řádná správa a rotace klíčů?
* Nejsou kryptografické klíče commitovány do repozitářů zdrojového kódu?
* Je šifrování vynucováno (tj. nechybí některé bezpečnostní direktivy nebo hlavičky HTTP (prohlížeče))?
* Je přijatý serverový certifikát a řetězec důvěry správně ověřován?
* Nejsou inicializační vektory ignorovány, znovu používány nebo generovány nedostatečně bezpečně pro použitý režim činnosti kryptografického algoritmu? Není používán nezabezpečený režim činnosti, jako je ECB? Není používáno neautentizované šifrování v případech, kdy je vhodnější autentizované šifrování?
* Nejsou hesla používána jako kryptografické klíče bez použití funkce pro odvození klíče z hesla (KDF)?
* Není používána náhodnost, která nebyla navržena tak, aby splňovala kryptografické požadavky? Pokud je zvolena správná funkce, nevyžaduje seedování ze strany vývojáře, a pokud ano, nebyl mechanismus silného seedování přepsán seedem s nedostatečnou entropií/nepředvídatelností?
* Nejsou používány zastaralé hashovací funkce, jako MD5 nebo SHA1, nebo nejsou používány nekryptografické hashovací funkce v případech, kdy jsou vyžadovány kryptografické hashovací funkce?
* Nejsou kryptografické chybové zprávy nebo informace z vedlejších kanálů zneužitelné, např. formou útoků typu padding oracle?
* Nelze kryptografický algoritmus downgradovat nebo obejít?

Viz reference ASVS: Cryptography (V11), Secure Communication (V12) a Data Protection (V14).


## Jak tomu zabránit

Proveďte alespoň následující kroky a prostudujte odkazy:

* Klasifikujte a označujte data, která aplikace zpracovává, ukládá nebo přenáší. Identifikujte, která data jsou citlivá, podle zákonů na ochranu soukromí, regulatorních požadavků nebo byznysových potřeb.
* Nejcitlivější klíče ukládejte do hardwarového nebo cloudového HSM (Hardware Security Module).
* Používejte dobře důvěryhodné implementace kryptografických algoritmů, kdykoli je to možné.
* Neukládejte citlivá data zbytečně. Zahoďte je co nejdříve nebo použijte tokenizaci v souladu s PCI DSS, nebo i trunkaci. Data, která nejsou uchovávána, nemohou být ukradena.
* Ujistěte se, že jsou všechna citlivá data v klidovém stavu šifrována.
* Zajistěte, aby byly používány aktuální a silné standardní algoritmy, protokoly a klíče; používejte správnou správu klíčů.
* Šifrujte všechna data při přenosu pouze pomocí protokolů ≥ TLS 1.2, se šiframi s forward secrecy (FS), ukončete podporu šifer cipher block chaining (CBC), podporujte algoritmy pro kvantovou výměnu klíčů. Pro HTTPS vynucujte šifrování pomocí HTTP Strict Transport Security (HSTS). Vše prověřujte pomocí nástroje.
* Zakažte ukládání do mezipaměti pro odpovědi, které obsahují citlivá data. To zahrnuje ukládání do mezipaměti ve vašem CDN, webovém serveru a jakékoli aplikační mezipaměti (např. Redis).
* Použijte požadované bezpečnostní kontroly podle klasifikace dat.
* Nepoužívejte nešifrované protokoly, jako jsou FTP a STARTTLS. Vyhněte se používání SMTP pro přenos důvěrných dat.
* Ukládejte hesla pomocí silných adaptivních a solí opatřených hashovacích funkcí s pracovním faktorem (faktorem zpoždění), jako jsou Argon2, yescrypt, scrypt nebo PBKDF2-HMAC-SHA-512. Pro starší systémy používající bcrypt získejte další doporučení v [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
* Inicializační vektory musí být voleny vhodně pro daný režim činnosti. To může znamenat použití CSPRNG (kryptograficky bezpečného pseudonáhodného generátoru čísel). Pro režimy, které vyžadují nonce, inicializační vektor (IV) nemusí používat CSPRNG. Ve všech případech by IV nikdy neměl být použit dvakrát s použitím téhož klíče.
* Vždy používejte autentizované šifrování namísto pouhého šifrování.
* Klíče by měly být generovány kryptograficky náhodně a ukládány v paměti jako pole bajtů. Pokud je použito heslo, musí být převedeno na klíč pomocí vhodné heslem založené funkce pro odvození klíče.
* Zajistěte, aby byla kryptografická náhodnost používána tam, kde je to vhodné, a aby nebyla seedována předvídatelným způsobem nebo s nízkou entropií. Většina moderních API nevyžaduje, aby vývojář seedoval CSPRNG, aby bylo bezpečné.
* Vyhýbejte se zastaralým kryptografickým funkcím, metodám blokové konstrukce a schématům vycpávání (padding), jako jsou MD5, SHA1, Cipher Block Chaining Mode (CBC), PKCS number 1 v1.5.
* Zajistěte, aby nastavení a konfigurace splňovaly bezpečnostní požadavky tím, že budou přezkoumány bezpečnostními specialisty, nástroji určenými k tomuto účelu, nebo obojím.
* Potřebujete se již nyní připravit na post-kvantovou kryptografii (PQC), viz odkaz (ENISA), aby systémy s vysokým rizikem byly bezpečné nejpozději do konce roku 2030.


## Příklady scénářů útoků 

**Scénář #1**: Webová aplikace nepoužívá nebo nevynucuje TLS pro všechny stránky, případně podporuje slabé šifrování. Útočník monitoruje síťový provoz (například v nezabezpečené bezdrátové síti), provede downgrade spojení z HTTPS na HTTP, zachytí požadavky a ukradne session cookie uživatele. Útočník tuto cookie následně přehraje (replay) a unese (autentizovanou) relaci uživatele, čímž získá přístup k soukromým datům uživatele nebo je může měnit. Namísto výše uvedeného může také měnit veškerá přenášená data, například příjemce peněžního převodu.

**Scénář #2**: Databáze hesel používá k ukládání hesel všech uživatelů nesolené nebo jednoduché hashovací funkce. Chyba v nahrávání souborů umožní útočníkovi získat databázi hesel. Všechny nesolené hashe mohou být odhaleny pomocí rainbow tabulky s předpočítanými hashi. Hashe generované jednoduchými nebo rychlými hashovacími funkcemi mohou být prolomeny pomocí GPU, i když byly solené.


## Reference



* [OWASP Proactive Controls: C2: Use Cryptography to Protect Data ](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
* [OWASP Application Security Verification Standard (ASVS): ](https://owasp.org/www-project-application-security-verification-standard) [V11,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x20-V11-Cryptography.md) [12, ](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md) [14](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md)
* [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
* [ENISA: A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
* [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)


## Seznam mapovaných CWE

* [CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

* [CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

* [CWE-320 Key Management Errors (Prohibited)](https://cwe.mitre.org/data/definitions/320.html)

* [CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

* [CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

* [CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

* [CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

* [CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

* [CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

* [CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

* [CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

* [CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

* [CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

* [CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

* [CWE-332 Insufficient Entropy in PRNG](https://cwe.mitre.org/data/definitions/332.html)

* [CWE-334 Small Space of Random Values](https://cwe.mitre.org/data/definitions/334.html)

* [CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

* [CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

* [CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

* [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

* [CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

* [CWE-342 Predictable Exact Value from Previous Values](https://cwe.mitre.org/data/definitions/342.html)

* [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

* [CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

* [CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

* [CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

* [CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

* [CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

* [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

* [CWE-1240 Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)

* [CWE-1241 Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)
