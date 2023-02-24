# A02:2021 – Fallas Criptográficas    ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Factores

| CWEs mapeadas | Tasa de incidencia máx | Tasa de incidencia prom | Explotabilidad ponderada prom| Impacto ponderado prom | Cobertura máx | Cobertura prom | Incidencias totales | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              |7.29                 | 6.81                |  79.33%       | 34.85%       | 233,788           | 3,075      |

## Resumen

Subiendo una posición al número 2, anteriormente conocido como *Exposición de datos sensibles*, que es más un amplio síntoma que una causa raíz, la atención se centra en las fallas relacionadas con la criptografía (o la falta de ésta).
Esto a menudo conduce a la exposición de datos sensibles. Las CWE incluidas son *CWE-259: Uso de contraseña en código fuente*, *CWE-327: Algoritmo criptográfico vulnerado o inseguro* y *CWE-331: Entropía insuficiente*.

## Descripción

Lo primero es determinar las necesidades de protección de los datos en tránsito y en reposo. Por ejemplo, contraseñas, números de tarjetas de crédito, registros médicos, información personal y secretos comerciales requieren protección adicional, principalmente si están sujetos a leyes de privacidad (por ejemplo, el Reglamento General de Protección de Datos -GDPR- de la UE), o regulaciones, (por ejemplo, protección de datos financieros como el Estándar de Seguridad de Datos de PCI -PCI DSS-).
Para todos esos datos:

-   ¿Se transmiten datos en texto claro? Esto se refiere a protocolos como HTTP, SMTP, FTP que también utilizan actualizaciones de TLS como STARTTLS. El tráfico externo de Internet es peligroso. Verifique todo el tráfico interno, por ejemplo, entre balanceadores de carga, servidores web o sistemas de back-end.

-   ¿Se utilizan algoritmos o protocolos criptográficos antiguos o débiles de forma predeterminada o en código antiguo?

-   ¿Se utilizan claves criptográficas predeterminadas, se generan o reutilizan claves criptográficas débiles, o es inexistente la gestión o rotación de claves adecuadas?
    ¿Se incluyen las claves criptográficas en los repositorios de código fuente?

-   ¿No es forzado el cifrado, por ejemplo, faltan las directivas de seguridad de los encabezados HTTP (navegador) o los encabezados?

-   ¿El certificado de servidor recibido y la cadena de confianza se encuentran debidamente validados?

-   ¿Los vectores de inicialización se ignoran, se reutilizan o no se generan de forma suficientemente seguros para el modo de operación criptográfico?
    ¿Se utiliza un modo de funcionamiento inseguro como el ECB? ¿Se utiliza un cifrado cuando el cifrado autenticado es más apropiada?

-   ¿Las contraseñas se utilizan como claves criptográficas en ausencia de una función de derivación de claves a partir de contraseñas?

-   ¿Se utiliza con fines criptográficos generadores de aleatoriedad que no fueron diseñaron para dicho fin? Incluso si se elige la función correcta, debe ser inicializada (seed) por el desarrollador y, de no ser así, ¿el desarrollador ha sobrescrito la funcionalidad de semilla fuerte incorporada con una semilla que carece de suficiente entropía/imprevisibilidad?

-   ¿Se utilizan funciones hash en obsoletas, como MD5 o SHA1, o se utilizan funciones hash no criptográficas cuando se necesitan funciones hash criptográficas?

-   ¿Se utilizan métodos criptográficos de relleno(padding) obsoletos, como PKCS número 1 v1.5?

-   ¿Se pueden explotar los mensajes de errores criptográficos como un canal lateral, por ejemplo, en forma de ataques de  criptoanálisis por modificación relleno (Oracle Padding)?

Consulte ASVS Crypto (V7), Data Protection (V9) y SSL/TLS (V10)

## Cómo se previene

Haga lo siguiente como mínimo, y consulte las referencias:

-   Clasifique los datos procesados, almacenados o transmitidos por una aplicación.
    Identifique qué datos son confidenciales de acuerdo con las leyes de privacidad, los requisitos reglamentarios o las necesidades comerciales.

-   No almacene datos sensibles innecesariamente. Descártelos lo antes posible o utilice una utilización de tokens compatible con PCI DSS o incluso el truncamiento.
    Los datos que no se conservan no se pueden robar.

-   Asegúrese de cifrar todos los datos sensibles en reposo (almacenamiento).

-   Garantice la implementación de algoritmos, protocolos y claves que utilicen estándares sólidos y actualizados; utilice una gestión de claves adecuada.

-   Cifre todos los datos en tránsito con protocolos seguros como TLS con cifradores de confidencialidad adelantada (forward secrecy, o FS), priorización de cifradores por parte del servidor y parámetros seguros. Aplique el cifrado mediante directivas como HTTP Strict Transport Security (HSTS).

-   Deshabilite el almacenamiento en caché para respuestas que contengan datos sensibles.

-   Aplique los controles de seguridad requeridos según la clasificación de los datos.

-   No utilice protocolos antiguos como FTP y SMTP para transportar datos sensibles.

-   Almacene las contraseñas utilizando funciones robustas, flexibles, que utilicen sal en los hashes y use un factor de retraso (factor de trabajo), como Argon2, scrypt, bcrypt o PBKDF2.

-   Elija vectores de inicialización apropiados para el modo de operación. Para muchos modos, esto significa usar un CSPRNG (generador de números pseudoaleatorios criptográficamente seguro).  Para los modos que requieren un nonce, el vector de inicialización (IV) no necesita un CSPRNG.  En todos los casos, el IV nunca debe usarse dos veces para una clave fija.

-   Utilice siempre cifrado autenticado en lugar de solo cifrado.

-   Las claves deben generarse criptográficamente al azar y almacenarse en la memoria como arrays de bytes. Si se utiliza una contraseña, debe convertirse en una clave mediante una función adecuada de derivación de claves basada en contraseña.

-   Asegúrese de que se utilice la aleatoriedad criptográfica cuando sea apropiado y que no se utilice una semilla de una manera predecible o con baja entropía.
    La mayoría de las API modernas no requieren que el desarrollador genere el CSPRNG para obtener seguridad.

-   Evite las funciones criptográficas y los esquemas de relleno(padding) en desuso, como MD5, SHA1, PKCS número 1 v1.5.

-   Verifique de forma independiente la efectividad de la configuración y los ajustes.

## Ejemplos de escenarios de ataque

**Escenario #1**: Una aplicación cifra los números de tarjetas de crédito en una base de datos mediante el cifrado automático de la base de datos. Sin embargo, estos datos se descifran automáticamente cuando se recuperan, lo que permite que por una falla de inyección SQL se recuperen números de tarjetas de crédito en texto sin cifrar.

**Escenario #2**: Un sitio no utiliza ni aplica TLS para todas sus páginas o admite un cifrado débil. Un atacante monitorea el tráfico de la red (por ejemplo, en una red inalámbrica insegura), degrada las conexiones de HTTPS a HTTP, intercepta solicitudes y roba la cookie de sesión del usuario. El atacante luego reutiliza esta cookie y secuestra la sesión (autenticada) del usuario, accediendo o modificando los datos privados del usuario. En lugar de lo anterior, podrían alterar todos los datos transportados, por ejemplo, el destinatario de una transferencia de dinero.

**Escenario #3**: La base de datos de contraseñas utiliza hashes simples o sin un valor inicial aleatorio único(salt) para almacenar todas las contraseñas. Una falla en la carga de archivos permite a un atacante recuperar la base de datos de contraseñas. Todos los hashes sin salt se pueden calcular a partir de una rainbow table de hashes pre calculados. Los hash generados por funciones hash simples o rápidas pueden ser descifrados a través de cálculos intensivos provistos por una o mas GPUs, incluso si utilizan un salt.

## Referencias

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Password and Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)

## Lista de CWEs mapeadas

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
