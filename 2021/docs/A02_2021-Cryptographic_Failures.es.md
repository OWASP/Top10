# A02:2021 – Fallos criptográficos    ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png)

## Factores

| CWEs mapeadas | Tasa de incidencia máx | Tasa de incidencia prom | Explotabilidad ponderada prom| Impacto ponderado prom | Cobertura máx | Cobertura prom | Incidencias totales | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              |7.29                 | 6.81                |  79.33%       | 34.85%       | 233,788           | 3,075      |

## Resumen

Subiendo una posición al #2, anteriormente conocido como Exposición de datos sensibles, que es más un síntoma amplio que una causa raíz, la atención se centra en las fallas relacionadas con la criptografía (o la falta de ella).
Lo que a menudo conduce a la exposición de datos sensibles. Las enumeraciones de debilidades comunes (CWE) notables incluidas son *CWE-259: Uso de contraseña en código fuente*, *CWE-327: Algoritmo criptográfico vulnerado o inseguro* y *CWE-331: Entropía insuficiente*.

## Descripción

Lo primero es determinar las necesidades de protección de los datos en tránsito y en reposo. Por ejemplo, las contraseñas, los números de tarjetas de crédito, los registros médicos, la información personal y los secretos comerciales requieren protección adicional. Principalmente si esos datos están sujetos a leyes de privacidad, por ejemplo, el Reglamento General de Protección de Datos (GDPR) de la UE, o regulaciones, por ejemplo, protección de datos financieros como el Estándar de Seguridad de Datos de PCI (PCI DSS).
Para todos esos datos:

-   ¿Se transmiten datos en texto claro? Esto se refiere a protocolos como HTTP, SMTP, FTP que también utilizan actualizaciones de TLS como STARTTLS. El tráfico externo de Internet es peligroso. Verifique todo el tráfico interno, por ejemplo, entre balanceadores de carga, servidores web o sistemas de back-end.

-   ¿Se utilizan algoritmos o protocolos criptográficos antiguos o débiles de forma predeterminada o en código antiguo?

-   ¿Se utilizan claves criptográficas predeterminadas, se generan o reutilizan claves criptográficas débiles, o es inexistente la gestión o rotación de claves adecuadas?
    ¿Se registran las claves criptográficas en los repositorios de código fuente?

-   ¿No es aplicada la encriptación, por ejemplo, faltan las directivas de seguridad de los encabezados HTTP (navegador) o los encabezados?

-   ¿El certificado de servidor recibido y la cadena de confianza están debidamente validados?

-   ¿Los vectores de inicialización se ignoran, se reutilizan o no se generan lo suficientemente seguros para el modo de operación criptográfico?
    ¿Se utiliza un modo de funcionamiento inseguro como el ECB? ¿Se utiliza encriptación cuando la encriptación autenticada es más apropiada?

-   ¿Las contraseñas se utilizan como claves criptográficas en ausencia de una función de derivación de claves base de contraseñas?

-   ¿Se utiliza la aleatoriedad con fines criptográficos que no se diseñaron para cumplir con los requisitos criptográficos? Incluso si se elige la función correcta, debe ser sembrada por el desarrollador y, de no ser así, ¿el desarrollador ha sobrescrito la funcionalidad de siembra fuerte incorporada con una semilla que carece de suficiente entropía/imprevisibilidad?

-   ¿Se utilizan funciones hash en desuso, como MD5 o SHA1, o se utilizan funciones hash no criptográficas cuando se necesitan funciones hash criptográficas?

-   ¿Se utilizan métodos criptográficos de relleno(padding) obsoletos, como PCKS número 1 v1.5?

-   ¿Se pueden explotar los mensajes de error criptográficos o la información del canal lateral, por ejemplo, en forma de ataques de relleno(padding) de Oracle?

Consulte ASVS Crypto (V7), Protección de datos (V9) y SSL/TLS (V10)

## Cómo se previene

Haga lo siguiente, como mínimo, y consulte las referencias:

-   Clasifique los datos procesados, almacenados o transmitidos por una aplicación.
    Identifique qué datos son confidenciales de acuerdo con las leyes de privacidad, los requisitos reglamentarios o las necesidades comerciales.

-   No almacene datos sensibles innecesariamente. Deséchelos lo antes posible o utilice la tokenización compatible con PCI DSS o incluso el truncamiento.
    Los datos que no se conservan no se pueden robar.

-   Asegúrese de cifrar todos los datos confidenciales que no están en movimiento.

-   Garantice la implementación de algoritmos, protocolos y claves que sean estándar sólidos y actualizados; utilice una gestión de claves adecuada.

-   Cifre todos los datos en tránsito con protocolos seguros como TLS con cifrado de confidencialidad directa (FS), priorización de cifrado por parte del servidor y parámetros seguros. Aplique el cifrado mediante directivas como HTTP Strict Transport Security (HSTS).

-   Deshabilite el almacenamiento en caché para respuestas que contengan datos confidenciales.

-   Aplique los controles de seguridad requeridos según la clasificación de datos.

-   No utilice protocolos antiguos como FTP y SMTP para transportar datos confidenciales.

-   Almacene las contraseñas utilizando funciones robustas y flexibles de saltet hash y use un factor de trabajo (factor de retraso), como Argon2, scrypt, bcrypt o PBKDF2.

-   Elija los vectores de inicialización apropiados para el modo de operación. Para muchos modos, esto significa usar un CSPRNG (generador de números pseudoaleatorios criptográficamente seguro).  Para los modos que requieren un nonce, entonces el vector de inicialización (IV) no necesita un CSPRNG.  En todos los casos, el IV nunca debe usarse dos veces para una clave fija.

-   Utilice siempre cifrado autenticado en lugar de solo cifrado.

-   Las claves deben generarse criptográficamente al azar y almacenarse en la memoria como arrays de bytes. Si se utiliza una contraseña, debe convertirse en una clave mediante una función de derivación de clave de base de contraseña adecuada.

-   Asegúrese de que se utilice la aleatoriedad criptográfica cuando sea apropiado y que no se haya sembrado de una manera predecible o con baja entropía.
    La mayoría de las API modernas no requieren que el desarrollador genere el CSPRNG para obtener seguridad.

-   Evite las funciones criptográficas y los esquemas de relleno(padding) en desuso, como MD5, SHA1, PKCS número 1 v1.5.

-   Verifique de forma independiente la efectividad de la configuración y los ajustes.

## Ejemplos de escenarios de ataque

**Escenario #1**: Una aplicación cifra los números de tarjetas de crédito en una base de datos mediante el cifrado automático de la base de datos. Sin embargo, estos datos se descifran automáticamente cuando se recuperan, lo que permite que por un error de inyección SQL se recuperen números de tarjetas de crédito en texto sin cifrar.

**Escenario #2**: Un sitio no usa ni aplica TLS para todas las páginas o admite un cifrado débil. Un atacante monitorea el tráfico de la red (por ejemplo, en una red inalámbrica insegura), degrada las conexiones de HTTPS a HTTP, intercepta solicitudes y roba la cookie de sesión del usuario. El atacante luego reproduce esta cookie y secuestra la sesión (autenticada) del usuario, accediendo o modificando los datos privados del usuario. En lugar de lo anterior, podrían alterar todos los datos transportados, por ejemplo, el destinatario de una transferencia de dinero.

**Escenario #3**: La base de datos de contraseñas utiliza hashes simples o sin un valor inicial aleatorio único(salt) para almacenar todas las contraseñas. Una falla en la carga de archivos permite a un atacante recuperar la base de datos de contraseñas. Todos los hashes sin salt se pueden exponer con una tabla arcoíris de hashes precalculados. Los hash generados por funciones hash simples o rápidas pueden ser descifrados por las GPU, incluso si usan un salt.

## Referencias

-   [Controles proactivos de OWASP: proteja datos en todas partes](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [Estándar de verificación de seguridad de aplicaciones OWASP (V7, 9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Hoja de referencia: Protección de la capa de transporte](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Hoja de referencia: Protección de la privacidad del usuario](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   [OWASP Hoja de referencia: contraseña y almacenamiento criptográfico](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

-   [OWASP Hoja de referencia: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   [Guía de pruebas de OWASP: testeo de criptografía débil](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)


## Lista de CWEs mapeadas

[CWE-261 Codificación débil para contraseña](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Seguimiento indebido de la cadena de confianza de un certificado](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Problemas criptográficos](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Transmisión de texto sin cifrar con información confidencial](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Uso de clave criptográfica en código fuente](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Intercambio de claves sin autenticación de entidad](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reutilización de un par clave-nonce en cifrado](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Uso de una clave pasada su fecha de vencimiento](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Falta del paso criptográfico obligatorio](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Fuerza de cifrado inadecuada](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Uso de un algoritmo criptográfico vulnerado o inseguro](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Hash unidireccional reversible](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 No usar un IV aleatorio con el modo CBC](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Uso de valores insuficientemente aleatorios](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Entropía insuficiente](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Uso incorrecto de semillas en el generador de números pseudoaleatorios(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Misma semilla en el generador de números pseudoaleatorios(PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Semilla predecible en generador de números pseudoaleatorios(PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Uso de un generador de números pseudoaleatorios criptográficamente débil(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generación de números o identificadores predecibles](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Verificación incorrecta de la firma criptográfica](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Transporte de credenciales sin protección](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Categoría A9 - Comunicaciones inseguras](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selección de algoritmo menos seguro durante la negociación('degradación del algoritmo')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Uso de un hash unidireccional sin salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Uso de un hash unidireccional con un salt predecible](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Uso de algoritmo RSA sin OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Protección insuficiente de la capa de transporte](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Uso de hash de contraseña con esfuerzo computacional insuficiente](https://cwe.mitre.org/data/definitions/916.html)
