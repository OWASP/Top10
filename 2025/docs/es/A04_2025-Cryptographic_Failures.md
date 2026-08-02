# A04:2025 Fallas Criptográficas ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}



## Antecedentes.

Bajando dos posiciones hasta el #4, esta debilidad se centra en fallas relacionadas con la ausencia de criptografía, criptografía insuficientemente robusta, filtración de claves criptográficas y errores relacionados. Tres de los CWEs más comunes en este riesgo involucran el uso de un generador de números pseudoaleatorios débil: *CWE-327 Algoritmo Criptográfico Vulnerado o Inseguro, CWE-331: Entropía Insuficiente*, *CWE-1241: Uso de Algoritmo Predecible en Generador de Números Aleatorios*, y *CWE-338 Uso de un Generador de Números Pseudoaleatorios (PRNG Pseudo-random Number Generator) Criptográficamente Débil*.



## Factores.


<table>
  <tr>
   <td>CWEs Mapeados
   </td>
   <td>Tasa Máx. de Incidencia
   </td>
   <td>Tasa Prom. de Incidencia
   </td>
   <td>Cobertura Máx.
   </td>
   <td>Cobertura Prom.
   </td>
   <td>Explotabilidad Ponderada Prom.
   </td>
   <td>Impacto Ponderado Prom.
   </td>
   <td>Total de Ocurrencias
   </td>
   <td>Total de CVEs
   </td>
  </tr>
  <tr>
   <td>32
   </td>
   <td>13.77%
   </td>
   <td>3.80%
   </td>
   <td>100.00%
   </td>
   <td>47.74%
   </td>
   <td>7.23
   </td>
   <td>3.90
   </td>
   <td>1,665,348
   </td>
   <td>2,185
   </td>
  </tr>
</table>



## Descripción.

En términos generales, todos los datos en tránsito deben cifrarse en la [capa de transporte](https://en.wikipedia.org/wiki/Transport_layer) (capa 4 del [modelo OSI](https://en.wikipedia.org/wiki/OSI_model)). Obstáculos anteriores como el rendimiento de la CPU y la gestión de claves privadas/certificados ahora son manejados por CPUs con instrucciones diseñadas para acelerar el cifrado (p. ej., [soporte AES](https://en.wikipedia.org/wiki/AES_instruction_set)), y la gestión de claves privadas y certificados se ha simplificado mediante servicios como [LetsEncrypt.org](https://LetsEncrypt.org), con los principales proveedores de nube ofreciendo servicios de gestión de certificados aún más integrados para sus plataformas específicas.

Más allá de asegurar la capa de transporte, es importante determinar qué datos necesitan cifrado en reposo y qué datos requieren cifrado adicional en tránsito (en la [capa de aplicación](https://en.wikipedia.org/wiki/Application_layer), capa 7 del OSI). Por ejemplo, contraseñas, números de tarjetas de crédito, registros médicos, información personal y secretos comerciales requieren protección adicional, especialmente si esos datos están sujetos a leyes de privacidad como el Reglamento General de Protección de Datos (RGPD Règlement Général sur la Protection des Données (General Data Protection Regulation)) de la UE, o regulaciones como el Estándar de Seguridad de Datos PCI (PCI DSS). Para todos esos datos:



* ¿Se usan algoritmos o protocolos criptográficos antiguos o débiles, ya sea por defecto o en código heredado?
* ¿Se usan claves criptográficas predeterminadas, se generan claves débiles, se reutilizan claves, o falta una gestión y rotación adecuada de claves?
* ¿Se incluyen claves criptográficas en repositorios de código fuente?
* ¿No se aplica el cifrado? Por ejemplo, ¿faltan directivas o cabeceras de seguridad HTTP (del navegador)?
* ¿Se valida correctamente el certificado del servidor recibido y la cadena de confianza?
* ¿Se ignoran, reutilizan o generan de forma insegura los vectores de inicialización para el modo de operación criptográfico? ¿Se usa un modo de operación inseguro como ECB? ¿Se usa cifrado cuando el cifrado autenticado sería más apropiado?
* ¿Se usan contraseñas como claves criptográficas sin una función de derivación de claves basada en contraseña?
* ¿Se usa aleatoriedad no diseñada para cumplir requisitos criptográficos? Aunque se elija la función correcta, ¿necesita ser inicializada (seed) por el desarrollador y, de ser así, ha sobrescrito la funcionalidad de semilla fuerte incorporada con una semilla con entropía/imprevisibilidad insuficiente?
* ¿Se usan funciones hash obsoletas como MD5 o SHA1, o se usan funciones hash no criptográficas cuando se necesitan funciones hash criptográficas?
* ¿Son explotables los mensajes de error criptográficos o la información de canal lateral, por ejemplo en forma de ataques de relleno de oracle (padding oracle)?
* ¿Puede el algoritmo criptográfico ser degradado o eludido?

Consultar referencias ASVS: Criptografía (V11), Comunicación Segura (V12) y Protección de Datos (V14).


## Cómo se previene.

Como mínimo, hacer lo siguiente y consultar las referencias:



* Clasificar y etiquetar los datos procesados, almacenados o transmitidos por una aplicación. Identificar qué datos son sensibles según las leyes de privacidad, los requisitos regulatorios o las necesidades del negocio.
* Almacenar las claves más sensibles en un HSM físico o basado en la nube.
* Usar implementaciones bien reconocidas de algoritmos criptográficos siempre que sea posible.
* No almacenar datos sensibles innecesariamente. Descartarlos lo antes posible o usar tokenización conforme a PCI DSS (Payment Card Industry Data Security Standard) (Estándar de Seguridad de Datos de la Industria de Tarjetas de Pago) o incluso truncamiento. Los datos que no se retienen no pueden ser robados.
* Asegurarse de cifrar todos los datos sensibles en reposo.
* Garantizar que estén en uso algoritmos, protocolos y claves estándar actualizados y robustos; usar una gestión de claves adecuada.
* Cifrar todos los datos en tránsito con protocolos >= TLS 1.2 únicamente, con cifradores de secreto hacia adelante (forward secrecy, FS), eliminar soporte para cifrados en modo CBC, soportar algoritmos de intercambio de claves cuánticos. Para HTTPS, aplicar cifrado mediante HTTP Strict Transport Security (HSTS). Verificar todo con una herramienta.
* Deshabilitar el caché para respuestas que contengan datos sensibles. Esto incluye el caché en el CDN, el servidor web y cualquier caché de aplicación (p. ej., Redis).
* Aplicar los controles de seguridad requeridos según la clasificación de datos.
* No usar protocolos sin cifrado como FTP y STARTTLS. Evitar usar SMTP para transmitir datos confidenciales.
* Almacenar contraseñas usando funciones de hashing robustas, adaptativas y con sal (salt), con un factor de trabajo (factor de retardo), como Argon2, yescrypt, scrypt o PBKDF2-HMAC-SHA-512. Para sistemas heredados que usan bcrypt, consultar la [Guía de referencia rápida de OWASP: Almacenamiento de Contraseñas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* Los vectores de inicialización deben elegirse apropiadamente para el modo de operación. Esto puede significar usar un CSPRNG (generador de números pseudoaleatorios criptográficamente seguro). Para modos que requieren un nonce, el vector de inicialización (IV) no necesita un CSPRNG. En todos los casos, el IV nunca debe usarse dos veces para una clave fija.
* Usar siempre cifrado autenticado en lugar de solo cifrado.
* Las claves deben generarse criptográficamente de forma aleatoria y almacenarse en memoria como arreglos de bytes. Si se usa una contraseña, debe convertirse en clave mediante una función de derivación de clave basada en contraseña apropiada.
* Asegurarse de que se use aleatoriedad criptográfica donde corresponda y que no haya sido inicializada (seeded) de forma predecible o con baja entropía. La mayoría de las APIs modernas no requieren que el desarrollador inicialice el CSPRNG para que sea seguro.
* Evitar funciones criptográficas obsoletas, métodos de construcción de bloques y esquemas de relleno (padding), como MD5, SHA1, Modo de Encadenamiento de Bloques (CBC), PKCS número 1 v1.5.
* Asegurarse de que las configuraciones y ajustes cumplan los requisitos de seguridad mediante revisión por especialistas en seguridad, herramientas diseñadas para este propósito, o ambos.
* Es necesario prepararse ahora para la criptografía poscuántica (PQC), ver referencia (ENISA), para que los sistemas de alto riesgo estén protegidos a más tardar a finales de 2030.


## Ejemplos de escenarios de ataque.

**Escenario #1**: Un sitio no usa ni exige TLS en todas las páginas, o admite cifrado débil. Un atacante monitorea el tráfico de red (p. ej., en una red inalámbrica insegura), degrada las conexiones de HTTPS a HTTP, intercepta solicitudes y roba la cookie de sesión del usuario. El atacante luego reproduce esta cookie y secuestra la sesión (autenticada) del usuario, accediendo o modificando los datos privados del usuario. Alternativamente, podría alterar todos los datos transportados, por ejemplo, el destinatario de una transferencia de dinero.

**Escenario #2**: La base de datos de contraseñas usa hashes sin sal (salt) o hashes simples para almacenar todas las contraseñas. Un fallo de carga de archivos permite a un atacante recuperar la base de datos de contraseñas. Todos los hashes sin salt pueden quedar expuestos con una tabla arcoiris (rainbow table) de hashes precalculados. Los hashes generados por funciones hash simples o rápidas pueden ser descifrados por GPUs, incluso si tenían sal.


## Referencias.



* [OWASP Controles Proactivos: C2: Usar Criptografía para Proteger Datos](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
* [Estándar de Verificación de Seguridad de Aplicaciones OWASP (ASVS): ](https://owasp.org/www-project-application-security-verification-standard) [V11,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x20-V11-Cryptography.md) [12, ](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md) [14](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md)
* [Guía de referencia rápida de OWASP: Protección de la Capa de Transporte](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
* [Guía de referencia rápida de OWASP: Protección de Privacidad del Usuario](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [Guía de referencia rápida de OWASP: Almacenamiento de Contraseñas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [Guía de referencia rápida de OWASP: Almacenamiento Criptográfico](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [Guía de referencia rápida de OWASP: HSTS (Seguridad de Transporte Estricta HTTP)](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [Guía de Pruebas OWASP: Pruebas de Criptografía Débil](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
* [ENISA: Hoja de Ruta de Implementación Coordinada para la Transición a la Criptografía Poscuántica](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
* [NIST publica los primeros 3 Estándares de Cifrado Poscuántico finalizados](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)


## Lista de CWEs Mapeados

* [CWE-261 Codificación Débil para Contraseñas (Weak Encoding for Password)](https://cwe.mitre.org/data/definitions/261.html)

* [CWE-296 Seguimiento Inadecuado de la Cadena de Confianza de un Certificado (Improper Following of a Certificate's Chain of Trust)](https://cwe.mitre.org/data/definitions/296.html)

* [CWE-319 Transmisión en Texto Plano de Información Sensible (Cleartext Transmission of Sensitive Information)](https://cwe.mitre.org/data/definitions/319.html)

* [CWE-320 Errores en la Gestión de Claves (Key Management Errors) (Prohibido)](https://cwe.mitre.org/data/definitions/320.html)

* [CWE-321 Uso de Clave Criptográfica Embebida (quemada) en el Código (Use of Hard-coded Cryptographic Key)](https://cwe.mitre.org/data/definitions/321.html)

* [CWE-322 Intercambio de Claves sin Autenticación de Entidad (Key Exchange without Entity Authentication)](https://cwe.mitre.org/data/definitions/322.html)

* [CWE-323 Reutilización de un Nonce o Par de Claves en el Cifrado (Reusing a Nonce, Key Pair in Encryption)](https://cwe.mitre.org/data/definitions/323.html)

* [CWE-324 Uso de una Clave Más Allá de su Fecha de Expiración (Use of a Key Past its Expiration Date)](https://cwe.mitre.org/data/definitions/324.html)

* [CWE-325 Paso Criptográfico Requerido Faltante (Missing Required Cryptographic Step)](https://cwe.mitre.org/data/definitions/325.html)

* [CWE-326 Fortaleza de Cifrado Inadecuada (Inadequate Encryption Strength)](https://cwe.mitre.org/data/definitions/326.html)

* [CWE-327 Algoritmo Criptográfico Vulnerado o Riesgoso (Use of a Broken or Risky Cryptographic Algorithm)](https://cwe.mitre.org/data/definitions/327.html)

* [CWE-328 Hash Unidireccional Reversible (Reversible One-Way Hash)](https://cwe.mitre.org/data/definitions/328.html)

* [CWE-329 No Usar un IV Aleatorio con el Modo CBC (Not Using a Random IV with CBC Mode)](https://cwe.mitre.org/data/definitions/329.html)

* [CWE-330 Uso de Valores Insuficientemente Aleatorios (Use of Insufficiently Random Values)](https://cwe.mitre.org/data/definitions/330.html)

* [CWE-331 Entropía Insuficiente (Insufficient Entropy)](https://cwe.mitre.org/data/definitions/331.html)

* [CWE-332 Entropía Insuficiente en el PRNG (Insufficient Entropy in PRNG)](https://cwe.mitre.org/data/definitions/332.html)

* [CWE-334 Espacio Pequeño de Valores Aleatorios (Small Space of Random Values)](https://cwe.mitre.org/data/definitions/334.html)

* [CWE-335 Uso Incorrecto de Semillas en el Generador de Números Pseudoaleatorios (Incorrect Usage of Seeds in Pseudo-Random Number Generator) (PRNG)](https://cwe.mitre.org/data/definitions/335.html)

* [CWE-336 Misma Semilla en el Generador de Números Pseudoaleatorios (Same Seed in Pseudo-Random Number Generator) (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

* [CWE-337 Semilla Predecible en el Generador de Números Pseudoaleatorios (Predictable Seed in Pseudo-Random Number Generator) (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

* [CWE-338 Uso de un Generador de Números Pseudoaleatorios Criptográficamente Débil (Use of Cryptographically Weak Pseudo-Random Number Generator) (PRNG)](https://cwe.mitre.org/data/definitions/338.html)

* [CWE-340 Generación de Números o Identificadores Predecibles (Generation of Predictable Numbers or Identifiers)](https://cwe.mitre.org/data/definitions/340.html)

* [CWE-342 Valor Exacto Predecible a Partir de Valores Anteriores (Predictable Exact Value from Previous Values)](https://cwe.mitre.org/data/definitions/342.html)

* [CWE-347 Verificación Inadecuada de Firma Criptográfica (Improper Verification of Cryptographic Signature)](https://cwe.mitre.org/data/definitions/347.html)

* [CWE-523 Transporte Desprotegido de Credenciales (Unprotected Transport of Credentials)](https://cwe.mitre.org/data/definitions/523.html)

* [CWE-757 Selección de Algoritmo Menos Seguro Durante la Negociación (Selection of Less-Secure Algorithm During Negotiation) ('Degradación de Algoritmo' / 'Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

* [CWE-759 Uso de Hash Unidireccional sin Sal (Use of a One-Way Hash without a Salt)](https://cwe.mitre.org/data/definitions/759.html)

* [CWE-760 Uso de Hash Unidireccional con Sal Predecible (Use of a One-Way Hash with a Predictable Salt)](https://cwe.mitre.org/data/definitions/760.html)

* [CWE-780 Uso del Algoritmo RSA sin OAEP (Use of RSA Algorithm without OAEP)](https://cwe.mitre.org/data/definitions/780.html)

* [CWE-916 Uso de Hash de Contraseña con Esfuerzo Computacional Insuficiente (Use of Password Hash With Insufficient Computational Effort)](https://cwe.mitre.org/data/definitions/916.html)

* [CWE-1240 Uso de una Primitiva Criptográfica con una Implementación Riesgosa (Use of a Cryptographic Primitive with a Risky Implementation)](https://cwe.mitre.org/data/definitions/1240.html)

* [CWE-1241 Uso de Algoritmo Predecible en Generador de Números Aleatorios (Use of Predictable Algorithm in Random Number Generator)](https://cwe.mitre.org/data/definitions/1241.html)