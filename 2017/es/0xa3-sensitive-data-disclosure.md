# A3:2017 Exposición de Datos Sensibles

| Agentes de amenaza/Vectores de ataque | Debilidades de seguridad         |      Impactos       |
| -- | -- | -- |
| Nivel de acceso : Explotabilidad 2    | Prevalencia 3 : Detectabilidad 2 | Técnico 3 : Negocio |
| En lugar de atacar directamente la criptografía, los atacantes roban claves, ejecutan ataques de intermediarios (Man in the Middle) o roban datos en texto plano del servidor, mientras se encuentran en tránsito, o del cliente (por ejemplo del navegador). Generalmente se requiere un ataque manual. Incluso, bases de datos con contraseñas que han sido hechas públicas pueden utilizarse para obtener las contraseñas originales utilizando GPUs (Unidades de Procesamiento Gráfico)| En los últimos años, este ha sido el ataque más común de gran impacto. El defecto más común es simplemente no cifrar datos sensibles. Cuando se emplea criptografía, es común la generación y gestión de claves débiles o el uso de algoritmos, cifradores y protocolos débiles, en particular técnicas débiles de hashing para el almacenamiento de contraseñas. Para los datos en tránsito las debilidades son fáciles de detectar, mientras que para los datos almacenados es muy difícil. Ambos con una explotabilidad muy variable. | Los fallos con frecuencia comprometen todos los datos que deberían estar protegidos. Típicamente, esta información incluye información personal sensible (PII) como registros de salud, credenciales, datos personales, tarjetas de crédito, que a menudo requiere protección según lo definido por las leyes o reglamentos como el PIBR de la UE o las leyes locales de privacidad. |

## ¿La aplicación es vulnerable?

Lo primero es determinar las necesidades de protección de los datos en tránsito y en almacenamiento. Por ejemplo, contraseñas, números de tarjetas de crédito, registros médicos, información personal y datos sensibles del negocio requieren una protección adicional, especialmente si dichos datos se encuentran en el ámbito de aplicación de leyes de privacidad, como por ejemplo el Reglamento General de Protección de Datos de la UE (GDPR) o regulaciones como por ejemplo financieras, como PCI Data Security Standard (PCI DSS). Para todos estos datos:

* ¿Se transmite algún dato en texto claro? Esto se refiere a protocolos como HTTP, SMTP y FTP. El tráfico en Internet es especialmente peligroso. Verifique también todo el tráfico interno, por ejemplo, entre los balanceadores de carga, servidores web o sistemas backend.
* ¿Se utilizan algoritmos criptográficos antiguos o débiles, ya sea por defecto o en código antiguo?
* ¿Se utilizan claves criptográficas predeterminadas, se generan o reutilizan claves criptográficas débiles, o falta una gestión o rotación adecuada de las claves?
* ¿No se aplica el cifrado, por ejemplo, no se han configurado alguna de las directivas de seguridad o encabezados para el navegador?
* ¿El Agente del usuario (aplicación o cliente de correo electrónico, por ejemplo), verifica que el certificado enviado por el servidor se válido?

Véase también [criptografía en el almacenamiento (V7)](https://wiki.owasp.org/index.php/ASVS_V7_Cryptography), [protección de datos (V9)](https://wiki.owasp.org/index.php/ASVS_V9_Data_rotection) y [seguridad de la comunicaciones (V10)](https://wiki.owasp.org/index.php/ASVS_V10_Communications) del ASVS.

## Cómo se previene

Realice como mínimo las siguientes recomendaciones y consulte las referencias:

* Clasificar los datos procesados, almacenados o transmitidos por el sistema. Identifique qué información es sensible de acuerdo a las regulaciones, leyes o requisitos del negocio.
* Aplicar los controles para cada clasificación.
* No almacene datos sensibles innecesariamente. Descártelos tan pronto como sea posible o utilice un sistema de tokens que cumpla con PCI DSS. Datos que no son retenidos no pueden ser robados.
* Asegúrese de cifrar todos los datos sensibles cuando son almacenados.
* Asegúrese de que se utilizan únicamente algoritmos y protocolos estándares  y fuertes, así como que para las claves se implementa una gestión adecuada.
* Cifre todos los datos en tránsito utilizando protocolos seguros como TLS con cifradores que utilicen perfect forward secrecy (PFS), priorización de cifradores por el servidor y parámetros seguros. Aplique el cifrado utilizando directivas como HTTP Strict Transport Security (HSTS).
* Almacene contraseñas utilizando funciones de hashing adaptables con un factor de trabajo (factor de retraso) además de sal, como [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt),[bcrypt](https://wikipedia.org/wiki/Bcrypt) o [PBKDF2](https://wikipedia.org/wiki/PBKDF2).
* Verifique la efectividad de sus configuraciones y parámetros de forma independiente.


## Ejemplos de escenarios de ataque

**Escenario #1**:  Una aplicación cifra números de tarjetas de crédito en una base de datos utilizando el cifrado automática de la base de datos. Sin embargo, estos datos son automáticamente decifrados al ser consultados, permitiendo que a través de un defecto de inyección SQL se obtengan los números de tarjetas de crédito en texto plano. 

**Escenario #2**: Un sitio web no utiliza o fuerza el uso de TLS para todas las páginas, o utiliza cifradores débiles. Un atacante monitorea el tráfico de la red (por ejemplo en una red WiFi insegura), degrada la conexión de HTTPs a HTTP e intercepta los pedidos, robando las cookies de sesión del usuario. El atacante reutiliza esta cookie y secuestra la sesión del usuario (autenticado), accediendo o modificando datos privados. Por otro lado, podría alterar los datos transportados, por ejemplo, el receptor de una transferencia monetaria.

**Escenario #3**: Se utilizan hashes simples o hashes sin sal para almacenar las contraseñas de los usuarios en una base de datos. Una falla en la carga de archivos permite a un atacante obtener la base de datos de contraseñas. Utilizando una Rainwbow table de valores pre calculados, se pueden recuperar las contraseñas originales.

## Referencias (en inglés)

### OWASP

* [Controles Proactivos de OWASP: Protección de Datos](https://wiki.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V9, V10, V11](https://wiki.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [Hoja de ayuda de OWASP: Protección de Capa Transporte](https://wiki.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [Hoja de ayuda de OWASP: Protección de Seguridad de Usuario](https://wiki.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [Hoja de ayuda de OWASP: Almacenamiento de Contraseña](https://wiki.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [Hoja de ayuda de OWASP: Almacenamiento Criptográfico](https://wiki.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [Proyecto de Cabezales de Seguridad de OWASP](https://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project)
* [Guía de Pruebas de OWASP: Pruebas de Criptografía débil](https://wiki.owasp.org/index.php/Testing_for_weak_Cryptography)

### Externas

* [CWE-359: Exposición de Información Privada - Violación de Privacidad](https://cwe.mitre.org/data/definitions/359.html)
* [CWE-220: Exposición de Información Sensible a Través de Consultas de Datos](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Problemas Criptográficos](https://cwe.mitre.org/data/definitions/310.html)
* [CWE-312: Almacenamiento en Texto Plano de Información Sensible](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Transmisión en Texto Plano de Información Sensible](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326: Cifrado Débil](https://cwe.mitre.org/data/definitions/326.html)
