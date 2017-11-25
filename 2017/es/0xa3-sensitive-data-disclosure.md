# A3:2017 Exposición de Datos Sensibles

| Agentes de amenaza/Vectores de ataque | Debilidad de Seguridad           | Impactos               |
| -- | -- | -- |
| Niv. de Acceso  \| Explotabilidad 2 | Prevalencia 3 \| Detección 2 | Técnico 3 \| Negocio |
| Hasta los atacantes anónimos, típicamente no rompen directamente la criptografía. Ellos rompen algo más, tal como robar claves, hacer ataques del tipo man-in-the-middle, o robar datos en texto plano directamente desde el servidor, mientras estos datos se encuentran en tránsito, o como cliente, por ejemplo desde el navegador del usuario. Ataques manuales son generalmente requeridos. | Desde los últimos años, este ha sido el ataque de gran impacto más común. La falla más común es simplemente no encriptar los datos sensibles. Cuando la criptografía es empleada, la generación de claves débiles, el débil manejo de las claves, el uso de algoritmos débiles es común, particularmente técnicas débiles de hashing de contraseñas. Para los datos en tránsito, las debilidades del lado del servidor son fáciles de detectar, pero difíciles para los datos en reposo. Ambas son de bastante y variada explotación. | El fracaso frecuentemente compromete todos los datos que debieron haber sido protegidos. Típicamente, esta información incluye información personal sensible(PII, Información Personal Identificable) como  historiales médicos, credenciales, datos personales, datos de tarjetas de crédito, los cuales en ocasiones requieren protección según dictan leyes y regulaciones, tales como la regulación de la Unión Europea, GDPR (Regulación General de Protección de Datos) o leyes locales de privacidad. |

## ¿Soy Vulnerable a la Exposición de datos?

Lo primero a determinar son las necesidades de protección de los datos en tránsito y en reposo. Por ejemplo contraseñas, números de tarjetas de crédito, historiales médicos y la información personal requieren protección extra, particularmente si estos datos caen bajo la regulación de la Unión Europea, GDPR (Regulación General de Protección de Datos), regulaciones o leyes locales de privacidad, regulaciones de protección de datos financieros, tales como el Acuerdo PCI DSS del Consejo sobre Normas de Seguridad de la PCI (PCI Security Standards Council, LLC), o leyes de historiales médicos, tales como la ley de Transparencia y Responsabilidad de Seguro Médico (HIPAA). Para todo tipo de datos:

* ¿Es algún dato de un sitio transmitido en texto plano, de forma interna o externa? El tráfico de Internet es especialmente peligroso, pero desde el que balancea las cargas hasta los servidores web o desde los servidores web hasta los sistemas de back end, puede ser problemático.
* ¿Son los datos sensibles guardados en texto plano, incluyendo los respaldos?
¿Hay algún algoritmo criptográfico débil o viejo siendo usado por defecto o en código más viejo? (ver A6:2017 Configuración de Seguridad Incorrecta)
* ¿Existen claves criptográficas por defecto en uso, claves de seguridad criptográficas débiles generadas o re-utilizadas, o falta de rotación o manejo apropiado de la clave?
* ¿La encriptación es no forzada, por ejemplo, existe alguna directiva de seguridad o cabezales faltantes de algún agente de usuario(navegador)?

Ver áreas ASVS [Crypto (V7), Protección de Datos (V9) y SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS)

## ¿Como prevenirlo?

Haz lo siguiente como mínimo y consulta las referencias:

* Clasificar los datos procesados, almacenados o transmitidos por un sistema. Aplicar controles según la clasificación.
Revisar las leyes de privacidad o regulaciones aplicables a los datos sensibles y protegerlos según los requerimientos regulatorios.
* No almacene datos sensibles innecesariamente. Deseche los datos tan pronto como sea posible o utilice un sistema de tokens que cumpla con PCI DSS. Los datos que no retiene, no pueden ser robados.
* Asegúrese de encriptar todos los datos sensibles que se encuentren en reposo.    
* Encripte todos los datos en tránsito, tal como utilizando TLS. Refuerce esta medida utilizando directivas de Seguridad de Transporte HTTP Estricta (HSTS).
* Asegúrese de que algoritmos robustos o cifrados, parámetros, protocolos y claves actualizadas sean utilizados, además de tener una adecuada gerencia de claves definida. Considere usar [crypto módulos](http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm).
* Asegúrese de que las contraseñas estén almacenadas con un algoritmo adaptativo fuerte, apropiado para la protección de contraseñas, tal como [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](http://en.wikipedia.org/wiki/Scrypt), [bcrypt](http://en.wikipedia.org/wiki/Bcrypt) y [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2). Configure el factor de trabajo (factor de retraso) tan alto como pueda tolerar.
* Deshabilite el cacheado para respuestas que contengan datos sensibles.
Verifique la efectividad de sus configuraciones independientemente.


## Ejemplo de Escenarios de Ataque

**Escenario #1**:  Una aplicación encripta números de tarjetas de crédito en una base de datos utilizando la encriptación automática de la base de datos. Sin embargo, estos datos son automáticamente desencriptados, permitiendo que una falla de inyección SQL recoja los números de tarjetas de crédito en texto plano. 

**Escenario #2**: Un sitio no utiliza o fuerza el uso de TLS para todas las páginas, o contiene encriptación débil. Un atacante simplemente monitorea el tráfico de la red, desnuda o intercepta el TLS (como una red inalámbrica abierta), y roba las cookies de sesión del usuario. El atacante entonces recarga esta cookie y secuestra la sesión del usuario(autenticado), accediendo o modificando los datos privados del usuario. En vez de lo mencionado, podría alterar todos los datos transportados, por ejemplo el receptor de una transferencia monetaria.

**Escenario #3**: La base de datos de contraseñas usa hashes sin sal para almacenar las contraseñas de todos. Una falla en la subida de archivos permite a un atacante obtener la base de datos de contraseñas. Todos los hashes sin sal pueden ser expuestos con una rainbow table de hashes pre-calculados.

## Referencias


* [OWASP Controles Proactivos - Protección de Datos](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Standard de Verificación de Seguridad de Aplicaciones - V9, V10, V11](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Cheat Sheet - Protección de Capa Transporte](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet - Protección de Seguridad de Usuario](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet - Almacenamiento de Contraseña](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [OWASP Cheat Sheet - Almacenamiento Criptográfico](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Proyecto de Cabezales de Seguridad](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)
* [OWASP Guía de Testing - Testing para la Criptografía Débil](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### Externas

* [CWE-359 Exposición de Información Privada - Violación de Privacidad](https://cwe.mitre.org/data/definitions/359.html)
* [CWE-220 Exposición de Información Sensible a Través de Consultas de Datos](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310 Problemas Criptográficos](https://cwe.mitre.org/data/definitions/310.html)
* [CWE-312 Almacenamiento en Texto Plano de Información Sensible](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319 Transmisión en Texto Plano de Información Sensible](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326 Encriptación Débil](https://cwe.mitre.org/data/definitions/326.html)
