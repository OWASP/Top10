# A2:2017 Pérdida de autenticación

Agentes de Amenaza/Vectores de Ataque | Debilidad de Seguridad           | Impactos               |
| -- | -- | -- |
| Nivel de acceso \| Explotabilidad 3 | Prevalencia 2 \| Detectabilidad 2 | Técnico 3 \| Negocio |
| Los atacantes tienen acceso a cientos de millones de combinaciones de pares de usuario y contraseña conocidas (debido a fugas de información) para el ingreso de credenciales, además de listas de cuentas administrativas por defecto, ataques mediante herramientas de fuerza bruta o diccionario y herramientas avanzadas para romper hashes de contraseñas | La prevalencia de la pérdida de autenticación es difundida debido al diseño y la implementación de la mayoría de los sistemas de identificación y gestión de acceso. Los atacantes pueden detectar la pérdida de autenticación de forma manual, pero se ven más atraídos por los volcados de contraseñas, los ataques de ingeniería social como el phishing. | Los atacantes solo tienen que obtener el acceso a unas pocas cuentas o solo a alguna cuenta de administrador para comprometer el sistema. Dependiendo del dominio de la aplicación, esto puedo permitir lavado de dinero y robo de identidad; o la divulgación de información sensible protegida legalmente. |

## ¿Soy Vulnerable?

Confirmación de la identidad del usuario, la autenticación y la gestión de sesiones son críticas para separar a los atacantes malintencionados sin autenticar de los usuarios autorizados. 
Puedes tener debilidades en la autenticación si tu aplicación:

* Permite la reutilización de credenciales conocidas [credential stuffing](https://www.owasp.org/index.php/Credential_stuffing), que es, cuando un atacante tiene una lista de pares de usuario y contraseña válidos (obtenidos mediante alguna fuga).
* Permite ataques de fuerza bruta u otros ataques automatizados.
* Permite contraseñas por defecto, débiles o muy conocidas, como "Password1" o "Contraseña1" o "administrador/administrador".
* Tiene un proceso de olvide mi contraseña o recuperación de credenciales débil o ineficaz, como "respuestas basadas en el conocimiento", las cuales no se pueden hacer seguras.
* Almacena las contraseñas en texto claro, cifradas o utilizando funciones de hash débiles, lo que permite su recuperación mediante herramientas de fuerza bruta o utilizando GPUs.
* No posee o tiene autenticación multi-factor ineficaz.

## ¿Cómo prevenirlo?

* No entregues o despliegues una aplicación con credenciales por defecto, especialmente para los usuarios administradores.
* [Almacenar las contraseñas utilizando una función de hash moderna](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Leverage_an_adaptive_one-way_function), como Argon2 o PBKDF2, con suficiente factor de trabajo para evitar la recuperación de la contraseña mediante ataques con GPUs.
* Implementa un control contra contraseñas débiles, tal como probar una nueva contraseña o un cambio de contraseña contra la lista del [top 10000 de peores contraseñas](https://github.com/danielmiessler/SecLists/tree/master/Passwords).
* Alinear las políticas de largo, complejidad y rotación de las contraseñas con las [pautas de la sección 5.1.1 para Secretos Memorizados de la guía NIST 800-63 B's](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) u otras políticas de contraseñas modernas, basadas en evidencias.
* Asegurarse que el registro, la recuperación de las credenciales y el uso de APIs, no permiten los ataques de enumeración de usuarios, mediante la utilización de los mismos mensajes genéricos en todas las salidas.
* Cuando es posible, implementar autenticación multi-factor para prevenir la reutilización de credenciales conocidas, fuerza bruta, ataques automatizados y ataques de credenciales robadas.
* Registrar los intentos fallidos de autenticación y alertar a los administradores cuando se detectan ataques de reutilización de credenciales conocidas, fuerza bruta u otros ataques.

## Ejemplos de Escenarios de Ataques

**Escenario #1**: [Reutilización de credenciales conocidas](https://www.owasp.org/index.php/Credential_stuffing), el uso de [listas de contraseñas conocidas](https://github.com/danielmiessler/SecLists), es un ataque común. Si una aplicación no limita la cantidad de intentos de autenticación, la aplicación puede ser utilizada como un oráculo para determinar si las credenciales son válidas.

**Escenario #2**: La mayoría de los ataques de autenticación ocurren debido al uso de contraseñas como único factor. Las consideradas mejores prácticas de requerir de una rotación y complejidad de las contraseñas, son vistos como alentadoras del uso y reúso de contraseñas débiles por parte de los usuarios. Se le recomienda a las organizaciones que detengan dichas prácticas y utilicen las prácticas recomendadas en la guía NIST 800-63 y el uso de la autenticación multi-factor.

**Escenario #3**: El almacenamiento inseguro de contraseñas (incluidas texto claro, contraseñas reversibles cifradas y contraseñas que utilizan funciones de hash débiles (tales como MD5/SHA1 con o sin sal)) pueden llevar a brechas de seguridad. Un esfuerzo reciente de un pequeño grupo de investigadores rompió [320 millones de contraseñas en menos de tres semanas](https://cynosureprime.blogspot.com.au/2017/08/320-million-hashes-exposed.html), incluyendo contraseñas largas. En vez de esto, utilizar algoritmos modernos de hash como Argon2, con sal y suficiente factor de trabajo para prevenir el uso de tablas arcoíris, diccionarios, etc.

## Referencias

### OWASP

* [Controles Proactivos OWASP - Implementar controles de Identificación y Autenticación]((https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls))
* [Estándar de Verificación de Seguridad de Aplicación de OWASP V2 Autenticación](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [Estándar de Verificación de Seguridad de Aplicación de OWASP V3 Gestión de Sesiones](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [Guía de Pruebas de OWASP: Identificación](https://www.owasp.org/index.php/Testing_Identity_Management)
* [Guía de Pruebas de OWASP: Autenticación](https://www.owasp.org/index.php/Testing_for_authentication)
* [Hoja de trucos de OWASP: Autenticación](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)
* [Hoja de trucos de OWASP: Reutilización de credenciales conocidas](https://www.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet)
* [Hoja de trucos de OWASP: Olvide mi contraseña](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [Hoja de trucos de OWASP: Almacenamiento de la contraseña](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [Hoja de trucos de OWASP: Gestión de Sesiones](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)

### Externas

* [NIST 800-63b 5.1.1 Secretos Memorizados – consejos modernos y basados en evidencia para la autenticación.](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)
* [CWE-287 Autenticación indebida](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384 Fijación de Sesión](https://cwe.mitre.org/data/definitions/384.html)
