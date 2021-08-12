# A2:2017 Pérdida de Autenticación

| Agentes de amenaza/Vectores de ataque | Debilidades de seguridad         |      Impactos       |
| -- | -- | -- |
| Nivel de acceso : Explotabilidad 3    | Prevalencia 2 : Detectabilidad 2 | Técnico 3 : Negocio |
| Los atacantes tienen acceso a cientos de millones de combinaciones de pares de usuario y contraseña conocidas (debido a fugas de información) para el ingreso de credenciales, además de listas de cuentas administrativas por defecto, ataques mediante herramientas de fuerza bruta o diccionario y herramientas avanzadas para romper hashes de contraseñas | La prevalencia de la pérdida de autenticación es difundida debido al diseño y la implementación de la mayoría de los sistemas de identificación y gestión de acceso. Los atacantes pueden detectar la pérdida de autenticación de forma manual, pero se ven más atraídos por los volcados de contraseñas, los ataques de ingeniería social como el phishing. | Los atacantes solo tienen que obtener el acceso a unas pocas cuentas o solo a alguna cuenta de administrador para comprometer el sistema. Dependiendo del dominio de la aplicación, esto puedo permitir lavado de dinero y robo de identidad; o la divulgación de información sensible protegida legalmente. |

## ¿La aplicación es vulnerable?

La confirmación de la identidad, la autenticación y la gestion de sesiones del usuario son fundamental para protegerse contra ataques relacionados con la autenticación.

Puede existir debilidades de autenticación si la aplicación:

* Permite ataques automatizados como la [reutilización de credenciales conocidas](https://owasp.org/www-community/attacks/Credential_stuffing), cuando el atacante posee una lista de pares de usuario y contraseña válidos.
* Permite ataques de fuerza bruta u otros ataques automatizados.
* Permite contraseñas por defecto, débiles o bien conocidas, como "Password1", "Contraseña1" o "admin/admin".
* Posee procesos débiles o inefectivos para el olvido de contraseña o recuperación de credenciales, como "respuestas basadas en el conocimiento", las cuales no se pueden implementar de forma segura seguras.
* Almacena las contraseñas en texto claro, cifradas o utilizando funciones de hash débiles (vea **A3:2017-Exposición de Datos Sensiblese**)..
* No posee una autenticación multi-factor  o la implementada es ineficaz.

## Cómo se previene

* Cuando sea posible, implemente la autenticación multifactorial para evitar ataques automatizados, de relleno de credenciales, fuerza bruta o reuso de credenciales robadas. 
* No incluya o implemente en su software credenciales por defecto, particularmente para administradores.
* Implemente un control contra contraseñas débiles, tal como verificar que una nueva contraseña o un cambio de contraseña no esté incluída en la lista del [top 10000 de peores contraseñas](https://github.com/danielmiessler/SecLists/tree/master/Passwords).
* Alinear las políticas de largo, complejidad y rotación de las contraseñas con las [pautas de la sección 5.1.1 para Secretos Memorizados de la guía NIST 800-63 B's](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) u otras políticas de contraseñas modernas, basadas en evidencias.
* Asegúrese que el registro, la recuperación de las credenciales y el uso de APIs, no permiten los ataques de enumeración de usuarios, mediante la utilización de los mismos mensajes genéricos en todas las salidas.
* Limite o incremente el tiempo de respuesta de cada intento fallids de inicio de sesión. Registre todos los fallos y avise a los administradores cuando se detecten rellenos de credenciales, fuerza bruta u otros ataques.
* Utilice un gestor de sesión en el servidor, integrado, seguro y que genera un nuevo ID de sesión aleatorio con alta entropía después de iniciar sesión. Los identificadores de sesión no deben incluirse en la URL, deben almacenarse de forma segura y ser invalidados después del cierre de sesión,  un tiempo de inactividad y un tiempo tiempo de espera absoluto.

## Ejemplos de escenarios de ataque

**Escenario #1**: [Relleno de credenciales](https://owasp.org/www-community/attacks/Credential_stuffing), el uso de [listas de contraseñas conocidas](https://github.com/danielmiessler/SecLists), es un ataque común. Si una aplicación no implementa protecciones automáticas de amenazas o rellenado de credenciales, la aplicación puede usarse como oráculo de contraseña para determinar si las credenciales son válidas.

**Escenario #2**: La mayoría de los ataques de autenticación ocurren debido al uso de contraseñas como único factor. Las consideradas mejores prácticas de requerir de una rotación y complejidad de las contraseñas, son vistos como alentadoras del uso y reúso de contraseñas débiles por parte de los usuarios. Se le recomienda a las organizaciones que detengan dichas prácticas y utilicen las prácticas recomendadas en la guía NIST 800-63 y el uso de la autenticación multi-factor.

**Escenario #3**: Escenario #3**: Los tiempos de vida de las sesiones de aplicación no están configurados correctamente. Un usuario utiliza una computadora pública para acceder a una aplicación. En lugar de seleccionar "logout", el usuario simplemente cierra la pestaña del navegador y se aleja. Un atacante usa el mismo navegador una hora más tarde, y el usuario continúa autenticado.

## Referencias (en inglés)

### OWASP

* [Controles Proactivos de OWASP: Implementar controles de Identificación y Autenticación]((https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity))
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V2 Autenticación](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V3 Gestión de Sesiones](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
* [Guía de Pruebas de OWASP: Identificación](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README) y [Autenticación](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README)
* [Hoja de ayuda de OWASP: Autenticación](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [Hoja de ayuda de OWASP: Reutilización de credenciales conocidas](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
* [Hoja de ayuda de OWASP: Olvide mi contraseña](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
* [Hoja de ayuda de OWASP: Almacenamiento de la contraseña](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [Hoja de ayuda: Gestión de Sesiones](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

### Externas

* [NIST 800-63b 5.1.1 Secretos Memorizados: consejos modernos basados en evidencia para la autenticación.](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)
* [CWE-287: Autenticación indebida](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Fijación de Sesión](https://cwe.mitre.org/data/definitions/384.html)
