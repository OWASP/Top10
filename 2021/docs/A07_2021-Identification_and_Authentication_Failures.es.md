# A07:2021 – Fallas de Identificación y Autenticación    ![icon](assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png)

## Factores

| CWEs mapeados | Tasa de incidencia máx | Tasa de incidencia prom | Cobertura máx | Cobertura prom | Exploit ponderado prom | Impacto ponderado prom | Incidencias totales | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 7.40                 | 6.50                | 79.51%       | 45.72%       | 132,195           | 3,897      |

## Resumen

Previamente denominada como *Pérdida de Autenticación*, descendió desde
la segunda posición, y ahora incluye CWEs que están más relacionados con
fallas de identificación. Los CWE notables incluidos son
*CWE-297: Validación incorrecta de Certificado con discrepancia de host*,
*CWE-287: Autenticación incorrecta* y
*CWE-384: Fijación de sesiones*.

## Descripción

La confirmación de la identidad, la autenticación y la gestión de sesiones
del usuario son fundamentales para protegerse contra ataques relacionados con
la autenticación. Puede haber debilidades de autenticación si la aplicación:

-   Permite ataques automatizados como la reutilización de credenciales
    conocidas, donde el atacante posee una lista de pares de usuario y
    contraseña válidos.

-   Permite ataques de fuerza bruta u otros ataques automatizados.

-   Permite contraseñas por defecto, débiles o bien conocidas, como "Password1"
    o "admin/admin".

-   Posee procesos débiles o no efectivos para las funcionalidades de
    olvido de contraseña o recuperación de credenciales, como
    "respuestas basadas en el conocimiento", las cuales no se
    pueden implementar de forma segura seguras.

-   Almacena las contraseñas en texto claro, cifradas o utilizando funciones
    de hash débiles (vea **A02:2021 – Fallos criptográficos**).

-   No posee una autenticación multi-factor o la implementada es ineficaz.

-   Expone el identificador de sesión en la URL.

-   Reutiliza el identificador de sesión después de iniciar sesión.

-   No invalida correctamente los ID de sesión. Las sesiones de usuario o
    los tokens de autenticación (principalmente tokens de inicio de sesión
    único (SSO)) no son correctamente invalidados durante el cierre de sesión
    o luego de un período de inactividad.

## Cómo prevenir

-   Cuando sea posible, implemente la autenticación multi-factor para evitar
    ataques automatizados de reutilización de credenciales conocidas,
    fuerza bruta y reuso de credenciales robadas.

-   No incluya o implemente en su software credenciales por defecto,
    particularmente para usuarios administradores.

-   Implemente un control contra contraseñas débiles, tal como verificar
    que una nueva contraseña o la utilizada en el cambio de contraseña
    no esté incluída en la lista de las 10,000 peores contraseñas.

-   Alinear las políticas de largo, complejidad y rotación de las contraseñas
    con las pautas de la sección 5.1.1 para Secretos Memorizados de la guía del
    NIST 800-63 B's u otras políticas de contraseñas modernas,
    basadas en evidencias.

-   Asegúrese que el registro, la recuperación de las credenciales y el
    uso de APIs, no permiten los ataques de enumeración de usuarios, mediante
    la utilización de los mismos mensajes genéricos en todas las salidas.

-   Limite o incremente el tiempo de respuesta cada vez más los intentos
    fallidos de inicio de sesión, pero tenga cuidado de no crear un escenario
    de denegación de servicio. Registre todos los fallos y avise a los
    administradores cuando se detecten ataques de rellenos automatizado de
    credenciales, fuerza bruta u otros.

-   Utilice un gestor de sesión en el servidor, integrado, seguro y que generé
    un nuevo ID de sesión aleatorio con alta entropía después de iniciar sesión.
    Los identificadores de sesión no deben incluirse en la URL,
    deben almacenarse de forma segura y deben ser invalidados después del
    cierre de sesión, luego de un tiempo de inactividad o por un tiempo tiempo
    de espera absoluto.

## Ejemplos de escenarios de ataque

**Escenario #1:** Relleno de credenciales, el uso de listas de contraseñas
conocidas, es un ataque común. Supongamos que una aplicación no se implementa
protección automatizada de relleno de credenciales. En ese caso, la aplicación
puede usarse como oráculo de contraseñas para determinar si las credenciales son
válidas.

**Escenario #2:** La mayoría de los ataques de autenticación ocurren debido al
uso de contraseñas como único factor. Las consideradas mejores prácticas de
requerir de una rotación y complejidad de las contraseñas, son vistos como
alentadoras del uso y reúso de contraseñas débiles por parte de los usuarios.
Se le recomienda a las organizaciones que detengan dichas prácticas y utilicen
las prácticas recomendadas en la guía NIST 800-63 y utilicen autenticación
multi-factor.

**Escenario #3:** Los tiempos de espera (timeouts) de las sesiones de aplicación
no están configurados correctamente. Un usuario utiliza una computadora pública
para acceder a una aplicación. En lugar de seleccionar "cerrar sesión", el
usuario simplemente cierra la pestaña del navegador y se aleja. Un atacante usa
el mismo navegador una hora más tarde, y el usuario continúa autenticado.

## Referencias

-   [OWASP Controles Proavtivos: Implementar la identidad digital](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Estándar de Verificación de Seguridad en Aplicaciones: V2 Autenticación](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Estándar de Verificación de Seguridad en Aplicaciones: V3 Gestión de Sesiones](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Guía de Pruebas: Identificación](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README), [Autenticación](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README)

-   [OWASP Cheat Sheet: Autenticación](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Reutilización de credenciales conocidas](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Olvide mi contraseña](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Gestión de Sesiones](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

-   [OWASP Amenazas automatizadas para aplicaciones web]
    (https://owasp.org/www-project-automated-threats-to-web-applications/)    

-   NIST 800-63b: 5.1.1 Secretos Memorizados

## Lista de CWEs mapeadas

[CWE-255 Errores de gestión de credenciales](https://cwe.mitre.org/data/definitions/255.html)

[CWE-259 Uso de contraseña en código fuente](https://cwe.mitre.org/data/definitions/259.html)

[CWE-287 Autenticación indebida](https://cwe.mitre.org/data/definitions/287.html)

[CWE-288 Omisión de autenticación mediante una ruta o canal alternativo](https://cwe.mitre.org/data/definitions/288.html)

[CWE-290 Omisión de autenticación mediante suplantación de identidad](https://cwe.mitre.org/data/definitions/290.html)

[CWE-294 Omisión de autenticación mediante captura-reenvio](https://cwe.mitre.org/data/definitions/294.html)

[CWE-295 Validación incorrecta de certificado](https://cwe.mitre.org/data/definitions/295.html)

[CWE-297 Validación incorrecta de Certificado con discrepancia de host](https://cwe.mitre.org/data/definitions/297.html)

[CWE-300 Canal accesible por puntos no finales](https://cwe.mitre.org/data/definitions/300.html)

[CWE-302 Omisión de autenticación por datos supuestos inmutables](https://cwe.mitre.org/data/definitions/302.html)

[CWE-304 Falta un paso crítico en la autenticación](https://cwe.mitre.org/data/definitions/304.html)

[CWE-306 Falta autenticación para función crítica](https://cwe.mitre.org/data/definitions/306.html)

[CWE-307 Restricción de intentos de autenticación excesivos](https://cwe.mitre.org/data/definitions/307.html)

[CWE-346 Error de validación de origen](https://cwe.mitre.org/data/definitions/346.html)

[CWE-384 Fijación de sesión](https://cwe.mitre.org/data/definitions/384.html)

[CWE-521 Requisitos debiles para las contraseñas](https://cwe.mitre.org/data/definitions/521.html)

[CWE-613 Caducidad de sesión insuficiente](https://cwe.mitre.org/data/definitions/613.html)

[CWE-620 Cambio de contraseña no verificado](https://cwe.mitre.org/data/definitions/620.html)

[CWE-640 Mecanismo de recuperación de contraseña débil](https://cwe.mitre.org/data/definitions/640.html)

[CWE-798 Uso de credenciales incluidas en el código fuente](https://cwe.mitre.org/data/definitions/798.html)

[CWE-940 Verificación incorrecta de la fuente de un canal de comunicación](https://cwe.mitre.org/data/definitions/940.html)

[CWE-1216 Errores del mecanismo de bloqueo](https://cwe.mitre.org/data/definitions/1216.html)
