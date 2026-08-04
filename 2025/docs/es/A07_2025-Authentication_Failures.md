# A07:2025 Fallas de Autenticación ![icon](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}


## Antecedentes

Las fallas de Autenticación mantienen su posición en el puesto #7 con un ligero cambio de nombre para reflejar con mayor precisión las 36 CWEs de esta categoría. A pesar de los beneficios de los marcos de trabajo estandarizados, esta categoría ha mantenido su rango #7 desde 2021. Las CWEs notables incluidas son *CWE-259: Uso de contraseñas codificadas, CWE-297: Validación incorrecta de certificado con discrepancia de host, CWE-287: Autenticación incorrecta, CWE-384: Fijación de sesión y CWE-798: Uso de credenciales codificadas*.


## Tabla de puntuación


<table>
  <tr>
   <td>CWEs Mapeadas
   </td>
   <td>Tasa Máxima de Incidencia
   </td>
   <td>Tasa Promedio de Incidencia
   </td>
   <td>Cobertura Máxima
   </td>
   <td>Cobertura Promedio
   </td>
   <td>Promedio Ponderado de Explotación
   </td>
   <td>Promedio Ponderado de Impacto
   </td>
   <td>Ocurrencias Totales
   </td>
   <td>CVEs Totales
   </td>
  </tr>
  <tr>
   <td>36
   </td>
   <td>15.80%
   </td>
   <td>2.92%
   </td>
   <td>100.00%
   </td>
   <td>37.14%
   </td>
   <td>7.69
   </td>
   <td>4.44
   </td>
   <td>1,120,673
   </td>
   <td>7,147
   </td>
  </tr>
</table>



## Descripción

Esta vulnerabilidad está presente cuando un atacante es capaz de engañar a un sistema para que reconozca como legítimo a un usuario inválido o incorrecto. Puede haber debilidades de autenticación si la aplicación:

* Permite ataques automatizados como el relleno de credenciales (credential stuffing), donde el atacante dispone de una lista filtrada de nombres de usuario y contraseñas válidos. Recientemente, este tipo de ataque se ha ampliado para incluir ataques de contraseñas híbridos (también conocidos como ataques de aspersión de contraseñas o password spray), en los que el atacante utiliza variaciones o incrementos de credenciales comprometidas para obtener acceso; por ejemplo, probando Password1!, Password2!, Password3!, y así sucesivamente.

* Permite ataques de fuerza bruta u otros ataques automatizados y programados (scripts) que no se bloquean rápidamente.

* Permite contraseñas predeterminadas, débiles o muy conocidas, como "Password1" o un nombre de usuario "admin" con una contraseña "admin".

* Permite a los usuarios crear nuevas cuentas con credenciales que ya se sabe que han sido vulneradas.

* Permite el uso de procesos de recuperación de credenciales y de olvido de contraseña débiles o ineficaces, como las "preguntas de seguridad basadas en el conocimiento", que no pueden hacerse seguras.

* Utiliza almacenes de datos de contraseñas en texto claro, cifrados o con hash débil (ver [A04:2025-Fallas Criptográficas](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)).

* Carece de autenticación de múltiples factores (MFA) o esta es ineficaz.

* Permite el uso de alternativas (fallbacks) débiles o ineficaces si la autenticación de múltiples factores no está disponible.

* Expone el identificador de sesión en la URL, en un campo oculto o en otra ubicación insegura accesible para el cliente.

* Reutiliza el mismo identificador de sesión después de un inicio de sesión exitoso.

* No invalida correctamente las sesiones de usuario o los tokens de autenticación (principalmente los tokens de inicio de sesión único (SSO)) durante el cierre de sesión o tras un periodo de inactividad.

* No valida correctamente el alcance (scope) y la audiencia prevista de las credenciales proporcionadas.


## Cómo prevenir

* Siempre que sea posible, implementar y aplicar el uso de la autenticación de múltiples factores (MFA) para evitar ataques automatizados de relleno de credenciales, fuerza bruta y reutilización de credenciales robadas.

* Siempre que sea posible, fomentar y habilitar el uso de gestores de contraseñas para ayudar a los usuarios a tomar mejores decisiones.

* No distribuir ni desplegar aplicaciones con credenciales predeterminadas, especialmente para los usuarios administradores.

* Implementar comprobaciones de contraseñas débiles, como probar las contraseñas nuevas o modificadas contra la lista de las 10,000 peores contraseñas.

* Durante la creación de nuevas cuentas y los cambios de contraseña, validar contra listas de credenciales que se sabe han sido vulneradas (por ejemplo: utilizando [haveibeenpwned.com](https://haveibeenpwned.com)).

* Alinear la longitud, la complejidad y las políticas de rotación de las contraseñas con las [directrices del Instituto Nacional de Estándares y Tecnología (NIST) 800-63b en la sección 5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html#:~:text=5.1.1%20Memorized%20Secrets) para Secretos Memorizados u otras políticas de contraseñas modernas y basadas en evidencias.

* No obligar a los seres humanos a rotar las contraseñas a menos que se sospeche de una vulneración. Si se sospecha de una vulneración, forzar el restablecimiento de las contraseñas de inmediato.

* Asegurarse de que las rutas de registro, recuperación de credenciales y API estén protegidas contra ataques de enumeración de cuentas utilizando los mismos mensajes para todos los resultados ("Nombre de usuario o contraseña inválidos").

* Limitar o retrasar de forma incremental los intentos fallidos de inicio de sesión, pero teniendo cuidado de no crear un escenario de denegación de servicio. Registrar todas las fallas y alertar a los administradores cuando se detecten o sospechen ataques de relleno de credenciales, fuerza bruta u otros.

* Utilizar un gestor de sesiones integrado, seguro y del lado del servidor que genere un nuevo ID de sesión aleatorio con alta entropía después del inicio de sesión. Los identificadores de sesión no deben estar en la URL, deben almacenarse de forma segura en una cookie segura e invalidarse tras el cierre de sesión, por inactividad y tras tiempos de espera absolutos.

* Idealmente, utilizar un sistema ya establecido y de confianza para gestionar la autenticación, la identidad y la gestión de sesiones. Transferir este riesgo siempre que sea posible adquiriendo y utilizando un sistema robusto y bien probado.

* Verificar el uso previsto de las credenciales proporcionadas; por ejemplo, para los JWT, validar las afirmaciones (*claims*) `aud`, `iss` y los alcances (scopes).


## Ejemplos de escenarios de ataque

**Escenario #1:** El relleno de credenciales (credential stuffing), es decir, el uso de listas de combinaciones conocidas de nombre de usuario y contraseña, es actualmente un ataque muy común. Recientemente, se ha descubierto que los atacantes "incrementan" o ajustan de otro modo las contraseñas, basándose en el comportamiento humano común. Por ejemplo, cambiando 'Invierno2025' por 'Invierno2026', o 'AmoAMiPerro6' por 'AmoAMiPerro7' o 'AmoAMiPerro5'. Este ajuste de los intentos de contraseña se denomina ataque de relleno de credenciales híbrido o ataque de aspersión de contraseñas (password spray), y pueden ser incluso más eficaces que la versión tradicional. Si una aplicación no implementa defensas contra amenazas automatizadas (fuerza bruta, scripts o bots) o relleno de credenciales, la aplicación puede utilizarse como un "oráculo de contraseñas" para determinar si las credenciales son válidas y obtener acceso no autorizado.

**Escenario #2:** La mayoría de los ataques de autenticación con éxito se producen debido al uso continuado de las contraseñas como único factor de autenticación. Lo que antes se consideraba una buena práctica, como los requisitos de rotación y complejidad de las contraseñas, incita a los usuarios tanto a reutilizar contraseñas como a usar contraseñas débiles. Se recomienda a las organizaciones que dejen de aplicar estas prácticas, según la norma NIST 800-63, y que impongan el uso de la autenticación de múltiples factores en todos los sistemas importantes.

**Escenario #3:** Los tiempos de espera de las sesiones de la aplicación no se han implementado correctamente. Un usuario utiliza un ordenador público para acceder a una aplicación y, en lugar de seleccionar "cerrar sesión", simplemente cierra la pestaña del navegador y se marcha. Otro ejemplo de esto es si una sesión de inicio de sesión único (SSO) no puede cerrarse mediante un cierre de sesión único (SLO). Es decir, un único inicio de sesión le permite acceder, por ejemplo, a su lector de correo, a su sistema de documentos y a su sistema de chat. Pero el cierre de sesión solo se produce en el sistema actual. Si un atacante utiliza el mismo navegador después de que la víctima crea que ha cerrado la sesión con éxito, pero con el usuario todavía autenticado en algunas de las aplicaciones, podrá acceder a la cuenta de la víctima. El mismo problema puede ocurrir en oficinas y empresas cuando no se ha salido correctamente de una aplicación sensible y un colega tiene acceso (temporal) al ordenador desbloqueado.


## Referencias

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)


## Lista de CWEs Mapeadas

* [CWE-258 Contraseña Vacía en Archivo de Configuración (Empty Password in Configuration File)](https://cwe.mitre.org/data/definitions/258.html)

* [CWE-259 Uso de Contraseña Codificada de Forma Rígida (Use of Hard-coded Password)](https://cwe.mitre.org/data/definitions/259.html)

* [CWE-287 Autenticación Incorrecta (Improper Authentication)](https://cwe.mitre.org/data/definitions/287.html)

* [CWE-288 Elusión de Autenticación Mediante una Ruta o Canal Alternativo (Authentication Bypass Using an Alternate Path or Channel)](https://cwe.mitre.org/data/definitions/288.html)

* [CWE-289 Elusión de Autenticación por Nombre Alternativo (Authentication Bypass by Alternate Name)](https://cwe.mitre.org/data/definitions/289.html)

* [CWE-290 Elusión de Autenticación por Suplantación de Identidad (Authentication Bypass by Spoofing)](https://cwe.mitre.org/data/definitions/290.html)

* [CWE-291 Dependencia de la Dirección IP para la Autenticación (Reliance on IP Address for Authentication)](https://cwe.mitre.org/data/definitions/291.html)

* [CWE-293 Uso del Campo Referer para la Autenticación (Using Referer Field for Authentication)](https://cwe.mitre.org/data/definitions/293.html)

* [CWE-294 Elusión de Autenticación por Captura y Repetición (Authentication Bypass by Capture-replay)](https://cwe.mitre.org/data/definitions/294.html)

* [CWE-295 Validación Inadecuada del Certificado (Improper Certificate Validation)](https://cwe.mitre.org/data/definitions/295.html)

* [CWE-297 Validación Inadecuada del Certificado con Discrepancia de Host (Improper Validation of Certificate with Host Mismatch)](https://cwe.mitre.org/data/definitions/297.html)

* [CWE-298 Validación Inadecuada de la Caducidad del Certificado (Improper Validation of Certificate Expiration)](https://cwe.mitre.org/data/definitions/298.html)

* [CWE-299 Validación Inadecuada de la Revocación del Certificado (Improper Check for Certificate Revocation)](https://cwe.mitre.org/data/definitions/299.html)

* [CWE-300 Canal Accesible por un No-Punto Final (Channel Accessible by Non-Endpoint)](https://cwe.mitre.org/data/definitions/300.html)

* [CWE-302 Elusión de Autenticación por Datos Supuestamente Inmutables (Authentication Bypass by Assumed-Immutable Data)](https://cwe.mitre.org/data/definitions/302.html)

* [CWE-303 Implementación Incorrecta del Algoritmo de Autenticación (Incorrect Implementation of Authentication Algorithm)](https://cwe.mitre.org/data/definitions/303.html)

* [CWE-304 Falta de un Paso Crítico en la Autenticación (Missing Critical Step in Authentication)](https://cwe.mitre.org/data/definitions/304.html)

* [CWE-305 Elusión de Autenticación por Debilidad Primaria (Authentication Bypass by Primary Weakness)](https://cwe.mitre.org/data/definitions/305.html)

* [CWE-306 Falta de Autenticación para una Función Crítica (Missing Authentication for Critical Function)](https://cwe.mitre.org/data/definitions/306.html)

* [CWE-307 Restricción Inadecuada de Intentos Excesivos de Autenticación (Improper Restriction of Excessive Authentication Attempts)](https://cwe.mitre.org/data/definitions/307.html)

* [CWE-308 Uso de Autenticación de Factor Único (Use of Single-factor Authentication)](https://cwe.mitre.org/data/definitions/308.html)

* [CWE-309 Uso del Sistema de Contraseñas para la Autenticación Primaria (Use of Password System for Primary Authentication)](https://cwe.mitre.org/data/definitions/309.html)

* [CWE-346 Error de Validación de Origen (Origin Validation Error)](https://cwe.mitre.org/data/definitions/346.html)

* [CWE-350 Dependencia de la Resolución DNS Inversa para una Acción Crítica de Seguridad (Reliance on Reverse DNS Resolution for a Security-Critical Action)](https://cwe.mitre.org/data/definitions/350.html)

* [CWE-384 Fijación de Sesión (Session Fixation)](https://cwe.mitre.org/data/definitions/384.html)

* [CWE-521 Requisitos de Contraseña Débiles (Weak Password Requirements)](https://cwe.mitre.org/data/definitions/521.html)

* [CWE-613 Expiración de Sesión Insuficiente (Insufficient Session Expiration)](https://cwe.mitre.org/data/definitions/613.html)

* [CWE-620 Cambio de Contraseña no Verificado (Unverified Password Change)](https://cwe.mitre.org/data/definitions/620.html)

* [CWE-640 Mecanismo de Recuperación de Contraseña Débil (Weak Password Recovery Mechanism for Forgotten Password)](https://cwe.mitre.org/data/definitions/640.html)

* [CWE-798 Uso de Credenciales Codificadas de Forma Rígida (Use of Hard-coded Credentials)](https://cwe.mitre.org/data/definitions/798.html)

* [CWE-940 Verificación Inadecuada del Origen de un Canal de Comunicación (Improper Verification of Source of a Communication Channel)](https://cwe.mitre.org/data/definitions/940.html)

* [CWE-941 Destino Especificado Incorrectamente en un Canal de Comunicación (Incorrectly Specified Destination in a Communication Channel)](https://cwe.mitre.org/data/definitions/941.html)

* [CWE-1390 Autenticación Débil (Weak Authentication)](https://cwe.mitre.org/data/definitions/1390.html)

* [CWE-1391 Uso de Credenciales Débiles (Use of Weak Credentials)](https://cwe.mitre.org/data/definitions/1391.html)

* [CWE-1392 Uso de Credenciales por Defecto (Use of Default Credentials)](https://cwe.mitre.org/data/definitions/1392.html)

* [CWE-1393 Uso de Contraseña por Defecto (Use of Default Password)](https://cwe.mitre.org/data/definitions/1393.html)
