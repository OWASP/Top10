# A8:2017 Desserialização insegura

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 1 | Prevalência 2 \| Detectabilidade 2 | Técnico 3 \| Negócio |
| A exploração da desserialização é um tanto difícil, pois as explorações prontas *off the shelf* raramente funcionam sem mudanças ou ajustes no código interno de exploração. | Este problema está incluído no Top 10 com base em uma [pesquisa da indústria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) e não em dados quantificáveis. Algumas ferramentas podem descobrir falhas de desserialização, mas a assistência humana é freqüentemente necessária para validar o problema. Espera-se que os dados de prevalência para falhas de desserialização aumentem à medida que as ferramentas são desenvolvidas para ajudar a identificá-los e resolvê-los. | O impacto das falhas de desserialização não pode ser subestimado. Essas falhas podem levar a ataques execução remota de código, sendo um dos ataques mais sérios possível. O impacto comercial depende das necessidades de proteção de sua aplicação e dados. |

## A aplicação está vulnerável?

Aplicações e APIs estarão vulneráveis se desserializarem objetos hostis ou adulterados fornecidos por um atacante.

Isso pode resultar em dois principais tipos de ataques:

* Ataques relacionados com a estrutura de objetos e dados onde o atacante modifica a lógica do aplicativo ou consegue a execução de código remoto arbitrário se houver classes disponíveis para a aplicação que possam alterar o comportamento durante ou após a deserialização. 
* Ataques típicos de manipulação de dados, como ataques de controle de acesso, onde as estruturas de dados existentes são usadas, mas o conteúdo é alterado.

Serialização pode ser usada em aplicações para:

* Comunicação remota / interprocesso (RPC / IPC)
* Protocolos com fio, serviços web, *message brokers*
* Caching/Persistência
* Bancos de dados, servidores de cache, sistemas de arquivos
* Cookies HTTP, parâmetros de formulário HTML, tokens de autenticação de API

## Como Prevenir

O único padrão de arquitetura seguro é não aceitar objetos serializados de fontes não confiáveis ou usar mídias de serialização que só permitem tipos de dados primitivos.

Se isso não for possível:

* Implementar verificações de integridade, tais como assinaturas digitais em qualquer objeto serializado para evitar a criação de objetos hostis ou a manipulação de dados.
* Aplicar restrições de tipos estritos durante a desserialização antes da criação do objeto, pois seu código geralmente espera um conjunto definível de classes. Casos onde esta técnica foi , demonstrou-se que a dependência exclusiva disso não é aconselhável.
* Isolar e executar o código que deserializa em ambientes de privilégios baixos quando possível.
* Exceções e falhas de desserialização do log, como por exemplo, onde o tipo de entrada não é o tipo esperado, ou a deserialização lança exceções.
* Restringir ou monitorar a conectividade de rede recebida e de saída de contêineres ou servidores que deserializam.
* Monitorizar a deserialização, alertar se um usuário deserializar constantemente.

* Enforce strict type constraints during deserialization before object creation as your code typically expects a definable set of classes. Bypasses to this technique have been demonstrated so reliance solely on this is not advisable.
* Isolate and run code that deserializes in low privilege environments when possible.
* Log deserialization exceptions and failures, such as where the incoming type is not the expected type, or the deserialization throws exceptions.
* Restrict or monitor incoming and outgoing network connectivity from containers or servers that deserialize.
* Monitor deserialization, alerting if a user deserializes constantly.


## Exemplos de Cenários de Ataque

**Scenario #1**: A React application calls a set of Spring Boot microservices. Being functional programmers, they tried to ensure that their code is immutable. The solution they came up with is serializing user state and passing it back and forth with each request. An attacker notices the "R00" Java object signature, and uses the Java Serial Killer tool to gain remote code execution on the application server.

**Scenario #2**: A PHP forum uses PHP object serialization to save a "super" cookie, containing the user's user ID, role, password hash, and other state:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

An attacker changes the serialized object to give themselves admin privileges:
`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## Referências

### OWASP

* [OWASP Cheat Sheet: Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [OWASP Proactive Controls: Validate All Inputs](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard: TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### Externas

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [Java Unmarshaller Security](https://github.com/mbechler/marshalsec)
* [OWASP AppSec Cali 2015: Marshalling Pickles](http://frohoff.github.io/appseccali-marshalling-pickles/)
