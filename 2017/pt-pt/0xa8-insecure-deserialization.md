# A8:2017 De-serialização Insegura

| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 1 | Prevalência: 2 \| Deteção: 2 | Técnico: 3 \| Negócio ? |
| Abusar da desserialização é algo difícil, uma vez que os _exploits_ existentes raramente funcionam sem alterações ou modificações ao código do _exploit_ subjacente. | Esta falha foi incluída no Top 10 baseado num [inqúerito à indústria][0xa81] e não em dados quantitativos. Algumas ferramentas podem descobrir falhas de desserialização, no entanto, a assistência humana é frequentemente necessária para validar o problema. É expectável que este tipo de vulnerabilidades seja cada vez mais prevalente e até venha a aumentar à medida que vão sendo desenvolvidas ferramentas para ajudar na identificação e correção. | O impacto das falhas de desserialização não pode ser subestimado. Estas falhas podem levar a ataques de execução remota de código, um dos ataques existentes mais sérios.
O impacto no negócio depende da necessidade de proteção dos dados. |

## A Aplicação é Vulnerável?

Aplicações e APIs são vulneráveis se desserializarem dados não confiáveis ou
objetos adulterados fornecidos pelo atacante. Isto resulta em dois tipos
principais de ataques:

* Ataques relacionados com objetos e estruturas de dados em que o atacante
  consegue modificar lógica aplicacional ou executar remotamente código
  arbitrário se existirem classes cujo comportamento possa ser alterado durante
  ou depois da desserialização.
* Ataques de adulteração de dados, tais como os relacionados com o controlo de
  acessos, onde são utilizadas estruturas de dados existentes mas cujo conteúdo
  foi alterado.

A serialização pode ser usada numa aplicação para:

* Comunicação remota e inter-processos (RPC/IPC)
* _Wire protocols_, _web services_, _message brokers_
* _Caching_/Persistência
* Base de Dados, servidores de _cache_, sistemas de ficheiros
* HTTP _cookies_, parâmetros de formulários HTML, _tokens_ de autenticação em
  APIs

## Como Prevenir

A única forma segura de utilizar serialização pressupõe que não são aceites
objetos serializados de fontes não confiáveis e que só são permitidos tipos de
dados primitivos.

Se isto não for possível, considere uma ou  mais das seguintes recomendações:

* Implementar verificações de integridade como assinatura digital nos objetos
  serializados como forma de prevenir a criação de dados hostis ou adulteração
  de dados
* Aplicar uma política rigorosa de tipos de dados durante a desserialização,
  antes da criação do objeto uma vez que a lógica tipicamente espera um conjunto
  de classes bem definido. Uma vez que existem formas demonstradas de contornar
  esta técnica, ela não deve ser usada individualmente.
* Isolar e correr a lógica de desserialização, sempre que possível, num ambiente
  com privilégios mínimos.
* Registar exceções e falhas na desserialização tais como tipos de dados não
  expectáveis.
* Restringir e monitorizar o tráfego de entrada e saída dos containers e
  servidores que realizam desserialização.
* Monitorizar a desserialização, gerando alertas quando esta operação é
  realizada com frequência anómala.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação de React invoca um conjunto de micro-serviços
Spring Boot. Tratando-se de programadores funcionais, tentaram assegurar que o
seu código fosse imutável. A solução que arranjaram foi serializar o estado do
utilizador e passar o mesmo de um lado para o outro em cada um dos pedidos. Um
atacante apercebe-se da existência do objecto Java "R00", e usa a ferramenta
Java Serial Killer para ganhar a possibilidade de executar código remoto no
servidor aplicacional.

**Cenário #2**: Um fórum de PHP usa a serialização de objetos PHP para gravar um
"super" _cookie_ que contém o identificador (ID) do utilizador, o seu papel, o
resumo (_hash_) da sua password e outros estados:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

Um atacante pode mudar o objeto serializado para lhe dar previlégios de
administrador:

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## Referências

### OWASP

* [OWASP Cheat Sheet: Deserialization][0xa82]
* [OWASP Proactive Controls: Validate All Inputs][0xa83]
* [OWASP Application Security Verification Standard: TBA][0xa84]
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse][0xa85]
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks][0xa86]

### Externas

* [CWE-502: Deserialization of Untrusted Data][0xa87]
* [Java Unmarshaller Security][0xa88]
* [OWASP AppSec Cali 2015: Marshalling Pickles][0xa89]

[0xa81]: https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html
[0xa82]: https://www.owasp.org/index.php/Deserialization_Cheat_Sheet
[0xa83]: https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs
[0xa84]: https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home
[0xa85]: https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse
[0xa86]: https://speakerdeck.com/pwntester/friday-the-13th-json-attacks
[0xa87]: https://cwe.mitre.org/data/definitions/502.html
[0xa88]: https://github.com/mbechler/marshalsec
[0xa89]: http://frohoff.github.io/appseccali-marshalling-pickles/ 

[1]: https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html

