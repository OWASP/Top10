# A8:2017 De-serialização Insegura

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 1 | Prevalência 2 \| Deteção 2 | Técnico 3 \| Negócio |
| A exploração da de-serialização é algo difícil, uma vez que os exploits existentes raramente funcionam sem alterações ou modificações ao código do exploit subjacente. | Esta falha foi incluída no Top 10 baseado numa [inqúerito à indústria][1] e não baseado em dados quantitativos. Algumas ferramentas podem descobrir falhas de de-serialização, no entanto, a assistência humana é frequentemente necessária para validar o problema. É expectável que este tipo de vulnerabilidades seja cada vez mais prevalente e até venha a aumentar à medida que vão sendo desenvolvidas ferramentas para ajudar na identificação e correção. | O impacto das falhas de de-serialização não pode ser subestimado. Estas falhas podem levar a ataques de execução remota de código, um dos ataques existentes mais sérios. O impacto no negócio depende da necessidade de proteção dos dados. |

## A Aplicação é Vulnerável?

Aplicações e APIs são vulneráveis se de-serializarem dados não confiáveis ou
objetos adulterados fornecidos pelo atacante. Isto resulta em dois tipos
principais de ataques:

* Ataques relacionados com objetos e estruturas de dados em que o atacante
  consegue modificar logica aplicaciona ou executar remotamente código
  arbitrário se existirem classes cujo comportamento possa ser alterado durante
  ou depois da de-serialização.
* Ataques de adulteração de dados, tais como os relacionados com o controlo de
  acessos, on são utilizadas estruturas de dados existentes mas cujo conteúdo
  foi alterado.

A Serialização pode ser usada numa aplicação para:

* Comunicação remota e inter-processos (RPC/IPC) 
* Wire protocols, web services, message brokers
* Caching/Persistência
* Base de Dados, servidores de cache, sistem de ficheiros
* HTTP cookies, parâmetros de formulários HTML, tokens de autenticação em APIs

## Como Prevenir

A única forma segura de utilizar serialização pressupõe que não são aceites
objetos serializados de fonts não confiávies e que só são permitidos tipos de
dados primitivos.
Se isto não for possível, considere uma ou  mais das seguintes recomendações:

* Implementar verificações de integridade como assinatura digital nos objetos
  serializados como forma de prevenir a criação de dados hostis ou adulteração
  de dados
* Aplicar uma política rigorosa de tipos de dados durante a de-serialização,
  antes da criação do objeto uma vez que a lógica tipicamente espera um conjunto
  de classes bem definido. Uma vez que existem formas demonstradas de contornar
  esta técnica, ela não deve ser usada individualmente.
* Isolar e correr a lógica de de-serialização, sempre que possível, num ambiente
  com privilégios mínimos.
* Registar exceções e falhas na de-serialização tais como tipos de dados não
  expectáveis.
* Restringir e monitorizar o tráfego de entrada e saída dos containers e
  servidores que realização de-serialização.
* Monitorizar a de-serialização, gerando alertas quando esta operação é
  realizada com frequência anómala.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação de React invoca um conjunto de micro-serviços
Spring Boot. Sendo programadores funcionais, tentaram assegurar que o seu código
fosse imutável. A solução que arranjaram foi serializar o estado do utilizador e
passar o mesmo de um lado para o outro em cada um dos pedidos. Um atacante
apercebe-se da existência "R00" de um objeto Java, e usa a ferramenta Java
Serial Killer para ganhar a possibilidade de executar código remoto no servidor
aplicacional.

**Cenário #2**: Um fórum de PHP usa a serialização de objetos PHP para gravar um
"super" cookie que contém o identificador (ID) do utilizador, o seu papel, o
resumo (hash) da sua password e outros estados:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

Um atacante pode mudar o objeto serializado para lhe dar previlégios de
administrador:

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
* https://github.com/mbechler/marshalsec

[1]: https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html

