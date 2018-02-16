# A8:2017 De-serialização Insegura

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 1 | Prevalência 2 \| Deteção 2 | Técnico 3 \| Negócio |
| A exploração da de-serialização é algo difícil, uma vez que os exploits existentes ("off the shelft") raramente funcionam sem alterações ou modificações ao código do exploit subjacente. | Este assunto está incluido no Top 10 baseado numa [pesquisa de indústria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) e não baseado em dados quantificávis. Algumas ferramentas podem descobrir falhas de de-serialização, no entanto, a assistência humana é frequentemente necessária para validar o problema. É expectável que este tipo de vulnerabilidades seja cada vez mais prevalente e até venha a aumentar à medida que vão sendo desenvolvidas ferramentas para as ajudar a identificar e corrigir. | O impacto das falhas de de-serialização não pode ser entendido. Podem levar a ataques de execução remota de código, um dos ataques existentes mais sérios. |

## Está a Aplicação Vulnerável?

As aplicações distribuídas ou aquelas que necessitam de armazenat o estado em clientes ou no sistema de ficheiros podem usar de-serialização de objectos. Aplicações distribuídas com "listeners" públicos ou aplicações que dependem da manutenção do estado no cliente, estão sujeitas a modificações nos dados serializados. Este ataque pode ser possível independentemente do formato de serialização usada (binária ou textual) ou da linguagem de programação. Aplicações ou APIs estarão vulneráveis quando:
* O mecanismo de serialização permite a criação de tipos de dados arbitrários, E
* Existam classes disponíveis para a aplicação que possam ser ligadas para modificar o comportamento da aplicação durante ou após a de-serialização, ou conteúdo não-intencional pode ser usado para influenciar o comportamento da aplicação, E
* A aplicação ou API aceita e de-serializa objectos hostis fornecidos pelo atacante, ou uma aplicação use um estado opaco do lado cliente sem os mecanismos de controlo de prvenção de alterações, OU
* Estado de segurança enviado para um cliente não-confiável sem algum tipo de controlo de integridade é provavelmente vulnerável a ataques na de-serialização.

## Como Prevenir?

O único padrão arquitectural seguro é não aceitar objectos serializados de fontes não-confiáveis ou usar mecanismos de serialização que apenas permitem tipos de dados primitivos.

Se tal não for possível:
* Implementar validações de integridade or encriptação dos objectos serializados para prevenir a criação de objectos hostis ou a modificação de dados.
* Forçar restrições de tipos específicos durante a de-serialização antes da criação do objecto; tipicamente o código está à espera de um conjunto definido de classes. Formas de ultrapassar esta técnica já foram anteriormente demonstradas.
* Isolar o código que efectua de-serializações, fazendo com o que o mesmo seja executado em ambientes com poucos previlégios.
* Registe excepções e falhas na de-serialização, tais como quando o tipo à chegada não é o esperado, ou se a de-serialização lança excepções.
* Restringir ou monitorizar ligações de entrada e saída da rede de contentores ou servidores que efectuam de-serialização.
* Monitorizar a de-serialização, e alertar se um utilizador está permanentemente a de-serializar.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação de React invoca um conjunto de micro-serviços Spring Boot. Sendo programadores funcionais, tentaram assegurar que o seu código fosse imutável. A solução que arranjaram foi serializar o estado do utilizador e passar o mesmo de um lado para o outro em cada um dos pedidos. Um atacante apercebe-se da existência "R00" de um objecto Java, e usa a ferramenta Java Serial Killer para ganhar a possibilidade de executar código remoto no servidor aplicacional.

**Cenário #2**: Um fórum de PHP usa a serialização de objectos PHP para gravar um "super" cookie que contém o identificador (ID) do utilizador, o seu papel, o hash da sua password, e outros estados:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

Um atacante pode mudar o objecto serializado para lhe dar previlégios de administrador:

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
