# A05:2021 – Configuração Incorreta de Segurança    ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## Fatores

| CWEs Mapeados | Taxa de Incidência Máxima | Taxa de Incidência Média | Exploração Média Ponderada | Impacto Médio Ponderado | Cobertura Máxima | Cobertura Média | Total de ocorrências | Total de CVEs |
|:-------------:|:-------------------------:|:------------------------:|:--------------------------:|:-----------------------:|:----------------:|:---------------:|:--------------------:|:-------------:|
| 20            | 19.84%                    | 4.51%                    | 8.12                       | 6.56                    | 89.58%           | 44.84%          | 208,387              | 789           |

## Visão Geral

Saindo da #6 posição na edição anterior, 90% das aplicações foram testados
para alguma forma de configuração incorreta, com uma taxa de incidência
média de 4% e mais de 208 mil ocorrências de _Common Weakness Enumeration_ (CWE)
nesta categoria de risco. Com mais mudanças em software altamente configurável,
não é surpreendente ver essa categoria subir. CWEs notáveis incluídos são
*CWE-16 Configuração* e *CWE-611 Restrição Imprópria de Referência de Entidade Externa XML*.

## Descrição 

A aplicação pode ser vulnerável se for:

- Falta de proteção de segurança apropriada em qualquer parte
    da _stack_ das aplicações ou permissões configuradas incorretamente
    em serviços em nuvem.

- Recursos desnecessários são ativados ou instalados (por exemplo,
    portas, serviços, páginas, contas ou privilégios desnecessários).

- As contas padrão e suas senhas ainda estão ativadas e inalteradas.

- O tratamento de erros revela _stack traces_ ou outras
    mensagens de erro excessivamente informativas aos usuários.

- Para sistemas atualizados, os recursos de segurança mais recentes
    estão desabilitados ou não estão configurados com segurança.

- As configurações de segurança nos servidores das aplicações, nos
    _frameworks_ (por exemplo, Struts, Spring, ASP.NET), bibliotecas,
    bancos de dados, etc., não estão definidas para proteger os valores.

- O servidor não envia cabeçalhos ou diretivas de segurança, ou eles
    não estão configurados para proteger os valores.

- O software está desatualizado ou vulnerável (consulte
  [A06: 2021-Componentes Vulneráveis e Desatualizados](A06_2021-Vulnerable_and_Outdated_Components.pt_BR.md)).

Sem um processo de configuração de segurança de aplicações que seja integrado e
repetível, os sistemas correm um risco maior.

## Como Prevenir

Devem ser implementados processos de instalação segura, incluindo:

- Um processo de proteção repetível torna mais rápido e fácil implantar
    outro ambiente que esteja devidamente bloqueado. Os ambientes de
    desenvolvimento, controle de qualidade e produção devem ser todos
    configurados de forma idêntica, com credenciais diferentes usadas
    em cada ambiente. Este processo deve ser automatizado para minimizar
    o esforço necessário para configurar um novo ambiente seguro.

- Uma plataforma mínima sem recursos, componentes, documentação e outros
    desnecessários. Remova ou não instale recursos e estruturas não utilizados.

- - Uma tarefa para revisar e atualizar as configurações apropriadas para todas
    as notas de segurança, atualizações e patches como parte do processo de
    gerenciamento de patch (consulte
    [A06: 2021-Componentes Vulneráveis e Desatualizados](A06_2021-Vulnerable_and_Outdated_Components.pt_BR.md)).
    Revise as permissões de armazenamento em nuvem (por exemplo, _S3 bucket permissions_).

- Uma arquitetura de aplicação segmentada fornece separação eficaz e
    segura entre componentes ou _tenants_, com segmentação,
    conteinerização ou grupos de segurança em nuvem (ACLs).

- Envio de diretivas de segurança para clientes, por exemplo, _Security Headers_.

- Um processo automatizado para verificar a eficácia das configurações
    em todos os ambientes.

## Exemplos de Cenários de Ataque

**Cenário #1:** O servidor da aplicação é fornecido com os sistemas de amostra
não removidos do servidor de produção. Esses aplicativos de amostra têm
falhas de segurança conhecidas que os invasores usam para comprometer o
servidor. Suponha que um desses aplicativos seja o console de administração
e as contas padrão não tenham sido alteradas. Nesse caso, o invasor
efetua login com as senhas padrão e assume o controle.

**Cenário #2:** A listagem do diretório não está desabilitada no servidor.
Um invasor descobre que pode simplesmente listar diretórios. O invasor
encontra e baixa as classes Java compiladas, que ele descompila e
faz engenharia reversa para visualizar o código. O invasor então
encontra uma falha grave de controle de acesso no aplicativo.

**Cenário #3:** A configuração do servidor de aplicações permite que os
detalhes das mensagens de erro, por exemplo, _stack trace_, sejam retornadas
aos usuários. Isso potencialmente expõe informações confidenciais ou falhas
subjacentes, como versões de componentes que são conhecidas por serem vulneráveis.

**Cenário #4:** Um provedor de serviços de nuvem tem permissões de
compartilhamento padrão abertas para a Internet por outros usuários de
_Content Security Policy header (CSP)_. Isso permite que dados confidenciais
armazenados no armazenamento em nuvem sejam acessados.

## Referências

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

-   Application Security Verification Standard V19 Configuration

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## Lista dos CWEs Mapeados

[CWE-2 7PK - Environment](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET Misconfiguration: Use of Impersonation](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 Java Runtime Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 Inclusion of Sensitive Information in an Include File](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

[CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
