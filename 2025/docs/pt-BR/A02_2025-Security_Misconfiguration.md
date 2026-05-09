# A02:2025 – Configuração Insegura (Security Misconfiguration) ![icon](../assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## Contexto

Subindo da 5ª posição na edição anterior, foi constatado que 100% das aplicações testadas apresentavam alguma forma de configuração incorreta, com uma taxa média de incidência de 3,00% e mais de 719 mil ocorrências de CWEs (_Common Weakness Enumeration_) nesta categoria de risco. Com a migração crescente para softwares altamente configuráveis, não é surpresa ver esta categoria subir no ranking. As CWEs notáveis incluídas são _CWE-16 Configuration_ e _CWE-611 Improper Restriction of XML External Entity Reference (XXE)_.

## Tabela de Pontuação

<table>
  <tr>
   <td>CWEs Mapeadas 
   </td>
   <td>Taxa Máx. de Incidência
   </td>
   <td>Taxa Média de Incidência
   </td>
   <td>Cobertura Máxima
   </td>
   <td>Cobertura Média
   </td>
   <td>Exploit Médio Ponderado
   </td>
   <td>Impacto Médio Ponderado
   </td>
   <td>Total de Ocorrências
   </td>
   <td>Total de CVEs
   </td>
  </tr>
  <tr>
   <td>16
   </td>
   <td>27.70%
   </td>
   <td>3.00%
   </td>
   <td>100.00%
   </td>
   <td>52.35%
   </td>
   <td>7.96
   </td>
   <td>3.97
   </td>
   <td>719,084
   </td>
   <td>1,375
   </td>
  </tr>
</table>

## Descrição

A configuração insegura ocorre quando um sistema, aplicação ou serviço de nuvem é configurado incorretamente do ponto de vista de segurança, criando vulnerabilidades.

A aplicação pode estar vulnerável se:

- Faltar o endurecimento de segurança (_security hardening_) apropriado em qualquer parte da stack da aplicação ou se houver permissões configuradas incorretamente em serviços de nuvem.
- Recursos desnecessários estiverem habilitados ou instalados (ex: portas, serviços, páginas, contas, **frameworks** de teste ou privilégios desnecessários).
- Contas padrão e suas senhas ainda estiverem habilitadas e inalteradas.
- Houver falta de uma configuração centralizada para interceptar mensagens de erro excessivas. O tratamento de erros revela _stack traces_ ou outras mensagens de erro excessivamente informativas aos usuários.
- Para sistemas atualizados, os recursos de segurança mais recentes estiverem desativados ou não configurados com segurança.
- Houver priorização excessiva da compatibilidade reversa, levando a configurações inseguras.
- As configurações de segurança nos servidores de aplicação, **frameworks** (ex: Struts, Spring, ASP.NET), bibliotecas, bancos de dados, etc., não estiverem definidas com valores seguros.
- O servidor não enviar **headers** ou diretivas de segurança, ou se estes não estiverem configurados com valores seguros.

Sem um processo de endurecimento (_hardening_) de configuração de segurança de aplicação concentrado e repetível, os sistemas correm um risco maior.

## Como Prevenir

Processos de instalação seguros devem ser implementados, incluindo:

- Um processo de _hardening_ repetível que permita a implantação rápida e fácil de outro ambiente devidamente bloqueado. Os ambientes de desenvolvimento, QA e produção devem ser configurados de forma idêntica, com credenciais diferentes usadas em cada um. Este processo deve ser automatizado para minimizar o esforço necessário para configurar um novo ambiente seguro.
- Uma plataforma mínima, sem quaisquer recursos, componentes, documentação ou amostras desnecessárias. Remova ou não instale recursos e **frameworks** não utilizados.
- Uma tarefa para revisar e atualizar as configurações de acordo com todas as notas de segurança, atualizações e **patches** como parte do processo de gerenciamento de **patches** (veja [A03 Falhas na Cadeia de Suprimentos de Software](A03_2025-Software_Supply_Chain_Failures.md)). Revise as permissões de armazenamento em nuvem (ex: permissões de buckets S3).
- Uma arquitetura de aplicação segmentada que forneça separação eficaz e segura entre componentes ou usuários (_tenants_), com segmentação, conteinerização ou grupos de segurança de nuvem (ACLs).
- Envio de diretivas de segurança para os clientes, ex: **headers** de segurança.
- Um processo automatizado para verificar a eficácia das configurações e definições em todos os ambientes.
- Adição proativa de uma configuração central para interceptar mensagens de erro excessivas como reserva (_backup_).
- Se essas verificações não forem automatizadas, elas devem ser verificadas manualmente, no mínimo, anualmente.
- Utilize federação de identidade, credenciais de curta duração ou mecanismos de acesso baseados em funções (RBAC) fornecidos pela plataforma subjacente, em vez de incorporar chaves estáticas ou segredos (_secrets_) no código, arquivos de configuração ou **pipelines**.

## Exemplos de Cenários de Ataque

**Cenário #1:** O servidor de aplicação vem com aplicações de exemplo não removidas do servidor de produção. Essas aplicações de exemplo têm falhas de segurança conhecidas que os **atacantes** usam para comprometer o servidor. Suponha que uma dessas aplicações seja o console de administração e as contas padrão não foram alteradas. Nesse caso, o **atacante** faz o login com a senha padrão e assume o controle.

**Cenário #2:** A listagem de diretórios não está desativada no servidor. Um **atacante** descobre que pode simplesmente listar os diretórios. O **atacante** encontra e baixa as classes Java compiladas, que ele descompila e faz engenharia reversa para visualizar o código. O **atacante**, então, encontra uma falha grave de controle de acesso na aplicação.

**Cenário #3:** A configuração do servidor de aplicação permite que mensagens de erro detalhadas, como _stack traces_, sejam retornadas aos usuários. Isso potencialmente expõe informações sensíveis ou falhas subjacentes, como versões de componentes que são conhecidamente vulneráveis.

**Cenário #4:** Um provedor de serviços de nuvem (CSP) define por padrão permissões de compartilhamento abertas para a Internet. Isso permite que dados sensíveis armazenados no armazenamento em nuvem sejam acessados.

## Referências

- [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
- [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
- [Application Security Verification Standard V13 Configuration](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
- [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
- ScienceDirect: Security Misconfiguration

## Lista de CWEs Mapeadas

- [CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption](https://cwe.mitre.org/data/definitions/5.html)
- [CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)
- [CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)
- [CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)
- [CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)
- [CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)
- [CWE-489 Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)
- [CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)
- [CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)
- [CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
