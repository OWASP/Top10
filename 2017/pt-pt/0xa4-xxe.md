# A4:2017 Entidades Externas de XML (XXE)


| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 2 | Prevalência: 3 \| Deteção: 2 | Técnico: 3 \| Negócio ? |
| Os atacantes podem abusar de processadores XML vulneráveis se conseguirem carregar XML ou incluir conteúdo malicioso num documento XML, abusando assim do código vulnerável, dependências ou integrações. | Por omissão, muitos dos processadores de XML mais antigos permitem a especificação de entidades externas, um URI que pode ser acedido e avaliado durante o processamento do XML. As ferramentas [SAST][0xa41] podem descobrir este problema através da análise das dependências e configuração. A deteção por ferramentas [DAST][0xa42] implica processos manuais adicionais. | Estas falhas podem ser usadas para extrair dados, executar um pedido remoto a partir do servidor, efectuar ataques de negação de serviço entre outros. O impacto no negócio depende da necessidade de proteção das aplicações afetadas, bem como dos dados. |

## A Aplicação é Vulnerável?

As aplicações e em particular serviços web baseados em XML ou integrações
posteriores podem ser vulneráveis a ataques se:

- A aplicação aceita XML diretamente ou carregamentos de XML, em particular de
  fontes pouco confiáveis, ou se insere dados não-confiáveis em documentos XML,
  que são depois consumidos pelo processador.
- Qualquer um dos processadores de XML em uso na aplicação ou em serviços web
  baseados em SOAP permite Definição de Tipo de Documento ([DTD][0xa43]). A
  desativação do processamento de DTD varia entre processadores de XML, é
  recomendável que consulte uma referência como o [Cheat Sheet da OWASP sobre
  Prevenção do XXE][0xa44].
- Se a aplicação usa _Security Assertion Markup Language_ (SAML) para
  processamento de identidade no contexto de segurança federada ou Single
  Sign-on (SSO): SAML usa XML para validação da identidade e pode por isso ser
  vulnerável.
- Se a aplicação usa SOAP anterior à versão 1.2, é provável que seja suscetível
  a ataques de XXE se as entidades XML estiverem a ser passadas à _framework_
  SOAP.
- Ser vulnerável a ataques de XXE muito provavelmente significa também que a
  aplicação é igualmente vulnerável a ataques de negação de serviço, incluindo o
  ataque _billion laughs_.

## Como Prevenir

O treino dos programadores é essencial para identificar e mitigar completamente
o XXE. Para além disso:

- Optar por um formato de dados mais simples, tal como JSON.
- Corrigir ou atualizar todos os processadores e bibliotecas de XML usados pela
  aplicação, dependências ou sistema operativo. Atualizar SOAP para a versão 1.2
  ou superior.
- Desativar o processamento de entidades externas de XML e de DTD em todos os
  processadores de XML em uso pela aplicação, tal como definido no [Cheat Sheet
  da OWASP sobre Prevenção do XXE][0xa44].
- Implementar validação, filtragem ou sanitização dos dados de entrada para
  valores permitidos (whitelisting) prevenindo dados hostis nos documentos de
  XML, cabeçalhos ou nós.
- Verificar que a funcionalidade de carregamento de ficheiros XML ou XSL valida
  o XML usando para o efeito XSD ou similar.
- As ferramentas [SAST][0xa41] podem ajudar a detetar XXE no código fonte, ainda
  assim a revisão do código é a melhor alternativa em aplicações de grande
  dimensão e complexidade com várias integrações.

Se estes controlos não forem possíveis considere a utilização de correções
virtuais, gateways de segurança de APIs, ou WAFs para detetar, monitorizar e
bloquear ataques de XXE.

## Exemplos de Cenários de Ataque

Numerosos problemas públicos com XXE têm vindo a ser descobertos, incluindo
ataques a dispositivos embutidos. XXE ocorre em muitos locais não expectáveis,
incluindo em dependências muito profundas. A forma mais simples de abuso passa
por carregar um ficheiro XML, que, quando aceite:
Cenário #1: O atacante tenta extrair dados do servidor:

**Cenário #1**: O atacante tenta extrair dados do servidor:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

**Cenário #2**: Um atacante analisa a rede privada do servidor alterando a
seguinte linha da `ENTITY` para:

```xml
<!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Cenário #3**: Um atacante tenta efetuar um ataque de negação de serviço
incluindo um potencial ficheiro sem fim:

```xml
<!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## Referências

### OWASP

- [OWASP Application Security Verification Standard][0xa45]
- [OWASP Testing Guide: Testing for XML Injection][0xa46]
- [OWASP XXE Vulnerability][0xa47]
- [OWASP Cheat Sheet: XXE Prevention][0xa44]
- [OWASP Cheat Sheet: XML Security][0xa49]

### Externas

- [CWE-611: Improper Restriction of XXE][0xa410]
- [Billion Laughs Attack][0xa411]

[0xa41]: https://owasp.org/www-community/Source_Code_Analysis_Tools
[0xa42]: https://owasp.org/www-community/Vulnerability_Scanning_Tools
[0xa43]: https://en.wikipedia.org/wiki/Document_type_definition
[0xa44]: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
[0xa45]: https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md
[0xa46]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
[0xa47]: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processingi
[0xa49]: https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html
[0xa410]: https://cwe.mitre.org/data/definitions/611.html
[0xa411]: https://en.wikipedia.org/wiki/Billion_laughs_attack

