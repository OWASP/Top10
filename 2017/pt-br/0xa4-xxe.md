# A4:2017 Entidades Externas de XML (XML External Entities - XXE)

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança     | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 2 | Prevalência 2 \| Detectabilidade 3 | Técnico 3 \| Negócio |
| Atacantes podem explorar processadores XML vulneráveis se eles puderem fazer upload de XML ou incluir conteúdo hostil em um documento XML, explorando código vulnerável, dependências ou integrações. | Por padrão, muitos processadores XML mais antigos permitem a especificação de uma entidade externa, um URI que é desreferenciado e avaliado durante o processamento XML. Ferramentas [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) podem descobrir esse problema inspecionando dependências e configuração. Ferramentas [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) requerem etapas manuais adicionais para detectar e explorar esse problema.| Essas falhas podem ser usadas para extrair dados, executar uma solicitação remota do servidor, escanear sistemas internos, realizar um ataque de negação de serviço e outros ataques. O impacto comercial depende das necessidades de proteção de todas as aplicações e dados afetados. |

## A Aplicação Está Vulnerável?

Aplicações e, em particular, serviços Web baseados em XML ou integrações em sistemas legados podem ser vulneráveis a ataques se:

* Sua aplicação aceita XML diretamente ou uploads de XML, especialmente de fontes não confiáveis, ou insere dados não confiáveis em documentos XML, que é então analisado por um processador XML.
* Qualquer um dos processadores XML na aplicação ou serviços web baseados em SOAP tem [definições de tipo de documento (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition) habilitados. Como o mecanismo exato para desabilitar o processamento de DTD varia de acordo com o processador, é recomendável consultar uma referência, como [OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Se sua aplicação usa SAML para processamento de identidade dentro de um sistema de segurança em federação ou de logon único (SSO). SAML usa XML para asserções de identidade e pode ser vulnerável.
* Se sua aplicação usa SOAP antes da versão 1.2, provavelmente estará suscetível a ataques XXE se as entidades XML estiverem sendo passadas para o framework SOAP.
* Ser vulnerável aos ataques do XXE provavelmente significa que sua aplicação é vulnerável a ataques de negação de serviço, incluindo o ataque de um bilhão de risos (*billion laughs attack*)

## Como Prevenir

Treinamento de desenvolvedor é essencial para identificar e mitigar o XXE. Além disso, a prevenção do XXE exige:

* Sempre que possível, use um formato de dados menos complicado, como JSON.
* Aplique os patches ou atualize todos os processadores e bibliotecas XML em uso pela aplicação ou em seu sistema operacional. Use controladores de dependência. Atualize o SOAP para SOAP 1.2 ou superior.
* Desabilite o processamento de DTD e entidade externa XML em todos os analisadores de XML da sua aplicação, de acordo com o [OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Implementar validação positiva de entrada do lado do servidor ("lista branca"), filtragem ou sanitização para prevenir dados hostis em documentos, cabeçalhos ou nós XML.
* Verifique se a funcionalidade de upload de arquivos XML ou XSL valida o XML entrante usando a validação XSD ou similar.
* Ferramentas SAST podem ajudar a detectar o XXE no código-fonte, embora a revisão manual do código seja a melhor alternativa em aplicações grandes e complexas com muitas integrações.

Se esses controles não forem possíveis, considere a utilização de patches virtuais, gateways de segurança de API, ou WAFs para detectar, monitorar e bloquear ataques de XXE.

## Examplos de Cenários de Ataque

Numerosos problemas públicos de XXE foram descobertos, incluindo o ataque a dispositivos *embedded*. O XXE ocorre em muitos lugares inesperados, incluindo dependências profundamente aninhadas. A maneira mais fácil é carregar um arquivo XML malicioso, se aceito:

**Cenário #1**: O atacante tenta extrair dados do servidor:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Cenário #2**: Um atacante examina a rede privada do servidor alterando a linha ENTITY acima para:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Cenario #3**: Um atacante tenta um ataque de negação de serviço, incluindo um arquivo potencialmente infinito:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## Referências

### OWASP

* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for XML Injection](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Vulnerability](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheat Sheet: XXE Prevention](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XML Security](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### Externas

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
