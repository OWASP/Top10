# A4:2017 Entidades Externas de XML (XXE)

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 2 | Prevalência 2 \| Deteção 3 | Técnico 3 \| Negócio |
| Os atacantes podem explorar processadores de XML vulneráveis se eles conseguirem carregar XML ou incluir conteúdo malicioso num documento XML, explorando o código vulnerável, dependências ou integrações. Profssionais de testes de intrusões podem explorar o XXE. Ferramentas DAST necessitam de passos manuais adicionais para explorar este aspecto. | Por defeito, muitos dos processadores de XML mais antigos permitem a especificação de entidades externas, uma URI que é de-referenciada e avaliada durante o processamento do XML. As ferramentas SAST podem descobrir este aspecto através da inspecção das dependências e da configuração. | Estas falhas podem ser usadas para extrair dados, executar um pedido remoto de um servidor, analizar sistemas internos, efectuar ataques de negação de serviço, e outros ataques. O impacto no negócio depende das necessidades de proteção de todas aplicações de dados. |

## Está a Aplicação Vulnerável?

As aplicações e em particular servicos web basedos em XML ou integrações posteriores podem ser vulneráveis a ataques se:

* A sua aplicação aceita XML directamente ou carregamentos de XML, em particular de fontes de pouca confiança, ou se insere dados não-confiáveis em documentos XML, que é tratada pelo processador.
* Qualquer um dos processadores de XML numa aplicação ou em serviços web baseados em SOAP possui [definições de tipos de documento (*document type definition*s - DTDs)](https://en.wikipedia.org/wiki/Document_type_definition) activada. Uma vez que o mecanismo para desactivar o processamento de DTD varia de processador para processador, é recomendável que consulte uma referência como o [Cheat Sheet da OWASP de Prevenção do XXE](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Se a sua aplicação usa o SOAP anterior à versão 1.2, é provável que seja susceptível a ataques de XXE se as entidades de XAML estiverem a ser passadas à framework SOAP.
* As ferramentas de SAST podem ajudar a detectar XXE no código-fonte, ambora a revisão de código manual seja a melhor alternativa em aplicações grandes e complexas com muitas integrações.
* Ser vulnerável a ataques de XXE significa que provavelmente que é igualmente vulnerável a muitos outros ataques de negação de serviço.

## Como Prevenir?

O treino dos programadores é essencial para identificar e mitigar completamente o XXE. Para além disso, prevenir XXE requer:

* Correção ou actualização a todos os processadores e bibliotecas de XML a serem usados pela aplicação ou no sistema operativo que suporta a aplicação. A utilização de verificadores de dependências é crítico para gerir o risco de bibliotecas e componentes não apenas da sua aplicação, mas todas as integrações a jusante.
* Desactivar o processamento de entidades externas de XML e de DTD emm todos os processadores de XML na sua aplicação, tal como está no [Cheat Sheet da OWASP de Prevenção do XXE](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Implementar ("*whitelisting*") positivo na validação de entradas do lado do servidor, filtros, ou sanitização para prevenir dados hostis nos documentos de XML, cabeçalhos, ou nós.
* Verificar que a funcionalidade de carregamento de ficheiros XML ou XSL valida o XML usando a validação por XSD ou similar.
* Actualizar o SOAP para a versão mais.

Se estes controlos não forem possíveis considere a utilização de correções virtuais, *gateways* de segurança de API, ou WAFs para detectar, monitorizar, e bloquear ataques de XXE.

## Exemplos de Cenários de Ataque

Numerosos problemas públicos com o XXE têm vindo a ser descobertos, incluindo o ataques a dispositivos embebidos. O XXE ocorre em muitos locais não expectáveis, incluindo em dependências muito profundas. A forma mais simples é carregar um ficheiro XML, se for aceite:

**Cenário #1**: O atacante tenta extrair dados do servidor:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Cenário #2**: Um atacantes analiza a rede privada do servidor alterando a seguinte linha da ENTITY line para:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Cenário #3**: Um atacante tentar efectuar um ataque de negação de serviço incluindo um potencial ficheiro sem fim:

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
