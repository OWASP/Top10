# A2:2017 Quebra de Autenticação

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 3 | Prevalência 2 \| Deteção 2 | Técnico 3 \| Negócio |
| Os atacantes têm acesso a centenas de milhões de combinações de nomes de utilizadores e palavras-passe válidas para preenchimento de credenciais, listas de contas administrativas padrão, ferramentas automatizadas de força bruta e ferramentas de ataque de dicionário e ferramentas avançadas de quebra palavras-passe recorrendo ao GPU.  | A prevalência da quebra de autenticação está muito espalhada devido ao desenho e implementação de muitos systemas de gestão de identidades e acesso. Os atacantes podem detectar quebras de autenticação usando formas manuais, mas são mais atraídos por listagens de palavras-pass, ou depois de um ataque de engenharia social como phishing ou semelhante. | Os atacantes apenas têm que ganhar acesso a algumas contas, ou apenas uma conta de administrador para comprometer o sistema. Dependendo do domínio da aplicação, isto pode permitir a lavagem de dinheiro, fraudes na segurança social e roubo de identidade; ou revelação de informação muito sensível. |

## Está a Aplicação Vulnerável?

A confirmação da identidade, autenticação e gestão de sessões dos utilizadores são criticias para separar utilizadores maliciosos não autenticados de utilizadores autorizados. A sua aplicação tem fraquezas na autenticação se:

* Permite [teste exaustivo de passwords, ou "*credential stuffing*"](https://www.owasp.org/index.php/Credential_stuffing), em que o atacante possui uma lista de nomes de utilizadores válidos e palavras-passe.
* Permite ataques de força bruta ou outro tipo de ataques automatizados.
* Permite palavras-passe por defeito, fracas ou muito conhecidas, tais somo "Password1" ou "admin/admin".
* Usa processos fracos de recuperação de credenciais ou de esquecimento de palavras-passe, tais como "perguntas baseadas em conhecimento", que podem não ser consideradas seguras.
* A utilização de palavras-passe em claro, encriptadas, ou com resumos fracos permite a rápida recureação de palavras-passe usando "*crackers*" de GPU ou ferramentas de força bruta.
* Não possua autenticação multifactor ou que a mesma não funcione correctamente.
* Expõe os identificadores de sessão na URL (p.e., na reescrita de URLs).
* Não roda os identificadores de sessão após o processo de "login" ter sido bem sucedido.
* Não invalida convenientemente os identificadores de sessão. As sessões do utilizador ou os tokens de autenticação (em particular os de "single sign-on" (SSO)) não são invalidados convenientemente durante o processo de "logout" ou após um período de inactividade.

## Como Prevenir?

* Não disponibilizar a aplicação com credenciais por defeito, em especial para utilizadores administradores
* [Armazenar palavras-passe recorrendo a funções de resumo modernas](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Leverage_an_adaptive_one-way_function), tais como Argon2 ou PBKDF2, com um factor de complexidade suficiente para prevenir ataques baseados em "*crackers*" de GPU
* Implementar verificações de palavras-chave fracas, tais como testar palavras-passe novas ou alteradas com a lista [das Top 10000 piores palavras-passe](https://github.com/danielmiessler/SecLists/tree/master/Passwords).
* Alinhar o comprimento da palavra-passe, complexidade e políticas de rotatividade com o guia [NIST 800-63 B na secção 5.1.1 para "*Memorized Secrets*"](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) ou outras políticas modernas para palavras-passe, baseadas em evidências.
* Assegurar que o registo, recuperação de credenciais, e caminhos da API estão preparados para resistirem a ataques de enumeração de contas usando as mesmas mensagesn para todos os resultados.
* Sempre que possível, implementar autenticação multifactor para prevenir ataques de testes exaustivos de palavras-passe, de força-bruta, de automatização e de roubos de credenciais.
* Registar falhas de autenticação e alertar os administradores sempre que forem detectados ataques de testes exaustivos de palavras-passe, de força bruta ou outros.

## Exemplos de Cenários de Ataque

**Cenário #1**: [o teste exaustivo de credenciais, ou "*credential stuffing*"](https://www.owasp.org/index.php/Credential_stuffing), que consiste na utilização de [listas de palavras-passe conhecidas](https://github.com/danielmiessler/SecLists), é um ataque comum. Se uma aplicação nãp limitar o número de tentativas de autenticação, a aplicação pode ser usada como um oráculo de palavras-pase para determinar se as credenciais são válidas.

**Cenário #2**: A maioria dos ataques de autenticação ocorrem devido ao facto de se usarem as palavras-passe como único factor. Outrora consideradas boas práticas, a rotatividade das palavras-passe e a complexidade das mesmas são hoje vistas como factores para encorajar os utilizadores a usar e reutilizaresm palavras-passe fracas. As organizações são recomendadas a deixarem de usar estas práticas (NIST 800-63) e passarem a usar autenticação multifactor.

**Cenário #3**: O armazenamento inseguro de palavras-passe (incluindo a utilização de texto em claro, palavras-passe encriptadas de forma reversível, ou usando funções de resumo fracas (tais como MD5/SHA1 com ou sem *salt*) pode dar origem a quebras de confidencialidade (*breaches*). Um esforço recente levado a cabo por um pequeno grupo de investigadores conseguiu quebrar [320 milhões de palavras-passe em menos de 3 semanas](https://cynosureprime.blogspot.com.au/2017/08/320-million-hashes-exposed.html), inclusivé palavras-passe longas. Ao invés use algoritmos de geração de reumos modernos tais como o Argon2, usando um "salt" e um factor de complexidade suficientemente grande para prevenir contra a utilização de tabelas arco-iris ("*rainbow tables*"), listas de palavras, entre outros.

## Referências

### OWASP

* [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls)
* [OWASP Application Security Verification Standard: V2 Authentication](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Application Security Verification Standard: V3 Session Management](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Identity](https://www.owasp.org/index.php/Testing_Identity_Management)
 and [Authentication](https://www.owasp.org/index.php/Testing_for_authentication)
* [OWASP Cheat Sheet: Authentication](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)
* [OWASP Cheat Sheet: Credential Stuffing](https://www.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Forgot Password](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [OWASP Cheat Sheet: Password Storage](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [OWASP Cheat Sheet: Session Management](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)

### Externas

* [NIST 800-63b: 5.1.1 Memorized Secrets - for thorough, modern, evidence based advice on authentication.](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
