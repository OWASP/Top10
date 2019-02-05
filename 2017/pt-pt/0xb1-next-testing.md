# +T O que se segue para os profissionais de testes de software

## Estebelecer um Plano contínuo de Testes de Segurança

Desenvolver código seguro é importante. Mas é crítico verificar se a segurança
que se pretende construir está actualmente presente, devidamente implementada, e
utilizada em toda as partes onde é suposto estar. O objectivo dos testes de
segurança aplicacional é o de fornecer esta prova. É um trabalho dificil e
complexo, e os rápidos processos modernos de desenvolvimento de software tais
como Agile e DevOps colocam pressão extrema nas abordagens e ferramentas
tradicionais. Assim, encorajamos seriamente que dedique algum tempo a refletir
sobre a forma como se vai focar no que é importante no seu portfolio completo de
aplicações, e fazê-lo de forma economicamente viável.

Os riscos modernos alteram-se frequentemente,  e por isso os dias da análise
exaustiva e testes de intrusão que eram realizados uma vez a cada dois anos já
não existem. O desenvolvimento moderno de software necessita de testes continuos
de segurança aplicacional ao longo do ciclo de desenvolvimento de software.
Procure melhorar as linhas de produção de software existentes com mecanismos de
automação de segurança que não atrasem o desenvolvimento. Qualquer que seja a
abordagem escolhida, considere o custo anual dos testes a realizar, multiplicado
pelo tamanho do seu portfolio aplicacional.

| Actividade | Descrição |
| --- | --- |
| Perceber o Modelo de Ameaças | Antes de começar a testar, tenha a certeza que percebe onde é que deve dedicar mais tempo. As prioridades têm origem no modelo de ameaças, e portanto se não tiver um, necessita de criar um antes de começar a testar. Considere a utilização do [OWASP ASVS][1] e do [OWASP Testing Guide][2] como recomendações e não dependa de vendedores de ferramentas para decidir o que é mais importantes para o seu negócio. |
| Perceber o seu SDLC | A sua abordagem aos testes de segurança aplicacional devem ser compatíveis com as pessoas, processos e ferramentas que usa no seu ciclo de desenvolvimento de software (SDLC). Tentativas para forçar passos, entraves e revisões extra vão provavelmente causar dificuldades, vão ser ultrapassados, e não vão ser escaláveis. Procure oportunidades naturais para reunir informação de segurança e passá-la ao seu processo de desenvolvimento. |
| Estratégias de Teste | Escolha a mais simples, rápida e mais precisa técnica para verificar cada requisito. A [OWASP Security Knowledge Framework][3] e o [OWASP Application Security Verification Standard][4] podem ser bons recursos de requisitos funcionais e não funcionais de segurança nos seus testes unitários e de integração. Tenha a certeza que considera os recursos humanos necessários para lidar com os falsos positivos resultantes da utilização de ferramentas automáticas, tais como com os problemas sérios resultantes dos falsos negativos. |
| Alcançar Cobertura e Precisão | Não precisa de testar tudo imediatamente. Foque-se no que é mais importante e expanda o seu programa de verificação ao longo do tempo. Isso significa expandir o conjunto de defesas de segurança e riscos que estão a ser verificados automaticamente, além de expandir o conjunto de aplicações e APIs cobertos. O objetivo é chegar ao ponto onde a segurança essencial de todas as suas aplicações e APIs é verificada continuamente. |
| Tornar os Resultados Impressionantes | Não interessa o quão bom você é nos testes, não fará qualquer diferença a menos que você o comunique de forma eficaz. Crie confiança mostrando que você entende como a aplicação funciona. Descreva claramente como a mesma pode ser abusada sem "linguagem técnica" e inclua um cenário de ataque para torná-lo real. Faça uma estimativa realista de quão difícil a vulnerabilidade é de descobrir e abusar e quão mau seria. Finalmente, forneça resultados nas ferramentas que as equipes de desenvolvimento já estão usar, e não em ficheiros PDF. |

[1]: https://www.owasp.org/index.php/ASVS
[2]: https://www.owasp.org/index.php/OWASP_Testing_Project
[3]: https://www.owasp.org/index.php/OWASP_Security_Knowledge_Framework
[4]: https://www.owasp.org/index.php/ASVS

