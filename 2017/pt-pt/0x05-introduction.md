# I Introdução
## Seja bem vindo ao OWASP Top 10 - 2017

Esta nova actualização acrescenta um conjunto de novos problemas, incluindo dois problemas selecionados pela comunidade - **A8:2017 - De-serialização Insegura** e **A10:2017 - Registo e Monitorização Insuficiente**. A opinião da comunidade guiou a coleção do maior conjunto de dados alguma vez recolhido na preparação de um standard de segurança aplicacional, e por isso estamos confiantes  que os restantes 8 problemas são os mais importantes para as organizações enfrentarem, em particular o **A3:2017 - Exposição de Dados Sensíveis** importante na era da Regulamentação Geral da Protecção de Dados (GDPR) da UE, **A6:2017 - Más Configurações de Segurança** em particular no que respeita a serviços de APIs e cloud, e **A9:2017 -Utilização de Componentes com Vulnerabilidades Conhecidas**, que pode ser particularmente desafiante para plataformas mais modernas, como o  node.js.

O OWASP Top 10 de 2017 é baseado principalmente em mais de 40 submissões de dados de empresas que são especializadas na área da segurança aplicacional e um inquérito realizado à indústria que obteve  515 respostas individuais. Estes dados refletem vulnerabilidades colecionadas de centenas de organizações e cerca de 100,000 aplicações e APIs reais. O itens do Top 10 foram selecionados e ordenados de acordo com a sua prevalência, combinadas com estimativas consensualizadas sobre a sua exploração, detecção e impacto.

O principal objectivo do OWASP Top 10 é o de educar programadores, desenhadores e arquitectos de aplicações, gestores e organizações sobre as consequências das mais comuns e mais importantes fraquezas de segurança em aplicações web. O Top 10 oferece técnicas básicas para proteger contra estas áreas problemáticas de elevado risco, e oferece direções sobre onde pode encontrar informação adicional sobre estes aspectos.

## Planeamento para actividades futuras

**Não pare no 10**. Existem centenas de problemas que podem afectar a segurança geral de uma aplicação web tal como discutido no [Guia de Programadores da OWASP][1] e nas [Séries de Cheat Sheets da OWASP][2]. Isto é leitura essencial para alguém que esteja a desenvolver aplicações web e APIs. Informação sobre como enThese are essential reading for anyone developing web applications and APIs. Guidance on how to effectively find vulnerabilities in web applications and APIs is provided in the [OWASP Testing Guide][3].

**Mudança constante**. O OWASP Top 10 vai continuar a mudar. Mesmo sem mudar uma única linha no código da sua aplicação, pode ficar vulnerável à medida que novas falhas são descobertas e métodos de ataque são refinados. Por favor, reveja os conselhos no final do Top 10 na parte “O que se se segue para Programadores, profissionais de Testes e Organizações” para mais informação.

**Pense positivo**. Quando estiver pronto para parar de perseguir vulnerabilidades e focar-se  no estabelecimento de controlos fortes de segurança aplicacional, a OWASP mantém e promove o [Standard de Verificação de Segurança Aplicacional da OWASP (ASVS)][4] como guia de aspectos a verificar para as organizações e revisores de aplicações.

**Use as ferramentas de forma inteligente**. As vulnerabilidades de segurança podem ser bastante complexas e muito intrincadas no meio do código. Em muitos casos, a abordagem mais eficiente para encontrar e eliminar estas fraquezas, consiste na utilização de especialistas humanos munidos de boas ferramentas.

**Empurre para esquerda, para a direita e para todo o lado**. Foco deve estar em tornar a segurança uma parte integral da cultura da sua organização em particular no departamento de desenvolvimento. Pode encontrar mais informação em [Modelo de Garantia da Maturidade do Software da OWASP (SAMM)][5].

## Reconhecimento

Gostaríamos de agradecer às organizações que contribuíram com os seus dados de vulnerabilidades para suportar esta actualização de 2017. Recebemos mais de 40 respostas à nossa solicitação de dados. Pela primeira vez, todos os dados que contribuíram para este Top 10, e a lista completa de contribuidores, é tornada pública. Acreditamos que esta é uma das maiores e mais heterogéneas coleções de dados de vulnerabilidades alguma vez recolhida publicamente.

Uma vez que existem mais organizações do que espaço aqui, criamos uma página dedicada a reconhecer as contribuições que foram realizadas. Queremos agradecer fortemente a estas organizações por estarem na linha da frente ao partilharem publicamente estes dados de vulnerabilidades resultante dos seus esforços. Esperamos que esta tendência continue a crescer e encoraje mais organizações a fazerem o mesmo e possivelmente serem vistas como um dos principais marcos da segurança baseada em provas. O OWASP Top 10 não seria possível sem estas contribuições incríveis.

Um agradecimento especial aos 516 indivíduos que gastaram o seu tempo a completar o inquérito de indústria. A voz deles ajudou a determinar duas novas adições ao Top 10. Os comentários adicionais, as notas de encorajamento (i críticas) foram todos devidamente apreciados. Sabemos que o vosso tempo é valioso e por isso queremos agradecer-lhes.

Gostaríamos de agradecer antecipadamente a todos os indivíduos que contribuíram com comentários construtivos significativos e pelo tempo que gastaram na revisão desta actualização do Top 10. Tanto quanto possível, estão todos listados na página de agradecimentos '+Ack'.

Finalmente, gostaríamos de agradecer antecipadamente a todos os tradutores que irão traduzir esta actualização do Top 10 em múltiplas línguas, ajudando a tornar o OWASP Top 10 mais acessível a todo o planeta.

[1]:	https://www.owasp.org/index.php/OWASP_Guide_Project
[2]:	https://www.owasp.org/index.php/Category:Cheatsheets
[3]:	https://www.owasp.org/index.php/OWASP_Testing_Project
[4]:	https://www.owasp.org/index.php/ASVS
[5]:	https://www.owasp.org/index.php/OWASP_SAMM_Project