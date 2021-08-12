# I Introdução

## Seja bem vindo ao OWASP Top 10 - 2017

Esta nova atualização introduz um conjunto de novos problemas, dois dos quais
selecionados pela comunidade - [A8:2017 - Desserialização Insegura][0x051] e
[A10:2017 - Registo e Monitorização Insuficiente][0x052]. Dois aspetos
diferenciadores em relação às versões anteriores do OWASP Top 10 são o
contributo substancial da comunidade e a maior coleção de dados alguma vez
recolhida na preparação de um standard de segurança aplicacional. Isto deixa-nos
confiantes que o novo OWASP Top 10 cobre os problemas de segurança aplicacional
com maior impacto que as organizações enfrentam.

O OWASP Top 10 de 2017 é baseado, essencialmente, em mais de 40 submissões de
dados de empresas especializadas na área da segurança aplicacional e num
inquérito realizado a profissionais individuais do sector, o qual obteve 515
respostas. Estes dados refletem as vulnerabilidades identificadas em centenas de
organizações e mais de 100.000 aplicações e APIs reais. Os tópicos do Top 10 são
selecionados e ordenados de acordo com a sua prevalência, combinada com uma
estimativa ponderada do potencial de abuso, deteção e impacto.

O principal objetivo do OWASP Top 10 é o de educar programadores, desenhadores e
arquitetos de aplicações, bem como gestores e as próprias organizações sobre as
consequências dos problemas de segurança mais comuns e mais importantes no
contexto das aplicações web. O Top 10 oferece não só técnicas básicas para
proteção nestas áreas problemáticas e de elevado risco, mas também direções
sobre onde encontrar informação adicional sobre estes assuntos.

## Planeamento Atividades Futuras

**Não pare no 10**. Existem centenas de problemas que podem afectar a segurança
geral de uma aplicação web tal como discutido no [Guia de Programadores da
OWASP][0x053] e nas [Séries de Cheat Sheets da OWASP][0x054]. Isto é leitura
essencial para alguém que esteja a desenvolver aplicações web e APIs.
Orientações sobre como encontrar efetivamente vulnerabilidades em aplicações web
e APIs são fornecidas no [OWASP Testing Guide][0x055].

**Mudança constante**. O OWASP Top 10 vai continuar a mudar. Mesmo sem mudar uma
única linha no código da sua aplicação, pode ficar vulnerável à medida que novas
falhas são descobertas e métodos de ataque são refinados. Por favor, reveja os
conselhos no final do Top 10 nas secções Próximos Passos Para
[Programadores][0x056], [Profissionais de Testes][0x057] e [Organizações][0x058]
para mais informação.

**Pense positivo**. Quando estiver pronto para parar de perseguir
vulnerabilidades e focar-se na definição de controlos fortes de segurança
aplicacional, lembre-se que a OWASP mantém e promove o [Standard de
Verificação][0x059] de [Segurança Aplicacional (ASVS)][0x0510] como guia de
aspetos a verificar, tanto para as organizações como para os revisores de
aplicações.

**Use as ferramentas de forma inteligente**. As vulnerabilidades de segurança
podem ser bastante complexas e escondidas no meio do código. Em muitos casos a
abordagem mais eficiente para encontrar e eliminar estas falhas consiste na
utilização de especialistas humanos munidos de boas ferramentas.

**Dispare em todas as direções**. Foque-se em tornar a  segurança parte
integrante da cultura da sua organização, em particular no departamento de
desenvolvimento. Pode encontrar mais informação em [Modelo de Garantia da
Maturidade do Software da OWASP (SAMM)][0x0511]

## Reconhecimento

Gostaríamos de agradecer às organizações que contribuíram com os seus dados
sobre vulnerabilidades para suportar esta actualização de 2017. Recebemos mais
de 40 respostas à nossa solicitação de dados. Pela primeira vez todos os dados
bem como a lista completa de contribuidores, foi tornada pública. Acreditamos
que esta é uma das maiores e mais heterogéneas coleções de dados sobre
vulnerabilidades alguma vez recolhida publicamente.

Uma vez que existem mais organizações do que espaço aqui disponível, criámos uma
[página dedicada][0x0512] a reconhecer as contribuições realizadas. Queremos
agradecer sinceramente a estas organizações por quererem estar na linha da
frente ao partilhar publicamente os dados sobre vulnerabilidades resultante dos
seus esforços. Esperamos que esta tendência continue a crescer e encoraje mais
organizações a fazerem o mesmo e possivelmente serem vistas como um dos
principais marcos da segurança baseada em evidências. O OWASP Top 10 não seria
possível sem estas contribuições incríveis.

Um agradecimento especial aos mais de 500 indivíduos que gastaram o seu tempo a
preencher o questionário. A voz deles ajudou a definir duas novas entradas no
Top 10. Os comentários adicionais, as notas de encorajamento (e críticas) foram
todos devidamente apreciados. Sabemos que o vosso tempo é valioso e por isso
queremos dizer Obrigado.

Gostaríamos de agradecer antecipadamente a todos os indivíduos que contribuíram
com os seus comentários construtivos e relevantes, e pelo tempo que gastaram na
revisão desta atualização do Top 10. Tanto quanto possível, estão todos listados
na página de “[Agradecimentos][0x0512]”.

Finalmente, gostaríamos de agradecer antecipadamente a todos os tradutores que
irão traduzir esta atualização do Top 10 em múltiplas línguas, ajudando a tornar
o OWASP Top 10 mais acessível a todo o planeta.

[0x051]: ./0xa8-insecure-deserialization.md
[0x052]: ./0xaa-logging-detection-response.md
[0x053]: https://github.com/OWASP/DevGuide
[0x054]: https://cheatsheetseries.owasp.org/
[0x055]: https://owasp.org/www-project-web-security-testing-guide/
[0x056]: ./0xb0-next-devs.md
[0x057]: ./0xb1-next-testing.md
[0x058]: ./0xb2-next-org.md
[0x059]: https://owasp.org/www-project-application-security-verification-standard/
[0x0510]: https://owasp.org/www-project-application-security-verification-standard/
[0x0511]: https://owasp.org/www-project-samm/
[0x0512]: ./0xd1-data-contributors.md

