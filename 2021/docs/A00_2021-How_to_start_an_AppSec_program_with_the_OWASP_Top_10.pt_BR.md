# Como iniciar um programa AppSec com o OWASP Top 10

Antes, o OWASP Top 10 nunca foi projetado para ser a base de um programa AppSec.
No entanto, é essencial começar de algum lugar para muitas organizações que
estão apenas começando em sua jornada de segurança de aplicações.
O OWASP Top 10 2021 é um bom começo como base para listas de verificação de segurança
e assim por diante, mas não é suficiente por si só.

## Etapa 1. Identifique as lacunas e os objetivos de seu programa appsec

Muitos programas de Aplicações de Segurança (AppSec) tentam correr antes 
que possam engatinhar ou andar. Esses esforços estão fadados ao fracasso. 
Incentivamos fortemente os CISOs e a liderança de AppSec a usar
o Modelo de Maturidade de Garantia de Software OWASP 
(Software Assurance Maturity Model - SAMM)\[<https://owaspsamm.org>\] para identificar 
pontos fracos e áreas de melhoria em um período de 1-3 anos. A primeira etapa
é avaliar onde você está agora, identificar as lacunas na governança,
design, implementação, verificação e operações que você precisa resolver
imediatamente em comparação com aquelas que podem esperar, e priorizar
a implementação ou melhoria das quinze práticas de segurança OWASP SAMM.
O OWASP SAMM pode ajudá-lo a construir e medir melhorias em seus
esforços de garantia de software.

## Etapa 2. Plano para um ciclo de vida de desenvolvimento de um Paved Road seguro

Tradicionalmente, a preservação dos chamados "unicórnios", o conceito de
paved road é a maneira mais fácil de causar o máximo impacto e
dimensionar os recursos do AppSec com a velocidade da equipe de desenvolvimento,
que só aumenta a cada ano.

O conceito de paved road é "o caminho mais fácil é também o mais seguro" e
deve envolver uma cultura de parcerias profundas entre a equipe de desenvolvimento
e a equipe de segurança, de preferência de forma que sejam uma só equipe.
O paved road visa melhorar, medir, detectar e substituir continuamente
alternativas inseguras por meio de uma biblioteca corporativa de reduções de
substituições seguras, com ferramentas para ajudar a ver onde melhorias podem ser
feitas ao adotar o paved road. Isso permite que as ferramentas
de desenvolvimento existentes relatem compilações inseguras e ajudem
as equipes de desenvolvimento a se autocorrigirem, evitando alternativas inseguras.

O paved road pode parecer muito a fazer, mas deve ser construída gradativamente ao
longo do tempo. Existem outras formas de programas appsec, notavelmente o 
_Microsoft Agile Secure Development Lifecycle_. Nem toda metodologia de programa
appsec se adapta a todas as empresas.

## Etapa 3. Implemente o Paved Road com suas equipes de desenvolvimento

Paved roads são construídos com o consentimento e envolvimento direto das equipes
de desenvolvimento e operações relevantes. O paved road deve estar estrategicamente
alinhado com os negócios e ajudar a entregar aplicativos mais seguros com mais rapidez.
O desenvolvimento do paved road deve ser um exercício holístico cobrindo toda a empresa
ou ecossistema de aplicativos, não um band-aid por aplicativo, como nos velhos tempos.

## Etapa 4. Migre todos os aplicativos futuros e existentes para o Paved Road

Adicione ferramentas de detecção de paved road conforme você as desenvolve e fornece
informações para equipes de desenvolvimento para melhorar a segurança de seus aplicativos
por meio de como eles podem adotar diretamente elementos do paved road. Uma vez que
um aspecto do paved road tenha sido adotado, as organizações devem implementar verificações
de integração contínua que inspecionam o código existente e check-ins que usam alternativas
proibidas e avisam ou rejeitam a compilação ou check-in. Isso evita que opções inseguras
entrem no código ao longo do tempo, evitando dívidas técnicas e um aplicativo inseguro
com defeito. Esses avisos devem ser vinculados à alternativa segura, para que a equipe
de desenvolvimento receba a resposta correta imediatamente. Eles podem refatorar
e adotar o componente do paved road rapidamente.

## Etapa 5. Teste se o Paved Road mitigou os problemas encontrados no OWASP Top 10

Os componentes do paved road devem abordar um problema significativo do OWASP Top 10,
por exemplo, como detectar ou consertar componentes vulneráveis automaticamente ou um plug-in IDE
de análise de código estático para detectar injeções ou, melhor ainda, uma biblioteca
que é sabidamente segura contra injeção, como React ou Vue. Quanto mais dessas substituições
seguras forem fornecidas às equipes, melhor. Uma tarefa vital da equipe do appsec é
garantir que a segurança desses componentes seja continuamente avaliada e aprimorada.
Depois de aprimoradas, alguma forma de via de comunicação com os consumidores do componente
deve indicar que uma atualização deve ocorrer, de preferência automaticamente,
mas se não, pelo menos destacada em um painel ou similar.

## Etapa 6. Construa o seu programa em um programa AppSec maduro

Você não deve parar no OWASP Top 10. Ele cobre apenas 10 categorias de riscos.
Recomendamos fortemente que as organizações adotem o Padrão de Verificação de Segurança
de Aplicativos (ASVS) e adicionem progressivamente componentes de paved road e testes para
os Níveis 1, 2 e 3, dependendo do nível de risco dos aplicativos desenvolvidos.

## Indo além

Todos os grandes programas AppSec vão além do mínimo. Todos devem continuar
se quisermos superar as vulnerabilidades do appsec.

- **Integridade conceitual**. Os programas AppSec maduros devem conter
    algum conceito de arquitetura de segurança, seja uma nuvem formal
    ou arquitetura de segurança corporativa ou modelagem de ameaças.

- **Automação e escala**. Programas maduros de AppSec tentam automatizar
    o máximo possível de seus resultados, usando scripts para emular
    etapas de teste de penetração complexas, ferramentas de análise
    de código estático disponíveis diretamente para as equipes de
    desenvolvimento, auxiliando as equipes de desenvolvimento na construção
    de unidades de appsec e testes de integração e muito mais.

- **Cultura**. Programas maduros de AppSec tentam construir o design
    inseguro e eliminar a dívida técnica do código existente, sendo
    parte da equipe de desenvolvimento e não à margem. As equipes da 
    AppSec que veem as equipes de desenvolvimento como "nós" e "eles"
    estão fadadas ao fracasso.

- **Melhoria continua**. Programas maduros de AppSec procuram melhorar
    constantemente. Se algo não estiver funcionando, pare de fazer isso.
    Se algo é desajeitado ou não escalável, trabalhe para melhorá-lo.
    Se algo não está sendo usado pelas equipes de desenvolvimento e não
    tem impacto ou tem impacto limitado, faça algo diferente. Só porque
    temos feito testes como _deskcheck_ desde os anos 1970, não significa
    que seja uma boa ideia. Meça, avalie e depois construa ou melhore.
