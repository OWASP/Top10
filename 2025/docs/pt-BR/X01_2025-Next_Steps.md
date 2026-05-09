# Próximos Passos

Por design, o OWASP Top 10 é inatamente limitado aos dez riscos mais significativos. Todo OWASP Top 10 possui riscos "no limiar" que são considerados extensivamente para inclusão, mas que, ao final, não entraram na lista. Os demais riscos eram mais prevalentes e impactantes.

Os três problemas a seguir valem bem o esforço de identificação e remediação para organizações que buscam um programa de AppSec maduro, consultorias de segurança ou fornecedores de ferramentas que desejam expandir a cobertura de suas ofertas.

---

## X01:2025 – Falta de Resiliência da Aplicação

### Contexto

Este é um renomeio do item Negação de Serviço (Denial of Service) de 2021. O nome foi alterado porque descrevia um sintoma em vez de uma causa raiz. Esta categoria foca em CWEs que descrevem fraquezas relacionadas a problemas de resiliência. A pontuação desta categoria foi muito próxima da [A10:2025-Tratamento Incorreto de Condições Excepcionais](A10_2025-Mishandling_of_Exceptional_Conditions.md). CWEs relevantes incluem: _CWE-400 Consumo Descontrolado de Recursos, CWE-409 Tratamento Incorreto de Dados Altamente Compactados (Amplificação de Dados), CWE-674 Recursão Descontrolada_ e _CWE-835 Loop com Condição de Saída Inalcançável ('Loop Infinito')._

### Tabela de Pontuação

[Mesmos valores da tabela original: 16 CWEs, Incidência Média 4,55%, Total de Ocorrências 865.066, etc.]

### Descrição

Esta categoria representa uma fraqueza sistêmica na forma como as aplicações respondem ao estresse, falhas e casos extremos, resultando na incapacidade de se recuperar de uma falha. Quando uma aplicação não lida adequadamente, não resiste ou não se recupera de condições inesperadas, restrições de recursos e outros eventos adversos, isso pode facilmente resultar em problemas de disponibilidade (mais comum), mas também em corrupção de dados, divulgação de dados sensíveis, falhas em cascata e/ou _bypass_ de controles de segurança.

Além disso, a categoria [X02:2025 Falhas de Gerenciamento de Memória](#x022025-falhas-de-gerenciamento-de-memória) também pode levar à falha da aplicação ou até de todo o sistema.

### Como Prevenir

Para prevenir este tipo de vulnerabilidade, você deve projetar seus sistemas prevendo falhas e recuperação.

- Adicione limites, cotas e funcionalidades de _failover_, dando atenção especial às operações que mais consomem recursos.
- Identifique páginas que demandam muitos recursos e planeje com antecedência: reduza a superfície de ataque, especialmente não expondo "gadgets" e funções desnecessárias que exijam muitos recursos (ex: CPU, memória) a usuários desconhecidos ou não confiáveis.
- Realize uma validação de entrada rigorosa com _allow-lists_ e limitações de tamanho, e então teste exaustivamente.
- Limite os tamanhos das respostas e nunca envie respostas brutas de volta ao cliente (processe no lado do servidor).
- Padrão para seguro/fechado (_fail closed_), negue por padrão e realize _rollback_ se houver um erro.
- Evite chamadas síncronas bloqueantes em threads de requisição (use assíncrono/não bloqueante, estabeleça _timeouts_, limites de concorrência, etc.).
- Teste cuidadosamente sua funcionalidade de tratamento de erros.
- Implemente padrões de resiliência como _circuit breakers_, _bulkheads_, lógica de retentativa (_retry_) e degradação suave (_graceful degradation_).
- Realize testes de desempenho e carga; adicione engenharia de caos (_chaos engineering_) se tiver apetite ao risco para isso.
- Implemente e projete arquiteturas visando redundância onde for razoável e financeiramente viável.
- Implemente monitoramento, observabilidade e alertas.
- Filtre endereços de remetentes inválidos de acordo com a RFC 2267.
- Bloqueie _botnets_ conhecidas por impressões digitais (_fingerprints_), IPs ou dinamicamente por comportamento.
- Prova de Trabalho (_Proof-of-Work_): inicie operações que consomem recursos no lado do _atacante_, o que não impacta grandes usuários normais, mas afeta bots que tentam enviar uma quantidade enorme de requisições.
- Limite o tempo de sessão no servidor baseado em inatividade e um _timeout_ final.

---

## X02:2025 – Falhas de Gerenciamento de Memória

### Contexto

Linguagens como Java, C#, JavaScript/TypeScript (node.js), Go e o Rust "seguro" são resilientes à memória (_memory safe_). Problemas de gerenciamento de memória tendem a ocorrer em linguagens que não possuem essa segurança, como C e C++. Esta categoria teve a pontuação mais baixa na pesquisa da comunidade e baixa nos dados, apesar de ter o terceiro maior número de CVEs relacionados. Acreditamos que isso se deva à predominância de aplicações web sobre as aplicações desktop tradicionais. Vulnerabilidades de gerenciamento de memória frequentemente possuem as pontuações CVSS mais altas.

### Descrição

Quando uma aplicação é forçada a gerenciar a memória por conta própria, é muito fácil cometer erros. Linguagens com gerenciamento seguro de memória são usadas cada vez mais, mas ainda existem muitos sistemas legados em produção, novos sistemas de baixo nível que exigem linguagens não seguras, e aplicações web que interagem com _mainframes_, dispositivos IoT, _firmware_ e outros sistemas. CWEs representativas são _CWE-120 Cópia de Buffer sem Verificação do Tamanho da Entrada ('Classic Buffer Overflow')_ e _CWE-121 Stack-based Buffer Overflow_.

As falhas de gerenciamento de memória podem ocorrer quando:

- Você não aloca memória suficiente para uma variável.
- Você não valida a entrada, causando um transbordamento (_overflow_) do _heap_, da _stack_ ou de um _buffer_.
- Você tenta acessar um objeto após ele ter sido liberado (_free_).
- Você vaza memória (_memory leak_) até que a aplicação falhe.

### Como Prevenir

A melhor maneira de prevenir falhas de gerenciamento de memória é usar uma linguagem com memória segura (_memory-safe_), como Rust, Java, Go, C#, Python, Swift, Kotlin ou JavaScript.

Se você não puder usar uma linguagem segura:

- Ative recursos do servidor que dificultam a exploração: ASLR, DEP e SEHOP.
- Monitore a aplicação em busca de vazamentos de memória (_memory leaks_).
- Valide cuidadosamente todas as entradas do sistema.
- Prefira funções mais seguras (ex: em C, prefira `strncpy()` em vez de `strcpy()`).
- Fixe todos os erros _e_ avisos (_warnings_) do compilador. Não ignore avisos apenas porque o programa compilou.

---

## X03:2025 – Confiança Inapropriada em Código Gerado por IA ('Vibe Coding')

### Contexto

Atualmente, o mundo inteiro fala sobre e utiliza IA, incluindo desenvolvedores de software. Embora ainda não existam CVEs ou CWEs específicas para código gerado por IA, é bem documentado que esse código frequentemente contém mais vulnerabilidades do que o código escrito por seres humanos.

### Descrição

Estamos vendo as práticas de desenvolvimento mudarem para incluir não apenas código escrito com auxílio de IA, mas código escrito e enviado (_committed_) quase inteiramente sem supervisão humana (frequentemente chamado de _vibe coding_). Assim como nunca foi uma boa ideia copiar trechos de código de blogs sem refletir, o problema é agravado neste caso. Trechos de código bons e seguros são raros e podem ser estatisticamente negligenciados pela IA devido a restrições do sistema.

### Como Prevenir

Urgimos que todas as pessoas que escrevem código considerem o seguinte ao usar IA:

- Você deve ser capaz de ler e entender totalmente todo o código que envia, mesmo que tenha sido escrito por uma IA. **Você é responsável por todo código que comita.**
- Revise minuciosamente todo código assistido por IA em busca de vulnerabilidades, idealmente com seus próprios olhos e com ferramentas de segurança (como análise estática).
- Considere utilizar um servidor de Geração Aumentada por Recuperação (RAG) com seus próprios exemplos de código seguro revisados e documentação interna.
- Implemente políticas e processos como parte do seu SDLC para informar aos desenvolvedores como devem ou não usar IA na organização.
- **Não é recomendado** usar _vibe coding_ para funções complexas, programas críticos de negócio ou sistemas que serão utilizados por muito tempo.
- Treine seus desenvolvedores sobre suas políticas e as melhores práticas para o uso seguro de IA no desenvolvimento de software.
