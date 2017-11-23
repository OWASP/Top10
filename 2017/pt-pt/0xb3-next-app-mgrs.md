# +A: O que se segue para os Gestores de Aplicações

## Gerir o Ciclo de Vida das Aplicações

As aplicações são alguns dos sistemas mais complexos que os humanos criam e mantêm regularmente. A gestão de TI para uma aplicação deve ser realizada por especialistas de TI que são responsáveis pelo ciclo de vida global de TI de uma aplicação.

Sugerimos que se definam donos e gestores de aplicações para cada aplicação para oferecer responsabilização, prestação de contas, de forma consultada e informada (RACI), para permitir que a organização possa descartar riscos, identificar quem é responsável pelo desenho de segurança, construção, teste e instalação da aplicação.

## Requisitos e Gestão de Recursos

* Colecionar e negociar os requisitos de negócio de uma aplicação com o negócio, incluindo receber requisitos de proteção relativos a confidencialidade, integridade e disponibilidade de todos os activos de dados.
* Compilar os requisitos técnicos incluindo os requisitos funcionais e não funcionais de segurança.
* Planear e negociar o orçamento que cobre todos os aspectos do desenho, construção e operação, incluindo actividades de segurança.

## Solicitação de Propostas (RFP) e Contratação

* Negociar os requisitos com os programadores internos e externos, incluindo guias e requisitos de segurança respeitantes ao seu programa de segurança, por exemplo, SDLC e melhores práticas.
* Classificar o cumprimento de todos os requisitos técnicos incluindo um planeamento básico e uma fase de desenho.
* Negociar todos os requisitos técnicos incluindo o desenho, segurança e acordos de nível de serviço (SLA).
* Adoptar templates listas de validação, tais como [Anexo de Contrato para Software Seguro da OWASP][1].

**NB: Por favor note que o Anexo é um exemplo específico para a lei de contratação nos EUA, e provavelmente necessita de ser adaptada à realidade jurídica de outros países. Por favor, consulte um aconselhamento legal antes de usar o Anexo.**

## Planear e Desenhar

Para assegurar que as aplicações têm um desenho seguro, o seguinte deve ser realizado:
* Negociar o planeamento e desenhar com os programadores e com os grupos internos interessados, por exemplo, os especialistas de segurança.
* Definir uma arquitectura de segurança, controlos e contramedidas de acordo com as proteções requeridas e o ambiente de segurança planeado. Isto deve ser suportado pelos especialistas de segurança.
* Garantir que o dono da aplicação assume os riscos remanescentes ou que proporcione os recursos adicionais.
* Para cada sprint de desenvolvimento, assegurar que as histórias de segurança são criadas para os requisitos funcionais, e que restrições são adicionais para os requisitos não-funcionais.

## Instalação, Teste e Lançamento

Para garantir operações e alterações seguras, deve ser realizado o seguinte:
* Automatizar a configuração segura da aplicação, dos interfaces e de todos os componentes necessários, incluindo autorizações.
* Testar as funções técnicas e integração com a arquitectura de TI e coordenar os testes de negócio.
* Criar casos de teste de “uso” e de “abuso” com perspectivas técnicas e de negócio.
* Gerir testes de segurança de acordo com os processos internos, as necessidades de proteção e o nível de segurança requerido pela aplicação.
* Colocar a aplicação em operação e migrar de aplicações usadas anteriormente se necessário.
Finalizar toda a documentação, incluindo o CMDB e a arquitectura de segurança.

## Operação e Alterações

Para assegurar as operações e alterações seguras, deve ser realizado o seguinte:
* Operar incluindo a gestão de segurança para a aplicação (por exemplo, a gestão de correções).
* Aumentar a consciencialização de segurança dos utilizadores e gerir conflitos da dicotomia entre usabilidade e segurança.
* Planear e gerir alterações, por exemplo, migrar para novas versões da aplicação ou outros componentes como o SO, middleware ou bibliotecas.
* Actualizar toda a documentação, incluindo o CMDB e a arquitectura de segurança, controlos e contramedidas, incluindo quaisquer cadernos ou documentação de projecto.

## Retirada de Sistemas

O processo de retirada do sistemas é muitas vezes ignorado. Deve assegurar que:
* Quaisquer dados importantes são arquivados. Todos os outros dados são apagados em segurança.
* Encerrar em segurança a aplicação, incluindo apagar contas, papéis e permissões não usadas.
* Actualizar o estado da aplicação para retirada na CMDB.

[1]:	https://www.owasp.org/index.php/OWASP_Secure_Software_Contract_Annex