# RN Notas da versão

## O que mudou de 2013 para 2017?

A mudança foi acelerada nos últimos quatro anos, e o OWASP Top 10 precisava mudar. Nós refatoramos completamente o OWASP Top 10,  renovamos a metodologia, utilizamos um novo processo de chamada de dados, trabalhamos com a comunidade, reordenamos nossos riscos, reescrevemos cada risco desde o início e adicionamos referências a frameworks e idiomas que agora são comumente usados. 

Ao longo dos últimos anos, a tecnologia e arquitetura fundamental das aplicações mudaram significativamente:

* Microsserviços desenvolvidos em node.js e Spring Boot estão substituindo aplicativos monolíticos tradicionais. Microsserviços vem com seus próprios desafios de segurança, incluindo: o estabelecimento de confiança entre eles, containers, gerenciamento de segredos, entre outros.
Código legado que nunca deveria se comunicar diretamente com a Internet agora está exposto através de uma API ou serviço web RESTful para ser consumido por aplicações de página única (SPAs) e aplicativos móveis. Os pressupostos básicos do código, como os chamadores confiáveis, não são mais válidos.
* Aplicações de página única, escritas em frameworks JavaScript, como Angular e React, permitem a criação de front ends altamente modulares e ricos em recursos. A funcionalidade do lado do cliente que tradicionalmente foi entregue no lado do servidor traz seus próprios desafios de segurança.
* O JavaScript agora é a principal linguagem da web com node.js executando no lado do servidor e frameworks web modernos como Bootstrap, Electron, Angular e React no cliente.

## Novos problemas, suportados por dados

* **A4:2017-XML External Entities (XXE)** é uma nova categoria primariamente suportado por dados gerados por ferramentas de análise de segurança de código fonte (source code analysis security testing tools [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)).

## Novos problemas, suportados pela comunidade

Pedimos à comunidade que fornecesse informações sobre duas categorias de fraquezas futuras. Após mais de 500 envios e remoção de problemas que já eram suportados por dados (como Sensitive Data Exposure e XXE), os dois novos problemas são:

* **A8:2017-Desserialização Insegura**, que permite execução de código remoto ou manipulação de objetos sensíveis nas plataformas afetadas.
* **A10:2017-Insuficiência de Logs e Monitoração**, a falta destes pode impedir ou atrasar significativamente a detecção de atividades maliciosas e brechas, respostas de incidentes e forense digital.

## Aposentados, mas não esquecidos

* **A4-Referências Insegura e Direta a Objetos** e **A7-Falta de Função para Controle do Nível de Acesso** foram unidos em **A5:2017-Quebra de Controle de Acesso**.
* **A8-Cross-Site Request Forgery (CSRF)**, Frameworks comumente já incluem defesas contra CSRF defenses, com < 5% de todas as aplicações, agora #13.
* **A10-Unvalidated Redirects and Forwards**, menos de 1% do conjunto de dados reportam este problema hoje, agora #25

![0x06-release-notes-1](images/0x06-release-notes-1.png)
