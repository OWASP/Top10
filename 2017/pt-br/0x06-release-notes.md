# RN Release Notes

## O que mudou de 2013 para 2017?

A mudança foi acelerada nos últimos quatro anos, e o OWASP Top 10 precisava mudar. Nós refatoramos completamente o OWASP Top 10,  renovamos a metodologia, utilizamos um novo processo de chamada de dados, trabalhamos com a comunidade, reordenamos nossos riscos, reescrevemos cada risco desde o início e adicionamos referências a frameworks e idiomas que agora são comumente usados. 

Ao longo dos últimos anos, a tecnologia e a arquitetura fundamentais das aplicações mudaram significativamente:

* Microsserviços escritos em node.js e Spring Boot estão substituindo aplicativos monolíticos tradicionais. Microsserviços vem com seus próprios desafios de segurança, incluindo o estabelecimento de confiança entre microservices, recipientes, gerenciamento de segredos, etc. Código legado que nunca deveria se comunicar diretamente com a Internet agora está atrás de uma serviço web ou API RESTful para ser consumido por SPAs e aplicativos móveis. Os pressupostos básicos do código, como os chamadores confiáveis, não são mais válidos.
* Aplicações de página única, escritas em frameworks JavaScript, como Angular e React, permitem a criação de front ends altamente modulares e ricas em recursos. A funcionalidade do lado do cliente que tradicionalmente foi entregue no lado do servidor traz seus próprios desafios de segurança.
* O JavaScript é agora o idioma principal da web com node.js executando o lado do servidor e estruturas modernas da Web, como Bootstrap, Electron, Angular e React fornecendo no cliente.

## Novos problemas, suportados por dados

* **A4:2017-XML External Entities (XXE)** é uma nova categoria primariamente suportado por dados gerados por ferramentas de análise de segurança de código fonte (source code analysis security testing tools [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)).

## Novos problemas, suportados pela comunidade

We asked the community to provide insight into two forward looking weakness categories. After over 500 peer submissions, and  removing issues that were already supported by data (such as Sensitive Data Exposure and XXE), the two new issues are 
Pedimos à comunidade que fornecesse informações sobre duas categorias de fraquezas futuras. Após mais de 500 envios e remoção de problemas que já eram suportados por dados (como Sensitive Data Exposure e XXE), os dois novos problemas são:

* **A8:2017-Desserialização Insegura**, que permite execução de código remoto ou manipulação de objetos sensíveis nas plataformas afetadas.
* **A10:2017-Insuficiência de Logs e Monitoração**, a falta destes pode impedir ou atrasar significativamente a deteção de atividades maliciosas e deteção de brechas, repostas de incidentes and digital forensics.

## Aposentados, mas não esquecidos

* **A4-Insecure Direct Object References** and **A7-Missing Function Level Access Control** merged into **A5:2017-Broken Access Control**.
* **A8-Cross-Site Request Forgery (CSRF)**, Frameworks commonly include CSRF defenses, with < 5% of all apps, now #13.
* **A10-Unvalidated Redirects and Forwards**, less than 1% of the data set supports this issue today, now #25

![0x06-release-notes-1](images/0x06-release-notes-1.png)
