# A11:2021 – Étapes suivantes

De par sa conception, le Top 10 de l'OWASP est limité aux dix risques les plus importants. Dans chaque Top 10 de l'OWASP, des risques "au seuil" ont été longuement examinés en vue de leur inclusion, mais n'ont finalement pas été retenus. Quelle que soit la façon dont nous avons essayé d'interpréter ou de déformer les données, les autres risques étaient plus répandus et avaient plus d'impact.

Qu'il s'agisse d'organisations travaillant à la mise en place d'un programme de sécurité des applications mature, de consultants en sécurité ou de fournisseurs d'outils souhaitant étendre la couverture de leurs offres, les quatre problèmes suivants valent la peine d'être identifiés et corrigés.

## Problèmes de qualité du code

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       38       |       49,46 %        |         2,22 %         |              7,1              |         6,7          |    60,85 %     |      23,42 %       |        101&nbsp;736        |      7&nbsp;564      |

- **Description**. Les problèmes de qualité du code comprennent les défauts ou les schémas de sécurité connus, la réutilisation de variables à des fins multiples, l'exposition d'informations sensibles dans les résultats de débogage, les erreurs "off-by-one", les situations de concurrence "time of check/time of use" (TOCTOU), les erreurs de conversion non signées ou signées, l'utilisation après libération, etc. La caractéristique de cette section est qu'elles peuvent généralement être identifiées à l'aide d'options de compilateur, d'outils d'analyse de code statique et de plugins IDE de linter. Les langages modernes ont, de par leur conception, éliminé bon nombre de ces problèmes, comme le concept de propriété et d'emprunt de la mémoire de Rust, la conception du threading de Rust et le typage strict et la vérification des limites de Go.
- **Comment s'en prémunir**. Activez et utilisez les options d'analyse de code statique de votre éditeur et de votre langage. Envisagez d'utiliser un outil d'analyse statique du code. Envisagez la possibilité d'utiliser ou de migrer vers un langage ou un framework qui élimine des classes de bogues, comme Rust ou Go.
- **Exemple de scénarios d'attaque**. Un attaquant peut obtenir ou mettre à jour des informations sensibles en exploitant une situation de concurrence utilisant une variable statiquement partagée entre plusieurs threads.
- **Références**
    - [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)
    - [Google Code Review Guide](https://google.github.io/eng-practices/review/)


## Déni de service

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       8        |       17,54 %        |         4,89 %         |              8,3              |         5,9          |    79,58 %     |      33,26 %       |        66&nbsp;985         |         973          |

- **Description**. Le déni de service est toujours possible si les ressources sont suffisantes. Cependant, les pratiques de conception et de développement ont une incidence importante sur l'ampleur du déni de service. Supposons que toute personne disposant d'un lien puisse accéder à un fichier volumineux, ou qu'une transaction coûteuse en termes de calcul se produise sur chaque page. Dans ce cas, le déni de service nécessite moins d'efforts pour être mené.
- **Comment s'en prémunir**. Testez les performances du code en termes d'utilisation du processeur, des E/S et de la mémoire, ré-architecturez, optimisez ou mettez en cache les opérations coûteuses. Envisagez des contrôles d'accès pour les objets de grande taille afin de vous assurer que seules les personnes autorisées peuvent accéder aux fichiers ou objets volumineux ou les servir par un réseau de mise en cache en périphérie.
- **Exemple de scénarios d'attaque**. Un attaquant peut déterminer qu'une opération prend 5 à 10 secondes pour se terminer. Lorsqu'il exécute quatre threads simultanés, le serveur semble ne plus répondre. L'attaquant utilise 1000 threads et met l'ensemble du système hors ligne.
- **Références**
    - [OWASP Cheet Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
    - [OWASP Attacks: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## Memory Management Errors

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Avg Weighted Exploit  | Avg Weighted Impact  | Max Coverage  | Avg Coverage  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

-   **Description**. Web applications tend to be written in managed
    memory languages, such as Java, .NET, or node.js (JavaScript or
    TypeScript). However, these languages are written in systems
    languages that have memory management issues, such as buffer or heap
    overflows, use after free, integer overflows, and more. There have
    been many sandbox escapes over the years that prove that just
    because the web application language is nominally memory “safe,” the
    foundations are not.

-   **How to prevent**. Many modern APIs are now written in memory-safe
    languages such as Rust or Go. In the case of Rust, memory safety is
    a crucial feature of the language. For existing code, the use of
    strict compiler flags, strong typing, static code analysis, and fuzz
    testing can be beneficial in identifying memory leaks, memory, and
    array overruns, and more.

-   **Example attack scenarios**. Buffer and heap overflows have been a
    mainstay of attackers over the years. The attacker sends data to a program, which it stores in an undersized stack buffer. The result is that information on the call stack is overwritten, including the function’s return pointer. The data sets the value of the return pointer so that when the function returns, it transfers control to malicious code contained in the attacker’s data.

-   **References**
    - [OWASP Vulnerabilities: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
    
    - [OWASP Attacks: Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
    
    - [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)
