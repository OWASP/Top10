# +RF リスクファクターに関する詳細

## Top 10 リスクファクターのまとめ

下の表は、2017 Top 10アプリケーションのセキュリティリスクと各リスクに紐付けたリスクファクターのまとめです。これらのファクターは、OWASP Top 10チームが持つ統計資料と経験に基づき決定しました。それぞれのアプリケーションや組織におけるリスクを理解するために、「脅威エージェント」と「ビジネス面への影響」を考慮しないといけません。ソフトウェアに甚大な弱点があったとしても、攻撃をする「脅威エージェント」がいない、或いは関連資産への「ビジネス面への影響」が極めて少ない場合、重大なリスクにはなりません。

![Risk Factor Table](images/0xc1-risk-factor-table.png)

## その他の考慮すべきリスク

Top 10は、幅広く含めていますが、考慮・評価すべきリスクは、他に多数あります。以前のTop 10に含まれていたリスクもありますが、まだ識別されていない新たな攻撃手法もあります。他に考慮すべき重要なアプリケーションのセキュリティリスクを以下に示します（CWE-ID順）：

- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion', 'AppDoS')](https://cwe.mitre.org/data/definitions/400.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-451: User Interface (UI) Misrepresentation of Critical Information (Clickjacking and others)](https://cwe.mitre.org/data/definitions/451.html)
- [CWE-601: Unvalidated Forward and Redirects](https://cwe.mitre.org/data/definitions/601.html)
- [CWE-799: Improper Control of Interaction Frequency (Anti-Automation)](https://cwe.mitre.org/data/definitions/799.html)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere (3rd Party Content)](https://cwe.mitre.org/data/definitions/829.html)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
