# A3:2017-機微な情報の露出

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点 | 影響 |
| -- | -- | -- |
| アクセスレベル : 悪用のしやすさ 2 | 蔓延度 3 : 検出のしやすさ 2 | 技術面への影響 3 : ビジネス面への影響 |
| 攻撃者は、ブラウザのようなクライアントからデータを送信するときに暗号化通信を直接攻撃するよりも、暗号鍵を盗み出したり、中間者攻撃を仕掛けたり、サーバ上にある平文のデータを盗み出します。一般的には、このリスクでは手動による攻撃を必要とします。あらかじめ盗み出したパスワードデータベースには、グラフィック処理ユニット(GPU)を使って総当たり攻撃できます。 | ここ数年以降、このリスクはもっとも一般的で影響力のある攻撃になりました。もっとも一般的な攻撃手法は、暗号化されていない機微な情報を狙ったものです。暗号化されている場合でも、弱い暗号鍵の生成と管理、弱い暗号アルゴリズム、プロトコル、暗号スイートの利用を狙った攻撃手法が知られています。特に、弱いハッシュ関数によるパスワードハッシュを狙った攻撃がよく知られています。データを送信する場合には、サーバサイドの弱点を容易に検知できますが、サーバ内に保存したデータの問題の検知は困難です。| 保護に失敗し保護すべきすべての情報が台無しになることは頻繁に生じています。多くの場合、これらの情報には健康記録、認証情報、個人情報、クレジットカードなどの機微な情報(PII)が含まれています。これらのデータについてはしばしば、EUにおけるGDPRや各地域のプライバシー関連の法律など、法律や規則で定められた保護が要求されます。 |

## 脆弱性発見のポイント

まず、送信あるいは保存するデータが保護を必要とするか見極めます。例えば、パスワード、クレジットカード番号、健康記録、個人データやビジネス上の機密は特に保護する必要があります。データに対して、EUの一般データ保護規則(GDPR)のようなプライバシー関連の法律が適用される場合、また、PCIデータセキュリティスタンダード(PCI DSS)など金融の情報保護の要求があるような規定がある場合には、特に注意が必要です。そのようなデータすべてについて、以下を確認してください:

- どんなデータであれ平文で送信していないか。これは、HTTP、SMTP、FTPのようなプロトコルを使っている場合に該当する。内部からインターネットに送信する場合、特に危険である。また、ロードバランサ、ウェブサーバ、バックエンドシステムなどの内部の通信もすべて確認する。
- バックアップも含め、機密データを平文で保存していないか。
- 古いまたは弱い暗号アルゴリズムを初期設定のまま、または古いコードで使っていないか。
- 初期値のままの暗号鍵の使用、弱い暗号鍵を生成または再利用、適切な暗号鍵管理または鍵のローテーションをしていない、これらの該当する箇所はないか。
- ユーザエージェント（ブラウザ）のセキュリティに関するディレクティブやヘッダーが欠落しているなど、暗号化が強制されていない箇所はないか。
- アプリ、メールクライアントなどのユーザエージェントが受信したサーバ証明書が正当なものか検証していない箇所はないか。

ASVS [Crypto (V6)](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x14-V6-Cryptography.md)、[Data Protection (V8)](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x16-V8-Data-Protection.md)、そして[SSL/TLS (V9)](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x17-V9-Communications.md)を参照。

## 防止方法

最低限実施すべきことを以下に挙げます。そして、参考資料を検討してください:

- アプリケーションごとに処理するデータ、保存するデータ、送信するデータを分類する。そして、どのデータがプライバシー関連の法律・規則の要件に該当するか、またどのデータがビジネス上必要なデータか判定する。
- 前述の分類をもとにアクセス制御を実装する。
- 必要のない機微な情報を保存しない。できる限りすぐにそのような機微な情報を破棄するか、PCI DSSに準拠したトークナイゼーションまたはトランケーションを行う。データが残っていなければ盗まれない。
- 保存時にすべての機微な情報を暗号化しているか確認する。
- 最新の暗号強度の高い標準アルゴリズム、プロトコル、暗号鍵を実装しているか確認する。そして適切に暗号鍵を管理する。
- 前方秘匿性(PFS)を有効にしたTLS、サーバサイドによる暗号スイートの優先度決定、セキュアパラメータなどのセキュアなプロトコルで、通信経路上のすべてのデータを暗号化する。HTTP Strict Transport Security ([HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html))のようなディレクティブで暗号化を強制する。
- パスワードを保存する際、[Argon2](https://github.com/p-h-c/phc-winner-argon2)、[scrypt](https://wikipedia.org/wiki/Scrypt)、 [bcrypt](https://wikipedia.org/wiki/Bcrypt)、[PBKDF2](https://wikipedia.org/wiki/PBKDF2)のようなワークファクタ(遅延ファクタ)のある、強くかつ適応可能なレベルのソルト付きハッシュ関数を用いる。
- 設定とその設定値がそれぞれ独立して効果があるか検証する。

## 攻撃シナリオの例

**シナリオ #1**: あるアプリケーションは、データベースの自動暗号化を使用し、クレジットカード番号を暗号化します。しかし、そのデータが取得されるときに自動的に復号されるため、SQLインジェクションによって平文のクレジットカード番号を取得できてしまいます。

**シナリオ #2**: あるサイトは、すべてのページでTLSを使っておらず、ユーザにTLSを強制していません。また、そのサイトでは弱い暗号アルゴリズムをサポートしています。攻撃者はネットワークトラフィックを監視し（例えば、暗号化していない無線ネットワークで）、HTTPS通信をHTTP通信にダウングレードしそのリクエストを盗聴することで、ユーザのセッションクッキーを盗みます。そして、攻撃者はこのクッキーを再送しユーザの(認証された)セッションを乗っ取り、そのユーザの個人データを閲覧および改ざんできます。また、攻撃者はセッションを乗っ取る代わりに、すべての送信データ（例えば、入金の受取人）を改ざんできます。

**シナリオ #3**: あるパスワードデータベースは、ソルトなしのハッシュまたは単純なハッシュでパスワードを保存しています。もし、ファイルアップロードの欠陥があれば、攻撃者はそれを悪用して、パスワードデータベースを取得できます。事前に計算されたハッシュのレインボーテーブルで、すべてのソルトなしのハッシュが解読されてしまいます。そして、たとえソルトありでハッシュ化されていても、単純または高速なハッシュ関数で生成したハッシュはGPUで解読されてしまうかもしれません。

## 参考資料

### OWASP

- [OWASP Proactive Controls: Protect Data](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/): [V6](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x14-V6-Cryptography.md), [9](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x16-V8-Data-Protection.md), [10](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x17-V9-Communications.md)
- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Password](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)と[Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Security Headers Project](https://owasp.org/www-project-secure-headers/); [Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)

### 外部資料

- [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
- [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-311: Missing Encryption](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html); [CWE-327: Broken/Risky Crypto](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
