# A3:2017 機密データの露出

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点 | 影響 |
| -- | -- | -- |
| アクセスレベル : 悪用難易度 2 | 流行度 3 : 検出難易度 2 | 技術的影響度 3 : ビジネスへの影響 |
| 攻撃者は、ブラウザのようなクライアントからデータを送信するときに暗号化通信を直接攻撃するよりも、暗号鍵を盗み出したり、中間者攻撃を仕掛けたり、サーバ上にある平文のデータを盗み出します。一般的には、このリスクでは手動による攻撃を必要とします。あらかじめ盗み出したパスワードデータベースには、グラフィック処理ユニット(GPU)を使って総当たり攻撃できます。 | ここ数年以降、このリスクはもっとも一般的で影響力のある攻撃になりました。もっとも一般的な攻撃手法は、暗号化されていない機密データを狙ったものです。機密データが暗号化されているときには、弱い暗号鍵の生成と管理、弱い暗号アルゴリズム、プロトコル、暗号スイートの利用を狙った攻撃手法が知られています。特に、弱いハッシュ関数によるパスワードハッシュを狙った攻撃がよく知られています。サーバサイトでは、データ送信方法に問題があると容易に検知できますが、保存しているデータの問題があると検知することが非常に難しいです。 | 保護されるべきデータがすべて暴露されることはよくあります。多くの場合、これらのデータには医療記録、認証情報、個人データ、クレジットカードなどの機密データが含まれています。これらのデータには、EUにおけるGDPRや各地域のプライバシー関連の法律のように法律や規則で定められた保護が要求される場合が多いです。 |

## 脆弱性有無の確認

まず初めに、送信中のデータおよび保存しているデータに保護を必要とするか決めます。例えば、パスワード、クレジットカード番号、医療記録、個人データやビジネス上の機密データは特別に保護する必要があります。対象データがEUの一般データ保護規則(GDPR)などのプライバシー関連の法律の保護下にある場合や、PCIデータセキュリティスタンダード(PCI DSS)などの金融観点からのデータ保護が要求される場合、特に意識しなければなりません。これらのデータに対して、以下を確認してください。

* どんなデータであれ平文で送信していないか? これは、HTTP、SMTP、FTPのようなプロトコルを使っている場合に該当する。内部からインターネットに送信する場合、特に危険だ。また、ロードバランサ、ウェブサーバ、バックエンドシステムなどの内部通信もすべて確認すること
* バックアップも含め、機密データを平文で保存していないか?
* 古いまたは弱い暗号アルゴリズムを初期設定のまま、または古いコードで使っていないか?
* 初期値のままの暗号鍵の使用、弱い暗号鍵を生成または再利用、適切な暗号鍵管理、鍵のローテーションをしていない、これらの該当する箇所はないか?
* ユーザエージェント（ブラウザ）のセキュリティに関するディレクティブやヘッダーが欠落しているなど、暗号化が強制されていない箇所はないか？
* アプリ、メールクライアントなどのユーザエージェントが受信したサーバ証明書が正当なものか検証していない箇所はないか?

ASVS [Crypto (V7)](https://www.owasp.org/index.php/ASVS_V7_Cryptography)、[Data Protection (V9)](https://www.owasp.org/index.php/ASVS_V9_Data_Protection)、そして[SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS_V10_Communications)を参照してください。

## 防止方法

最低限、下記を実施してください。そして、参考資料を検討してください:

* アプリケーションごとに処理するデータ、保存するデータ、送信するデータを分類する。そして、どのデータがプライバシー関連の法律・規則の要件に該当するか、またどのデータがビジネス上必要なデータか判定する。
* 前述の分類にもとにアクセス制御を実装する。
* 必要ない機密データを保存しない。できる限りすぐにそのような機密データを破棄するか、PCI DSSに準拠したトークナイゼーションまたはトランケーションを行う。データが残っていなければ盗まれない。
* 保存時にすべての機密データを暗号化しているか確認する。
* 最新の暗号強度の高い標準アルゴリズム、プロトコル、暗号鍵を実装しているか確認する。そして適切に暗号鍵を管理する。
* 前方秘匿性(PFS)を有効にしたTLS、サーバサイドによる暗号スイートの優先度決定、セキュアパラメータなどのセキュアなプロトコルで、通信経路上のすべてのデータを暗号化する。HTTP Strict Transport Security (HSTS)のようなディレクティブで暗号化を強制する。
* [Argon2](https://www.cryptolux.org/index.php/Argon2)、[scrypt](https://wikipedia.org/wiki/Scrypt)、 [bcrypt](https://wikipedia.org/wiki/Bcrypt)、[PBKDF2](https://wikipedia.org/wiki/PBKDF2)のように、十分な暗号強度があり、work factor (delay factor)を使えるソルト化ハッシュ関数でパスワードを保存する。
* 設定とその設定値がそれぞれ独立して効果があるか検証する

## 攻撃シナリオの例

**シナリオ #1**: あるアプリケーションは、データベースの自動暗号化を使用し、クレジットカード番号を暗号化します。しかし、そのデータが取得されるときに自動的に復号されるため、SQLインジェクションによって平文のクレジットカード番号を取得できてしまいます。

**シナリオ #2**: あるサイトは、すべてのページでTLSで使っておらず、ユーザにTLSを強制していません。また、そのサイトでは弱い暗号アルゴリズムをサポートしています。攻撃者はネットワークトラフィックを監視し（例えば、暗号化していない無線ネットワークで）、HTTPS通信をHTTP通信にダウングレードしそのリクエストを盗聴することで、ユーザのセッションクッキーを盗みます。そして、攻撃者はこのクッキーを再送しユーザの(認証された)セッションを乗っ取り、そのユーザの個人データを閲覧および改ざんできます。また、攻撃者はセッションを乗っ取る代わりに、すべての送信データ（例えば、入金の受取人）を改ざんできます。

**シナリオ #3**: あるパスワードデータベースは、ソルトなしのハッシュまたは単純なハッシュでパスワードを保存しています。もし、ファイルアップロードの欠陥があれば、攻撃者はそれを悪用して、パスワードデータベースを取得できます。事前に計算されたハッシュのレインボーテーブルで、すべてのソルトなしのハッシュが解読されてしまいます。そして、たとえソルトありでハッシュ化されていても、単純または高速なハッシュ関数で生成したハッシュはGPUで解読されてしまうかもしれません。

## 参考資料

### OWASP

* [OWASP Proactive Controls: Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard]((https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)): [V7](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [9](https://www.owasp.org/index.php/ASVS_V9_Data_Protection), [10](https://www.owasp.org/index.php/ASVS_V10_Communications)
* [OWASP Cheat Sheet: Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: Password](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)と[Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project); [Cheat Sheet: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Testing Guide: Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### その他

* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-311: Missing Encryption](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html); [CWE-327: Broken/Risky Crypto](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
