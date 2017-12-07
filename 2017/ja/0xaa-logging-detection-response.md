# A10:2017 ロギングと監視の不足

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| Access Lvl : 悪用難易度 2 | 流行度 3 : 検出難易度 1 | 技術的影響度 2 : ビジネスへの影響 |
|ほぼすべての重大なインシデントの背後にはロギングと監視の不足があります。監視及びタイムリーな対応の欠如を利用することで、攻撃者は攻撃を検出されることなく目標を達成します。|[業界調査](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html)に基づいてこの問題はトップ10に追加されました。十分な監視があるかどうかを判断するための方法の1つは、侵入テスト後のログを調べることです。 どのような損害を引き起すのかを理解するためにテスターの行動に対して十分なログが記録される必要があります。 | 成功した攻撃の多くは脆弱性の調査から始まります。 このような調査を続けることによって、脆弱性攻撃の成功率がほぼ100％になる可能性があります。2016年には侵害を特定するのに[平均191日](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&)という多くの時間がかかりました 。 |

## 脆弱性有無の確認

ロギングや検出、監視、アクティブな応答の不足は、いつでも発生します:

* ログイン、失敗したログイン、重要なトランザクションなどの監査可能なイベントがログに記録されていない。
* 警告とエラーが発生してもログメッセージが生成されない、または不十分、不明確なメッセージが生成されている。
* アプリケーションとAPIのログが、疑わしいアクティビティを監視していない。
* ログがローカルにのみ格納されている。
* アラートの適切なしきい値とレスポンスのエスカレーションプロセスが整えられていない、または有効ではない。
* [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)ツール（[OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)など）による侵入テストとスキャンがアラートをあげない。
* アプリケーションがリアルタイム、準リアルタイムにアクティブな攻撃を検出、エスカレート、またはアラートすることができない。

ユーザーまたは攻撃者がログやアラートのイベントを閲覧できると、情報の漏えいが発生する可能性があります（A3：2017 - 機密情報の公開を参照）。

## 防止方法

アプリケーションによって保存または処理されるデータのリスクに応じて：

* ログイン、アクセス制御の失敗、サーバー側の入力検証の失敗をユーザーコンテクストに応じて不審なアカウントや悪意のあるアカウントを識別するのに十分なだけ記録し、後日、フォレンジック分析を行うのに十分な時間分保持する。
* 集中ログ管理ソリューションで簡単に使用できる形式でログが生成されていることを確認する。
* 価値の高いトランザクションを守るために、(変更不可の）append-onlyデータベースのテーブルなどのような、改ざんや削除を防止する整合性制御による監査証跡が設けられていることを確認する。
* 疑わしい活動が適時に検出され、対応されるように、効果的な監視とアラートを確立する。
* [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)以降のような、インシデント対応および復旧計画を策定または採用する。

[OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project)、[OWASP ModSecurity Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project)を使用したModSecurityなどのWebアプリケーションファイアウォール、カスタムダッシュボードとアラートを使用したログ相関ソフトウェアなど、商用およびオープンソースのアプリケーション保護フレームワークがあります。

## 攻撃シナリオの例

**シナリオ #1**: 小さなチームが運営するオープンソースのプロジェクトフォーラムソフトウェアが、ソフトウェアの欠陥を突かれてハッキングされました。攻撃者は、次のバージョンとすべてのフォーラムの内容を含む内部のソースコードリポジトリを削除しました。ソースは回復することができましたが、監視、ロギング、アラートの不足によって問題が悪化してしまいました。この問題の発生により、フォーラムソフトウェアプロジェクトはアクティブではなくなってしまいました。

**シナリオ #2**: 同じパスワードを使用するユーザーに対して、攻撃者はスキャンを実施します。彼らは、このパスワードを使用しているすべてのアカウントを乗っ取ることができるようになります。他のユーザーに対しては、このスキャンは1回だけ失敗したログインとなります。数日後、スキャンは異なるパスワードで繰り返される場合があります。

**シナリオ #3**: 米国の大手小売業者が、添付ファイルを分析する内部マルウェア分析サンドボックスを持っていたと言われています。サンドボックスソフトウェアは、望ましくないと思われるソフトウェアを検出しましたが、誰もこの検出に応答しませんでした。サンドボックスは、外部銀行による不正なカード取引によって侵害が検出されるまでにしばらくの間警告を発していました。

## 参考資料

### OWASP

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet: Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### その他

* [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
