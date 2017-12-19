# A10:2017-不十分なロギングとモニタリング

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| アクセスレベル : 悪用のしやすさ 2 | 蔓延度 3 : 検出のしやすさ 1 | 技術面への影響 2 : ビジネス面への影響 |
|不十分なロギングとモニタリングの悪用が、ほぼすべての重大なインシデントの背後にあります。モニタリングとタイムリーな対応の不備を突き、攻撃者は攻撃を検知されることなく目標を達成します。|[業界調査](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html)に基づいてこの問題はTop 10に追加されました。十分にモニタリングされているかどうかを判断するための方法の1つは、ペネトレーションテスト後のログを調べることです。どのような損害を引き起すのかを理解するために、テスターの行動に対して十分なログが記録される必要があります。 | 成功した攻撃の多くは脆弱性の下調べから始まります。このような下調べを見逃し続けることによって、脆弱性攻撃の成功率がほぼ100％になる可能性があります。2016年には侵害を特定するのに[平均191日](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&)という多くの時間がかかりました。 |

## 脆弱性発見のポイント

ロギングや検知、モニタリング、適時の対応が十分に行われないという状況は、いつでも発生します:

* ログイン、失敗したログイン、重要なトランザクションなどの監査可能なイベントがログに記録されていない。
* 警告とエラーが発生してもログメッセージが生成されない、または不十分、不明確なメッセージが生成されている。
* アプリケーションとAPIのログが、疑わしいアクティビティをモニタリングしていない。
* ログがローカルにのみ格納されている。
* アラートの適切なしきい値とレスポンスのエスカレーションプロセスが整えられていない、または有効ではない。
* ペネトレーションテストや[DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)ツール（[OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)など）によるスキャンがアラートをあげない。
* アプリケーションがリアルタイム、準リアルタイムにアクティブな攻撃を検知、エスカレート、またはアラートすることができない。

ユーザまたは攻撃者がログやアラートのイベントを閲覧できると、情報の漏えいが発生する可能性があります（A3：2017 - 機密情報の公開を参照）。

## 防止方法

アプリケーションによって保存または処理されるデータのリスクに応じて対応する：

* ログイン、アクセス制御の失敗、サーバーサイドの入力検証の失敗を全てログとして記録するようにする。ログは、不審なアカウントや悪意のあるアカウントを特定するために十分なユーザコンテキストを持ち、後日、フォレンジック分析を行うのに十分な期間分保持するようにする。
* 統合ログ管理ソリューションで簡単に使用できる形式でログが生成されていることを確認する。
* 価値の高いトランザクションにおいて、監査証跡が取得されていること。その際、追記型データベースのテーブルなどのような、完全性を保つコントロールを用いて、改ざんや削除を防止する。
* 疑わしい活動がタイムリーに検知されて対応されるように、効果的なモニタリングとアラートを確立する。
* [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)（またはそれ以降）のような、インシデント対応および復旧計画を策定または採用する。

[OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project)、[OWASP ModSecurity Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project)を使用したModSecurityなどのWebアプリケーションファイアウォール、カスタムダッシュボードとアラートを使用したログ相関分析ソフトウェアなど、商用およびオープンソースのアプリケーション保護フレームワークがあります。

## 攻撃シナリオの例

**シナリオ #1**: 小さなチームが運営するオープンソースのプロジェクトフォーラムソフトウェアが、ソフトウェアの欠陥を突かれてハッキングされました。攻撃者は次期バージョンと、すべてのフォーラムの内容を含む内部のソースコードリポジトリを削除しました。ソースコードは回復することができましたが、モニタリング、ロギング、アラートの欠如によって問題が悪化してしまいました。この問題の発生により、フォーラムソフトウェアプロジェクトは活発ではなくなりました。

**シナリオ #2**: 良くあるパスワードを使用するユーザに対して、攻撃者はスキャンを実施します。彼らは、このパスワードを使用しているすべてのアカウントを乗っ取ることができるようになります。他のユーザにとって、このスキャンは1回だけ失敗したログインとなります。また別の日に、スキャンは異なるパスワードで繰り返される場合があります。

**シナリオ #3**: 米国の大手小売業者が、添付ファイルを分析する内部マルウェア分析サンドボックスを持っていたとのことです。サンドボックスソフトウェアは、望ましくないと思われるソフトウェアを検知しましたが、誰もこの検知に対応しませんでした。サンドボックスは、外部の銀行による不正なカード取引によって侵害が検知されるまで、しばらくの間警告を発し続けていました。

## 参考資料

### OWASP

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet: Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### その他

* [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
