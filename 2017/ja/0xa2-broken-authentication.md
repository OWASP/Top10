# A2:2017 認証の不備

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| アクセスレベル : 悪用難易度 3 | 流行度 2 : 検出難易度 2 | 技術的影響度 3 : ビジネスへの影響 |
| 攻撃者は、アカウントリスト攻撃（パスワードリスト攻撃）に使える数十億にのぼる有効なユーザ名とパスワードの組み合わせ、初期設定の管理者アカウントリスト、自動化された総当たり攻撃、辞書攻撃ツールを悪用してきます。そして、彼らはセッション管理における攻撃手法、特に有効期限が切れたセッショントークンに関連したものをよく理解しています。 | 一般的にユーザ認証とアクセス制御を設計・実装するため、認証の不備が広く流行しています。セッション管理はユーザ認証とアクセス制御の基盤であり、ステートフルなアプリケーションすべてがセッション管理を実装しています。攻撃者は手動で認証の不備を発見し、自動化ツールによるパスワードリスト攻撃や辞書攻撃を仕掛けて、それらを攻撃できます。 | 攻撃者は、システムを侵害するために、いくつかのアカウントまたはたった一つの管理者アカウントのアクセス権限を奪取すれば十分です。アプリケーション次第で、この攻撃はマネーロンダリング、社会的な不正行為、個人情報の侵害、法的に保護された重要な機密情報の漏えいにつながる恐れがあります。 |

## 脆弱性有無の確認

認証に関連した攻撃を防ぐためには、ユーザ認証、セッション管理の設計・実装を確認することが重要です。

アプリケーションが下記の条件を満たす場合、認証の設計・実装に問題があるかもしれません:

* 有効なユーザ名とパスワードのリストを持つ攻撃者による[アカウントリスト攻撃](https://www.owasp.org/index.php/Credential_stuffing)のような自動化された攻撃が成功する
* 総当たり攻撃や、その他の自動化された攻撃が成功する
* "Password1"や"admin/admin"のような初期設定と同じパスワード、強度の弱いパスワード、よく使われるパスワードを登録できる
* 安全に実装できない"秘密の質問"のように、脆弱または効果的でないパスワード復旧手順やパスワードリマインダを実装している
* 平文のパスワード、暗号化したパスワード、または脆弱なハッシュ関数でハッシュ化したパスワードを保存している(**A3:2017-機密データの露出**を参照)
* 多要素認証を実装していない、または効果的な多要素認証を実装していない
* URLからセッションIDが露見する(例: URLリライト)
* ログインに成功した後でセッションIDを変更しない
* 適切にセッションIDを無効にしない。ログアウトまたは一定時間操作がないとき、ユーザのセッションや認証トークン(特に、シングルサインオン(SSO)トークン)が適切に無効にならない

## 防止方法

* 自動化された攻撃、アカウントリスト攻撃、総当たり攻撃、盗まれたユーザ名/パスワードを再利用した攻撃を防ぐために、できる限り多要素認証を実装する
* 初期アカウント(特に管理者ユーザ)を残したまま出荷およびリリースしない
* 新しいパスワードまたは変更後のパスワードが[top 10000 worst passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)のリストにないか照合するようなパスワード検証を実装する
* [NIST 800-63 B's guidelines in section 5.1.1 for Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)やパスワードポリシーの基になるドキュメントにしたがい、パスワード長、パスワードの複雑性や定期変更までの期間を決める
* すべて同じメッセージを出力することで、ユーザ登録、パスワード復旧、API で存在するアカウントか判定できないようにする
* パスワード入力の失敗回数に制限を設ける、またはパスワード入力に失敗したらログインできるまでに待ち時間を設ける。アカウントリスト攻撃、総当たり攻撃、または他の攻撃を検知したとき、すべてのログイン失敗を記録し、アプリケーション管理者に通知する
* フレームワークなどが標準で提供するセッション管理機構をサーバサイドで採用して、ログイン後に高いエントロピーを持つランダムなセッションIDを生成する。セッションIDはURLを含めず、セキュアに保存し、ログアウト・一定時間操作がない・一定期間のタイムアウトした後に無効にすべきである

## 攻撃シナリオの例

シナリオ #1: [アカウントリスト攻撃](https://www.owasp.org/index.php/Credential_stuffing)や[lists of known passwords](https://github.com/danielmiessler/SecLists)を用いた攻撃は、広く知られた攻撃手法です。アプリケーションが自動化された攻撃やアカウントリスト攻撃に対策していない場合、そのアプリケーションがID/パスワードの組み合わせが正しいか検証するパスワードオラクルとして悪用されるかもしれません。

**シナリオ #2**: パスワードが認証の一要素として使われ続けていることから、ほとんどの認証に関連する攻撃が起こっています。ユーザが脆弱なパスワードを設定、または再利用しやすい状況にないか、かつてのベストプラクティス、パスワード変更および複雑性の要件をレビューしてください。組織には、NIST 800-63におけるプラクティスの実装をやめること、多要素認証を採用することを推奨します。

**シナリオ #3**: アプリケーションにセッションタイムアウトが適切に実装されていません。ユーザが公共の場のコンピュータでそのアプリケーションにアクセスします。そのユーザは、アプリケーションからログアウトする代わりに単純にブラウザでそのタブを閉じて、その場を立ち去ります。一時間後、攻撃者が同じコンピュータでブラウザを起動すると、まだそのユーザでログインしたままになっています。

## 参考資料

### OWASP

* [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls)
* [OWASP Application Security Verification Standard: V2 Authentication](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Application Security Verification Standard: V3 Session Management](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Identity](https://www.owasp.org/index.php/Testing_Identity_Management)
 と [Authentication](https://www.owasp.org/index.php/Testing_for_authentication)
* [OWASP Cheat Sheet: Authentication](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)
* [OWASP Cheat Sheet: Credential Stuffing](https://www.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Forgot Password](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [OWASP Cheat Sheet: Session Management](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)
* [OWASP Automated Threats Handbook](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### その他

* [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) - 緻密な調査に基づく最新の認証に関するアドバイス
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
