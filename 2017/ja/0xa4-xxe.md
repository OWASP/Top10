# A4:2017 XML 外部エンティティ参照 (XXE)

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| Access Lvl : 悪用難易度 2 | 流行度 2 : 検出難易度 3 | 技術的影響 3 : ビジネスへの影響 |
| 攻撃者は、脆弱なコード、依存関係、または統合を利用して、XMLをアップロードしたり、悪意のあるコンテンツをXML文書に含めることができる場合、その脆弱なXMLプロセッサを悪用することができます。 | 多くの古いXMLプロセッサにおいて、デフォルトでは、外部エンティティ（XML処理中に参照先のデータを取得しevalされるURI）の指定が可能です。 [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) ツールで依存関係と構成を調べることでこの問題を発見できます。 [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) ツールでこの問題を検出しエクスプロイトを見つけるには手作業を加える必要があります。マニュアルテストをするなら、XXEのテスト方法を習得する必要があります。これは、2017年の時点では一般にテストされていないためです。 | これらの欠陥は、データの抽出、サーバからのリモート要求の実行、内部システムのスキャン、サービス不能攻撃の実行、その他の攻撃の実行に使用できます。 |

## どんなアプリケーションが脆弱ですか？

アプリケーション、特にXMLベースのWebサービスやダウンストリーム統合では、次のような攻撃を受ける可能性があります:

* アプリケーションは、特に信頼できないソースからXMLを直接またはXMLアップロードを受け入れるか、信頼できないデータをXMLドキュメントに挿入し、XMLプロセッサによって解析されます。
* アプリケーションまたはSOAPベースのWebサービスのXMLプロセッサにおいて、[ドキュメントタイプ定義（DTD）]（https://en.wikipedia.org/wiki/Document_type_definition）が有効になっています。 DTD処理を無効にする実際のメカニズムはプロセッサによって異なるため、[OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)のようなリファレンスを調べると良いでしょう。 
* アプリケーションが統合されたセキュリティあるいはシングルサインオン（SSO）の目的でIDの処理にSAMLを使用する場合、SAMLはIDアサーションにXMLを使用しているため、脆弱である可能性があります。
* アプリケーションがバージョン1.2より前のSOAPを使用する場合、XMLエンティティがSOAPフレームワークに渡されていると、XXE攻撃の影響を受けやすくなります。
* XXE攻撃に対して脆弱であるということは、アプリケーションがDoS攻撃に脆弱である可能性が高いということになります。

## 防止方法

開発者のトレーニングは、XXEを特定し、軽減するために不可欠です。加えて、XXEを防ぐには以下のことが不可欠です:

* 可能な限り、JSONなどの複雑さの低いデータ形式を使用し、機密データのシリアライズを避けてください。
* アプリケーションまたは基盤となるオペレーティングシステムで使用されているすべてのXMLプロセッサおよびライブラリにパッチをあてるか、アップグレードします。依存関係チェッカーを使用してください。 SOAPは、SOAP 1.2かそれ以降のものに更新します。
* [OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)に従い、アプリケーション内のすべてのXMLパーサーでXML外部エンティティとDTD処理を無効にします。
* ホワイトリスト方式でサーバーサイドの入力検証や、XMLドキュメント、ヘッダ、ノード内の悪意のあるデータのフィルタリング、またはサニタイズを実装します。
* XMLまたはXSLファイルのアップロード機能において、XSD検証などを使用して受信するXMLを検証していることを確認します。
* SASTツールはソースコード内のXXEを検出するのに役立ちますが、多くのインテグレーションを伴う大規模で複雑なアプリケーションでは、手動によるコードレビューが最善の選択肢です。

もしこうしたコントロールができない場合には、仮想パッチ、APIセキュリティゲートウェイ、あるいはWebアプリケーションファイアウォール（WAF）を使用して、XXE攻撃を検出、監視、およびブロックすることを検討してください。

## 攻撃シナリオの例

多くの公開サーバでのXXE問題が発見されています。 XXEは、深くネストされた依存関係を含むさまざまな予期しない場所で発生します。最も簡単な攻撃方法は、サーバが受け入れる場合に、悪質なXMLファイルをアップロードすることです。

**シナリオ #1**: 攻撃者はサーバからデータを取り出そうと試みます:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**シナリオ #2**: 攻撃者は、上記のENTITY行を次のように変更して、サーバーのプライベートネットワークを調べようとします:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**シナリオ #3**: 攻撃者は終わりのないファイルを含めることでDoS攻撃を試みます:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## 参考資料

### OWASP

* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for XML Injection](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Vulnerability](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheat Sheet: XXE Prevention](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XML Security](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### 外部資料

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
