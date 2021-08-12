# A4:2017-XML 外部エンティティ参照 (XXE)

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| アクセスレベル : 悪用のしやすさ 2 | 蔓延度 2 : 検出のしやすさ 3 | 技術面への影響 3 : ビジネス面への影響 |
| 攻撃者は、脆弱なコード、依存関係、または統合を利用して、XML文書をアップロードしたり、悪意のあるコンテンツをXMLドキュメントに含めることができる場合、その脆弱なXMLプロセッサを悪用できます。 | 多くの古いXMLプロセッサにおいて、初期設定で、外部エンティティ（XML処理中に参照先のデータを取得し実行されるURI）を指定できます。 [SAST](https://owasp.org/www-community/Source_Code_Analysis_Tools) ツールで依存関係と構成を調べることでこの問題を発見できます。 [DAST](https://owasp.org/www-community/Vulnerability_Scanning_Tools) ツールでこの問題を検出しエクスプロイトを見つけるには手動による作業を加える必要があります。手動でテストをするなら、XXEのテスト方法を習得する必要があります。これは、2017年の時点では一般にテストされていないためです。 | これらの欠陥は、その他の攻撃と同様に、データの抽出、サーバからのリモート要求の実行、内部システムのスキャン、サービス不能攻撃の実行に使用できます。ビジネス面への影響の大きさは、この影響を受けるアプリケーションとデータを保護する必要がどれほどあるかにかかっています。 |

## 脆弱性発見のポイント

アプリケーション、特にXMLベースのWebサービスやダウンストリーム統合が下記の条件を満たす場合、脆弱である可能性があります:

* アプリケーションが、特に信頼できないソースからの直接またはアップロードによるXMLドキュメントを受け入れる。または、アプリケーションが信頼できないデータをXMLドキュメントに挿入し、XMLプロセッサによって解析される。
* アプリケーションまたはSOAPベースのWebサービスのXMLプロセッサにおいて、[ドキュメントタイプ定義（DTD）](https://en.wikipedia.org/wiki/Document_type_definition)が有効になっている。なお、DTD処理を無効にする実際のメカニズムはXMLプロセッサによって異なるため、[OWASP Cheat Sheet 'XXE Prevention'](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)などの資料を参考にすると良い。
* アプリケーションが統合されたセキュリティあるいはシングルサインオン（SSO）の目的でIDの処理にSAMLを使用する。SAMLはIDアサーションにXMLを使用しているため、脆弱である可能性がある。
* アプリケーションがバージョン1.2より前のSOAPを使用する。XMLエンティティがSOAPフレームワークに渡されていると、XXE攻撃の影響を受けやすくなる。
* XXE攻撃に対して脆弱であるということは、アプリケーションがBillion Laughs攻撃(XML爆弾を使う攻撃)のようなDoS攻撃に脆弱であるということと、ほぼ同義である。

## 防止方法

開発者のトレーニングは、XXEを特定し、軽減するために不可欠です。加えて、XXEを防ぐには以下のことが不可欠です:

* 可能な限り、JSONなどの複雑さの低いデータ形式を使用し、機微なデータのシリアライズを避ける。
* アプリケーションまたは基盤となるオペレーティングシステムで使用されているすべてのXMLプロセッサおよびライブラリにパッチをあてるか、アップグレードする。依存関係チェッカーを使用する。そして、SOAPはSOAP 1.2かそれ以降のものに更新する。
* [OWASP Cheat Sheet 'XXE Prevention'](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)に従い、アプリケーション内のすべてのXMLパーサーでXML外部エンティティとDTD処理を無効にする。
* ホワイトリスト方式によるサーバーサイドの入力検証や、XMLドキュメント、ヘッダ、ノード内の悪意のあるデータのフィルタリング、またはサニタイズを実装する。
* XMLまたはXSLファイルのアップロード機能において、XSD検証などを使用して受信するXMLを検証していることを確認する。
* SASTツールはソースコード内のXXEを検出するのに役立つが、多くのインテグレーションを伴う大規模で複雑なアプリケーションでは、手動によるコードレビューが最善の選択肢である。

もしこうしたコントロールができない場合には、仮想パッチ、APIセキュリティゲートウェイ、あるいはWebアプリケーションファイアウォール（WAF）を使用して、XXE攻撃を検出、監視、およびブロックすることを検討してください。

## 攻撃シナリオの例

多くの公開サーバでのXXE問題が発見されています。また、組み込み機器に対する攻撃も確認されています。XXEは、深くネストされた依存関係を含むさまざまな予期しない場所で発生します。最も簡単な攻撃方法は、サーバが受け入れる場合に、悪質なXMLファイルをアップロードすることです。

**シナリオ #1**: 攻撃者はサーバからデータを取り出そうと試みます:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**シナリオ #2**: 攻撃者は、上記のENTITY行を次のように変更して、サーバのプライベートネットワークを調べようとします:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**シナリオ #3**: 攻撃者は終わりのないファイルを含めることでDoS攻撃を試みます:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## 参考資料

### OWASP

* [OWASP Application Security Verification Standard](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
* [OWASP Testing Guide: Testing for XML Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)
* [OWASP XXE Vulnerability](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheat Sheet: XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: XML Security](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html)

### 外部資料

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
