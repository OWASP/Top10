# A8:2017-安全でないデシリアライゼーション

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| アクセスレベル : 悪用のしやすさ 1 | 蔓延度 2 : 攻撃検知のしやすさ 2 | 技術面への影響 3 : ビジネス面への影響 |
| 既成のエクスプロイト手法は、元のエクスプロイトコードに変更や調整を加えずに攻撃が成功するケースはまれです。そのためデシリアライゼーションの悪用は、容易ではありません。 | この問題は、OWASPが行った[業界調査](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html)に基づきTop10に組み込まれましたが、定量的なデータに基づいたものではありません。 ツールによっては、デシリアライゼーションに関する欠陥を発見可能ですが、問題を検証するために、多くの場合、人手による支援が必要です。 問題の特定と対応を支援する道具立てが開発されるに伴い、デシリアライゼーションに関する欠陥が蔓延するであろうことが予想されます。 | デシリアライゼーションの欠陥による影響は、憂慮すべきものです。 これらの欠陥は、最も深刻な攻撃の一つであるリモートコード実行攻撃を可能にします。 ビジネス面への影響は、アプリケーションとデータを保護する重要性に依存します。 |

## 脆弱性有無の確認

攻撃者により供給された悪意を持った、あるいは改ざんされたオブジェクトのデシリアライズにより、アプリケーションとAPIは脆弱になります。

主な2種類の攻撃:

* オブジェクトとデータ構造に関連した攻撃：デシリアライズ中またはデシリアライズ後に、振る舞いを変更できるクラスがアプリケーションで使用可能な場合、攻撃者は、アプリケーションロジックの変更または、任意のリモートコード実行を行える攻撃である。
* 典型的なデータ改ざん攻撃：既存のデータ構造が内容を変えられて使われるようなアクセス制御関連の攻撃である。

シリアライゼーションが、以下のような用途にアプリケーションで使用される場合：

* リモート間またはローカル内でのプロセス間通信（RPCやIPC）
* ワイヤプロトコル、Webサービス、メッセージブローカー
* キャッシュ/永続化
* データベース、キャッシュサーバー、ファイルシステム
* HTTPクッキー、HTMLフォームのパラメータ、API認証トークン

## 防止方法

安全なアーキテクチャを実現するには、シリアライズされたオブジェクトを信頼できないデータ供給元から受け入れないか、もしくはシリアライズ対象のデータをプリミティブなデータ型のみにします。

上記の対策を取れない場合、以下の防止方法から一つ以上を検討してください：

* 悪意のあるオブジェクトの生成やデータの改ざんを防ぐために、シリアライズされたオブジェクトにデジタル署名などの整合性チェックを実装する。
* コードは定義可能なクラスに基づくため、オブジェクトを生成する前に、デシリアライゼーションにおいて厳密な型制約を強制する。ただし、この手法を回避する方法は実証済みなので、この手法頼みにすることはお勧め出来ない。
* 可能であればデシリアライズに関するコードは分離して、低い権限の環境下で実行する。
* 型の不整合やデシリアライズ時に生じた例外など、デシリアライゼーションで発生した失敗や例外はログに記録する。
* デシリアライズするコンテナやサーバーからの、送受信に関するネットワーク接続は、制限もしくはモニタリングする。
* 特定のユーザーが絶えずデシリアライズしていないか、デシリアライゼーションをモニタリングし、警告する。


## 攻撃シナリオの例

**シナリオ #1**: Reactアプリケーションが、一連のSpring Bootマイクロサービスを呼び出します。
関数型言語のプログラマーは、イミュータブルなコードを書こうとします。
そこで、プログラマーは、呼び出しの前後でシリアライズしたユーザーの状態を渡す、と言う解決策を思いつきます。
攻撃者は （base64でエンコードされていることを示す）"r00"と言うJavaオブジェクトのシグネチャに気づき、Java Serial Killerツールを使用してアプリケーションサーバー上でリモートコードを実行します。

**シナリオ #2**: あるPHPフォーラムでは、PHPオブジェクトのシリアライゼーションを使用して、ユーザーのユーザーID、ロール、パスワードハッシュやその他の状態を含むSuper Cookieを保存します。：

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

攻撃者は、シリアライズされたオブジェクトを変更して攻撃者自身に管理者権限を与えます。

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## 参考資料

### OWASP

* [OWASP Cheat Sheet: Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [OWASP Proactive Controls: Validate All Inputs](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard: TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### その他

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [Java Unmarshaller Security](https://github.com/mbechler/marshalsec)
* [OWASP AppSec Cali 2015: Marshalling Pickles](http://frohoff.github.io/appseccali-marshalling-pickles/)
