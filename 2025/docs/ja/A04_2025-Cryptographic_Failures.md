# A04:2025 暗号化の不備 (Cryptographic Failures) ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景 (Background)

本カテゴリは、前回から順位を2つ下げて第4位となりました。暗号化の欠如や強度の不足、暗号鍵の漏洩、およびそれらに関連するエラーに焦点を当てています。本リスクにおける主要な CWE (共通弱点一覧) のうち 3 つは、脆弱な擬似乱数生成器 (PRNG: Pseudo-Random Number Generator) の利用に関連するものです。具体的には、壊れた、あるいはリスクのある暗号アルゴリズムの利用 (CWE-327)、不十分なエントロピー (CWE-331)、乱数生成器における予測可能なアルゴリズムの利用 (CWE-1241)、および暗号学的に脆弱な擬似乱数生成器の利用 (CWE-338) が挙げられます。

## スコアテーブル (Score Table)

<table>
  <tr>
   <td>紐付けられた CWE 数</td>
   <td>最大出現率</td>
   <td>平均出現率</td>
   <td>最大網羅率</td>
   <td>平均網羅率</td>
   <td>平均加重悪用スコア</td>
   <td>平均加重影響スコア</td>
   <td>出現総数</td>
   <td>CVE 総数</td>
  </tr>
  <tr>
   <td>32</td>
   <td>13.77%</td>
   <td>3.80%</td>
   <td>100.00%</td>
   <td>47.74%</td>
   <td>7.23</td>
   <td>3.90</td>
   <td>1,665,348</td>
   <td>2,185</td>
  </tr>
</table>

## 説明 (Description)

原則として、伝送中のすべてのデータはトランスポート層 (OSI 第4層) で暗号化されるべきです。かつて課題であった CPU 負荷や証明書管理は、モダンな CPU が備える暗号化加速命令 (AES 命令セット等) や、LetsEncrypt.org のような自動化サービス、クラウドベンダーによる統合管理機能によって解決されています。

トランスポート層の保護に加え、保存済みのデータ (Data at Rest) や、アプリケーション層 (OSI 第7層) での追加保護が必要なデータを特定することが重要です。特にパスワード、クレジットカード番号、健康記録、個人情報、および営業秘密は、GDPR (EU 一般データ保護規則) や PCI DSS (クレジットカード業界のデータセキュリティ基準) 等の法的・規制要件に基づき、厳重な保護が求められます。

以下の項目を点検してください。

* デフォルト設定や古いコードにおいて、強度の低い暗号アルゴリズムやプロトコルを使用していないか。
* デフォルトの暗号鍵を使用していないか。鍵の強度は十分か。鍵を使い回していないか。適切な鍵管理やローテーションが行われているか。
* 暗号鍵がソースコードリポジトリにコミットされていないか。
* 暗号化が強制されているか。ブラウザのセキュリティヘッダー (HSTS 等) やディレクティブが欠落していないか。
* サーバー証明書およびトラストチェーン (信頼の連鎖) が適切に検証されているか。
* 初期化ベクトル (IV) を無視、再利用していないか。暗号モードに適した方法で生成されているか。ECB (電子符号表モード) のような安全でないモードを使用していないか。認証付き暗号がより適切な場面で、単なる暗号化を使用していないか。
* パスワードを暗号鍵として使用する際、適切な鍵導出関数 (KDF) を介しているか。
* 乱数生成器が暗号学的要件を満たしているか。シード値に十分なエントロピーや予測不能性が備わっているか。
* MD5 や SHA1 などの廃止されたハッシュ関数、あるいは非暗号学的ハッシュ関数を誤用していないか。
* 暗号エラーメッセージやサイドチャネル情報 (パディング・オラクル攻撃等) が悪用される恐れはないか。
* 暗号アルゴリズムのダウングレードや回避が可能になっていないか。

参照: ASVS 暗号化 (V11)、安全な通信 (V12)、データ保護 (V14)

## 防止方法 (How to Prevent)

最低限、以下の対策を実施し、関連資料も参照してください。

* **データの分類とラベリング：** アプリケーションが処理・保存・伝送するデータを分類し、ラベル付けしてください。プライバシー法、規制要件、またはビジネス上のニーズに基づき、どのデータが機密 (Sensitive) であるかを特定します。
* **HSM での鍵保存：** 最も重要な鍵は、ハードウェアまたはクラウドベースの HSM (ハードウェア・セキュリティ・モジュール) に保存してください。
* **信頼できる暗号実装の使用：** 可能な限り、十分に信頼されている暗号アルゴリズムの実装を使用してください。
* **不要な機密データの破棄：** 機密データを不必要に保存しないでください。不要になったデータは速やかに破棄するか、PCI DSS 準拠のトークン化や切り詰め (Truncation) を実施してください。保存されていないデータは盗まれることもありません。
* **保存データの暗号化：** すべての機密データは保存時 (Data at Rest) に暗号化してください。
* **最新かつ強力なアルゴリズムの使用：** 最新かつ強力な標準アルゴリズム、プロトコル、鍵を使用し、適切な鍵管理を行ってください。
* **伝送データの暗号化：** すべての伝送データは TLS 1.2 以上のプロトコルのみで暗号化してください。前方秘匿性 (FS: Forward Secrecy) を備えた暗号スイートを使用し、CBC (暗号ブロック連鎖) モードのサポートは停止してください。量子鍵交換アルゴリズムもサポートしてください。HTTPS 通信には HTTP Strict Transport Security (HSTS) を強制し、ツールですべてを検証してください。
* **キャッシュの無効化：** 機密データを含むレスポンスについては、CDN、Web サーバー、およびアプリ側のキャッシュ (Redis 等) を無効化してください。
* **データ分類に応じた制御の適用：** データ分類に応じて、必要なセキュリティ制御を適用してください。
* **非暗号化プロトコルの禁止：** FTP や STARTTLS などの非暗号化プロトコルを使用しないでください。機密データの送信に SMTP を使用することも避けてください。
* **パスワードの安全な保存：** パスワードには Argon2、yescrypt、scrypt、または PBKDF2-HMAC-SHA-512 のような、ソルト付きでワークファクター（遅延ファクター）を持つ適応型ハッシュ関数を使用してください。bcrypt を使用しているレガシーシステムについては、[OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) で詳細なアドバイスを確認してください。
* **適切な IV の選択：** 初期化ベクトル (IV) は暗号モードに適した方法で選択してください。ノンスを必要とするモードでは、IV に CSPRNG (暗号論的擬似乱数生成器) は不要です。いずれの場合も、固定鍵に対して同じ IV を二度使用しないでください。
* **認証付き暗号の採用：** 単なる暗号化ではなく、常に認証付き暗号 (Authenticated Encryption) を使用してください。
* **暗号鍵の生成と保存：** 鍵は暗号論的にランダムに生成し、メモリ上ではバイト配列として保存してください。パスワードを使用する場合は、適切なパスワードベースの鍵導出関数 (KDF) を介して鍵に変換する必要があります。
* **暗号乱数の適切な使用：** 暗号乱数が適切に使用され、予測可能な方法や低エントロピーでシードされていないことを確認してください。ほとんどの最新 API では、開発者が CSPRNG をシードする必要はありません。
* **非推奨の暗号関数の回避：** MD5、SHA1、CBC モード、PKCS #1 v1.5 などの非推奨の暗号関数、ブロック構築方式、パディングスキームを使用しないでください。
* **設定のセキュリティレビュー：** 設定と構成がセキュリティ要件を満たしていることを、セキュリティ専門家やツール、またはその両方によってレビューしてください。
* **耐量子計算機暗号 (PQC) への備え：** 2030年末までにリスクの高いシステムを保護できるよう、今から PQC (Post-Quantum Cryptography) への移行準備を進めてください。関連資料 (ENISA) を参照してください。

## 攻撃シナリオの例 (Example Attack Scenarios)

**シナリオ #1：** あるサイトが全ページで TLS を強制していない、あるいは強度の低い暗号を許可している。攻撃者は、保護されていないワイヤレスネットワーク等でトラフィックを監視し、HTTPS から HTTP への接続ダウングレードを実行する。これにより、セッション Cookie を奪取して認証済みセッションを乗っ取り、ユーザーの個人データへのアクセスや改ざん（振込先の変更等）を行う。

**シナリオ #2：** パスワードデータベースが、ソルトなしの単純なハッシュ形式で保存されていた。ファイルアップロードの脆弱性を突いてデータベースが奪取された結果、レインボーテーブル (事前計算済みハッシュの一覧) を用いてすべてのパスワードが露呈した。たとえソルトが付与されていても、単純で高速なハッシュ関数は GPU によるクラッキングの標的となる。

## 関連資料 (References)

* [OWASP Proactive Controls: C2: Use Cryptography to Protect Data](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
* [OWASP Application Security Verification Standard (ASVS):](https://owasp.org/www-project-application-security-verification-standard) [V11,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x20-V11-Cryptography.md) [12,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md) [14](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md)
* [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
* [ENISA: A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
* [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)
* [CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)
* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-320 Key Management Errors (Prohibited)](https://cwe.mitre.org/data/definitions/320.html)
* [CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
* [CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)
* [CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)
* [CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)
* [CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)
* [CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
* [CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)
* [CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)
* [CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
* [CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)
* [CWE-332 Insufficient Entropy in PRNG](https://cwe.mitre.org/data/definitions/332.html)
* [CWE-334 Small Space of Random Values](https://cwe.mitre.org/data/definitions/334.html)
* [CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)
* [CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)
* [CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)
* [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)
* [CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)
* [CWE-342 Predictable Exact Value from Previous Values](https://cwe.mitre.org/data/definitions/342.html)
* [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
* [CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)
* [CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)
* [CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)
* [CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)
* [CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)
* [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
* [CWE-1240 Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)
* [CWE-1241 Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)


