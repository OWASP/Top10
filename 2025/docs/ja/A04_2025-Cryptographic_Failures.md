# A04:2025 暗号化の失敗 (Cryptographic Failures) ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

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
* 初期化ベクトル (IV) を無視、再利用していないか。暗号モードに適した方法で生成されているか。ECB (電子符号表モード) のような不セキュアなモードを使用していないか。
* パスワードを暗号鍵として使用する際、適切な鍵導出関数 (KDF) を介しているか。
* 乱数生成器が暗号学的要件を満たしているか。シード値に十分なエントロピーや予測不能性が備わっているか。
* MD5 や SHA1 などの廃止されたハッシュ関数、あるいは非暗号学的ハッシュ関数を誤用していないか。
* 暗号エラーメッセージやサイドチャネル情報 (パディング・オラクル攻撃等) が悪用される恐れはないか。
* 暗号アルゴリズムのダウングレードや回避が可能になっていないか。

## 防止方法 (How to Prevent)

最低限、以下の対策を実施してください。

* **データの分類とラベリング：** アプリケーションが処理・保存・伝送するデータを分類してください。法規制やビジネス上のニーズに基づき、どのデータが機密 (Sensitive) であるかを特定します。
* **重要資産の保護：** 最も重要な鍵は、ハードウェアまたはクラウドベースの HSM (ハードウェア・セキュリティ・モジュール) に保存してください。
* **不要な機密データの破棄：** 機密データを不必要に保存しないでください。不要になったデータは速やかに破棄するか、PCI DSS 準拠のトークン化や切り詰め (Truncation) を実施してください。保存されていないデータは盗まれることもありません。
* **保存データの暗号化：** すべての機密データは保存時に暗号化してください。
* **プロトコルとアルゴリズムの更新：** 暗号化が必要なすべての伝送には、TLS 1.2 以上を使用してください。前方秘匿性 (FS: Forward Secrecy) を備えた暗号、および量子耐性を持つ鍵交換アルゴリズムを採用し、CBC (暗号ブロック連鎖) モードのサポートは停止してください。HTTPS 通信には HSTS を強制してください。
* **キャッシュの無効化：** 機密データを含むレスポンスについては、CDN、Web サーバー、およびアプリ側のキャッシュ (Redis 等) を無効化してください。
* **パスワードの安全な保存：** パスワードには Argon2、yescrypt、scrypt、または PBKDF2-HMAC-SHA-512 のような、ソルト付きの適応型ハッシュ関数を使用してください。
* **認証付き暗号の採用：** 単なる暗号化ではなく、常に認証付き暗号 (Authenticated Encryption) を使用してください。
* **耐量子計算機暗号 (PQC) への備え：** 2030年末までを見据え、リスクの高いシステムを保護するための PQC 移行ロードマップを策定してください。

## 攻撃シナリオの例 (Example Attack Scenarios)

**シナリオ #1：** あるサイトが全ページで TLS を強制していない、あるいは強度の低い暗号を許可している。攻撃者は、保護されていないワイヤレスネットワーク等でトラフィックを監視し、HTTPS から HTTP への接続ダウングレードを実行する。これにより、セッション Cookie を奪取して認証済みセッションを乗っ取り、ユーザーの個人データへのアクセスや改ざん（振込先の変更等）を行う。

**シナリオ #2：** パスワードデータベースが、ソルトなしの単純なハッシュ形式で保存されていた。ファイルアップロードの脆弱性を突いてデータベースが奪取された結果、レインボーテーブル (事前計算済みハッシュの一覧) を用いてすべてのパスワードが露呈した。たとえソルトが付与されていても、単純で高速なハッシュ関数は GPU によるクラッキングの標的となる。

## 関連資料 (References)

* [OWASP Proactive Controls: C2: データの保護に暗号技術を活用する](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
* [OWASP ASVS: V11 暗号化, V12 安全な通信, V14 データ保護](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Cheat Sheet: パスワードの保存](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [NIST: 第1次耐量子暗号標準 (PQC) の公開](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
* [CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
* [CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
* [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
* [CWE-1241 Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)


