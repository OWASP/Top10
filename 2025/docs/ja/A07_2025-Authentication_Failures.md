# A07:2025 認証の不備 (Authentication Failures) ![icon](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景 (Background)

「認証の失敗」は、前回から引き続き第7位となりました。36の CWE (共通弱点一覧) をより正確に表すために名称が微修正されましたが、標準化されたフレームワークが普及した現在でも、依然としてこの順位に留まっているものです。主要な CWE には、ハードコードされたパスワードの利用 (CWE-259, CWE-798)、ホスト不一致を伴う証明書の不適切な検証 (CWE-297)、不適切な認証 (CWE-287)、およびセッション固定 (CWE-384) が含まれます。

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
   <td>36</td>
   <td>15.80%</td>
   <td>2.92%</td>
   <td>100.00%</td>
   <td>37.14%</td>
   <td>7.69</td>
   <td>4.44</td>
   <td>1,120,673</td>
   <td>7,147</td>
  </tr>
</table>

## 説明 (Description)

本脆弱性は、攻撃者がシステムを欺き、無効なユーザーや誤ったユーザーを正当なものとして認識させた場合に発生します。

以下の項目に当てはまる場合、アプリケーションに認証上の不備が存在する可能性があります。

* **自動化攻撃の許容：** クレデンシャルスタッフィング (Credential Stuffing) や、流出した資格情報のバリエーションを試すパスワードスプレー攻撃 (Password Spray Attacks) を許容している。
* **脆弱なパスワードの許可：** デフォルト設定、脆弱な、あるいは広く知られたパスワードの使用を許可している。
* **漏洩済み情報の利用：** 既に侵害が確認されている資格情報を用いて新規アカウントを作成できてしまう。
* **不適切なリカバリプロセス：** 「秘密の質問」のような、安全性を確保できない知識ベースの回答に依存したパスワード復旧プロセスを採用している。
* **不十分なデータ保護：** パスワードをプレーンテキスト、あるいは脆弱なハッシュ形式で保存している（[A04:2025 暗号化の失敗](A04_2025-Cryptographic_Failures.md) 参照）。
* **MFA の欠如：** 多要素認証 (MFA) が実装されていない、あるいはそのフォールバック手段が脆弱である。
* **セッション管理の不備：** URL や不セキュアな場所へセッション ID を露出させている、あるいはログイン後にセッション ID を再利用している。
* **不完全なログアウト：** ログアウト時や一定時間の無活動後に、セッションや認証トークン（特に SSO トークン）が正しく無効化されない。
* **検証の不足：** 提供された資格情報の適用範囲 (Scope) や意図された対象 (Audience) を正しく検証していない。

## 防止方法 (How to Prevent)

* **MFA の強制：** 可能な限り多要素認証 (MFA) を実装し、盗まれた資格情報の再利用や自動化された攻撃を防御してください。
* **パスワードマネージャーの推奨：** ユーザーがより安全なパスワードを選択できるよう、パスワードマネージャーの利用を促してください。
* **デフォルト設定の排除：** 管理ユーザーを含め、初期設定の資格情報が残った状態でデプロイしないでください。
* **漏洩済み情報のチェック：** パスワード設定・変更時に、ワーストパスワードリストや漏洩済み情報（[haveibeenpwned.com](https://haveibeenpwned.com) 等の活用）との照合を実施してください。
* **最新ガイドラインへの準拠：** パスワードの長さ、複雑さ、およびローテーションポリシーは、[NIST 800-63b (セクション 5.1.1)](https://pages.nist.gov/800-63-3/sp800-63b.html) などの証拠に基づいた最新のガイドラインに準拠してください。
* **メッセージの共通化：** アカウント列挙攻撃を防ぐため、ログインや復旧時のメッセージは、成否にかかわらず共通のもの（例：「ユーザー名またはパスワードが無効です」）を使用してください。
* **ログイン試行の制限：** ログイン失敗時の試行を制限、あるいは遅延させてください。ただし、DoS 攻撃に繋がらないよう慎重に設計する必要があります。
* **セキュアなセッション管理：** ログイン後に高いエントロピーを持つ新しいランダムなセッション ID を生成し、URL ではなくセキュアな Cookie に保存してください。ログアウトやタイムアウト時には必ずサーバー側で無効化してください。
* **信頼できるシステムの利用：** 実績があり十分にテストされた認証・アイデンティティ管理システムを導入することで、リスクを転嫁することを検討してください。
* **トークンの検証：** JWT 等を利用する場合、`aud` (Audience) や `iss` (Issuer) クレーム、および Scope を必ず検証してください。

## 攻撃シナリオの例 (Example Attack Scenarios)

**シナリオ #1：ハイブリッド型クレデンシャルスタッフィング**
攻撃者は漏洩済みの資格情報リストに対し、「Winter2025」を「Winter2026」に変えるなどの人間特有の規則性を突いてパスワードを微調整し、攻撃を試みます。自動化された脅威への防御策がない場合、アプリケーションはパスワードの妥当性を確認するための踏み台（パスワードオラクル）として悪用されてしまいます。

**シナリオ #2：SSO ログアウトの不備**
シングルログアウト (SLO) が実装されていない場合、複数のシステムに SSO でログインした後、一つのシステムでログアウトしても、他のシステムへの認証が残ったままになることがあります。共有端末などでブラウザを閉じずに席を離れた場合、攻撃者が残存したセッションを通じて被害者のアカウントへアクセスできてしまいます。

## 関連資料 (References)

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)
* [NIST 800-63b: 認証とライフサイクル管理](https://pages.nist.gov/800-63-3/sp800-63b.html)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
* [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
* [CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
* [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)


