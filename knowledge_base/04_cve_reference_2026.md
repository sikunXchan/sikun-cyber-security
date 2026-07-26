# CVE・脆弱性トレンド リファレンス(2026年)

対象非公開の演習では特定CVE番号への依存は危険(対象が一致しない可能性が高い)。
ここでは**脆弱性のクラス・パターン**を優先し、具体例としてCVEを添える。
出典は各セクション末尾に記載。

## 全体トレンド

- 2026年前半だけで21,500件以上のCVEが新規開示(前年同期比+16〜18%)
- 新規CVEの悪用までの中央値は5日未満 — パッチ未適用の窓が狭い
- Webアプリへの攻撃は2025年に62.9億件(前年40億件から+56%)
出典: [cybersecuritynews.com](https://cybersecuritynews.com/10-high-risk-vulnerabilities-of-2026/), [Recorded Future](https://www.recordedfuture.com/blog/april-cve-landscape)

## Webアプリケーション(OWASP Top 10 2025)

対象が「Webサイト」の場合、まずこの順で疑う:

1. **A01 Broken Access Control(依然として1位)** — 認可漏れ。URLやパラメータの改ざんで
   他ユーザーのリソースにアクセスできないか(IDOR)、管理機能に一般ユーザーで到達できないか
2. **A02 Security Misconfiguration(5位→2位に上昇)** — デフォルト設定放置、不要なデバッグ
   エンドポイント露出、エラーメッセージからのスタックトレース漏洩
3. **A03 Software Supply Chain Failures(新設)** — 使用ライブラリ・依存パッケージのバージョン
   を確認し、既知脆弱性がないか照合(`pip list`, `npm list`, パッケージのバージョン表示等)
4. **A10 Mishandling of Exceptional Conditions(新設)** — 異常系(不正入力・タイムアウト・
   リトライ)の処理不備によるロジック崩壊

実務手順:
- レスポンスヘッダー・エラーページからフレームワーク/バージョンを特定 → 既知CVEを照合
- 管理画面・APIエンドポイントを認可なしで直接叩けないか試す(A01)

出典: [OWASP Top 10:2025](https://owasp.org/Top10/2025/), [SecureLayer7](https://blog.securelayer7.net/owasp-top-10-security-risks/)

## IoT機器

対象が「IoT機器」の場合:

- **デフォルト認証情報(CWE-1392)が依然として最多**。ファームウェアに固定/変更不可の認証情報が
  焼き込まれているケースが多い(例: CVE-2026-50005、Brickcom製カメラの静的認証情報で映像に
  フルアクセス可能)
- **ファームウェア更新の検証不備** — 署名検証なし、または非認証チャネルでの更新受付により、
  悪意あるファームウェアを注入できる場合がある
- 多くのIoT機器はEOL(サポート終了)後もパッチが提供されず、稼働し続けている
- 通信プロトコルが一般的なセキュリティツールでパースされない(独自プロトコル・独自暗号化)
  ことが多く、盗聴よりも「認証情報の直接取得」や「ローカル通信の観測(暗号化されていない
  制御系トラフィックがないか)」の方が現実的な突破口になりやすい

出典: [SEC.co CVE-2026-50005](https://sec.co/vulnerabilities/cve-2026-50005), [Fortinet](https://www.fortinet.com/resources/cyberglossary/iot-device-vulnerabilities)

## ローカルアプリケーション・ローカルネットワークサービス

対象が「ローカルアプリケーション」の場合、権限昇格の定番パターン:

- **SMB/RDPの権限昇格系CVEが多発**(2026年: CVE-2026-24294, CVE-2026-26128, CVE-2026-21533など)
  — 低権限ローカルユーザーがSYSTEM権限まで到達する経路が繰り返し発見されている
- **共通パターン**: 認証境界の実装不備、競合状態(race condition)、情報漏洩(メモリ内の
  認証情報・トークンが別プロセスから読める)からの権限昇格チェーン
- 実務手順: バージョン情報の取得 → 既知の権限昇格チェーンの有無を確認 → ローカルの
  設定ミス(書き込み可能なサービスパス、SUID、cronジョブ等 — 03_privilege_escalation.md参照)
  と組み合わせて突破口を探す

出典: [SentinelOne CVE-2026-24294](https://www.sentinelone.com/vulnerability-database/cve-2026-24294/), [Penligent CVE-2026-21533](https://www.penligent.ai/hackinglabs/cve-2026-21533-the-rdp-foot-in-the-door-bug-that-turns-a-low-priv-user-into-system/)

## 使い方の指針

- 対象のサービス・バージョンが分かったら、まずこのファイルのクラス分類と照合する
- 一致するクラスがあれば、該当する一般的な手法(認可漏れ確認・デフォルト認証情報試行・
  権限昇格チェーンの探索等)を優先的に試す
- 具体的なCVE番号がそのまま刺さる可能性は低い(対象非公開のため)ので、
  「このクラスの脆弱性が過去に多い」という事前知識として使うこと
