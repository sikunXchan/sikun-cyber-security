# 偵察(Recon)プレイブック

## 基本方針
- まずポートスキャンでサービスを特定してから深掘りする。いきなり攻撃を試さない
- 各サービスのバージョンを取得し、既知の脆弱性(CVE)がないか確認する
- 発見した情報は report(recon, ...) でこまめに共有する

## 手順
1. **ポートスキャン**: `nmap -sV -sC -p- <target>` (全ポート + バージョン検出 + デフォルトスクリプト)
   - 全ポートは時間がかかるので、まず `nmap -sV -sC <target>` (上位1000ポート)で当たりを付けてもよい
2. **Webサービスがあれば**:
   - `curl -sI http://<target>` でヘッダー確認(サーバー種別、フレームワーク)
   - ディレクトリ探索: `gobuster dir -u http://<target> -w <wordlist>` (wordlistが無ければ手動で /admin /login /api /.git などを試す)
   - `curl http://<target>/robots.txt` `curl http://<target>/.git/config` なども確認
3. **バージョンが判明したら**: 既知の脆弱性がないか知識(学習データ)から検索し、なければ web_exploitation.md の手法を試す
4. SSHやFTPなどが空いていれば、バナー情報からバージョンを控えておく(後で権限昇格や既知exploitの判断に使う)

## 報告の粒度
- ポートが開いているのを見つけたら都度 report(recon, "port X open (service)")
- サービスバージョンが分かったら追加で report(recon, ...)
- 明らかに攻撃の糸口になりそうなもの(古いバージョン、デフォルト認証情報の可能性など)は report(recon, ..., severity="info") で軽くフラグを立てておく
