# 権限昇格プレイブック(Linux)

侵入に成功し一般ユーザー権限を得た後、root権限を取れないか確認する手順。

## 列挙(まずここから)
- `sudo -l` — パスワード無しで実行できるコマンドがないか
- `find / -perm -4000 -type f 2>/dev/null` — SUIDビットが立ったファイル
- `cat /etc/crontab` `ls -la /etc/cron.*` — root権限で定期実行されるジョブに書き込めないか
- `uname -a` — カーネルバージョン(古ければkernel exploitの可能性)
- `cat /etc/passwd` — 他のユーザーアカウントの確認

## よくある昇格パターン
- SUID付きの一般的でないバイナリ → GTFOBins的な悪用方法がないか検討
- 書き込み可能なcronスクリプト → root権限で実行されるスクリプトを改ざん
- sudoで無条件実行を許可されたコマンド → そのコマンド経由でシェルを取る
- パスワード使い回し(recon段階で見つけた認証情報がroot/他ユーザーでも通るか試す)

## 報告
- 昇格の糸口を見つけた段階で report(exploit, "権限昇格の糸口: ...")
- root取得に成功したら report(finding, "root権限取得に成功: 手法の概要", severity="critical")
