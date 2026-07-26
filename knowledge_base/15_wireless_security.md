# 無線LANセキュリティ

家庭内Wi-Fi環境が攻撃対象・攻撃経路になる場合の理論・手法。ARPスプーフィングの前提となる「同一L2セグメントへの到達」をWi-Fi経由でどう成立させるかにも関わる。

## WPA2の既知の弱点
- 4-way handshakeをキャプチャできれば、オフラインでパスフレーズの辞書攻撃・総当たりが可能(弱いパスフレーズなら現実的な時間で破れる)
- **WPS(Wi-Fi Protected Setup)**: 8桁PINの設計上の欠陥により、実質的に前半4桁・後半4桁を別々に総当たりできてしまい、探索空間が約11,000通り程度まで縮小する。Reaverのようなツールで数時間規模でPINを割れることがある。WPSが有効なルーターは特に狙われやすい
出典: [MyCyberSecurityPath: Wireless Network Security](https://mycybersecuritypath.com/cybersecurity/wireless-hacking/)

## WPA3でも残る弱点
- **Dragonblood系脆弱性**: サイドチャネル攻撃によるデータ漏洩、WPA2へのダウングレード強制、DoS条件などが報告されている
- **移行モード(Transition Mode)の罠**: WPA3とWPA2を両方受け付ける互換モードを有効にしていると、攻撃者が同じSSIDでWPA2のみを提供する偽AP(Evil Twin)を立て、デバイスがWPA2側にフォールバック接続してしまうことで4-way handshakeを窃取できる — 2026年の研究でもUbuntu/Windows双方のクライアントで、証明書検証設定が甘い場合にEvil Twin接続が成立することが確認されている
出典: [RedLegg: WPA3 Evil Twin Attack](https://www.redlegg.com/blog/wpa3-evil-twin-attack), [Payatu: WPA3 Isn't the End of Wi-Fi Hacking](https://payatu.com/blog/wpa3-isnt-the-end-of-wi-fi-hacking/)

## Evil Twin(偽アクセスポイント)攻撃の考え方
1. 対象と同じSSID・可能なら同じような信号強度になる偽APを立てる
2. 正規APより電波が強い/認証が緩いと、クライアントが自動的に偽APへ接続してしまうことがある
3. 偽AP経由の通信は完全に攻撃者の制御下にあるため、ARPスプーフィングを使うまでもなくMITMが成立する(むしろEvil TwinはARPスプーフィングより直接的なMITM手法)
4. キャプティブポータル(偽のログイン画面)を組み合わせれば、認証情報の直接窃取も可能

## Wi-Fi経由MITMとARPスプーフィングの関係
- ARPスプーフィングは「同一L2セグメントに参加した後」に行う攻撃。家庭内Wi-Fiの場合、そのセグメントへの参加自体はWi-Fiパスワードを知っている(正規に接続する)前提で成立することが多い
- Evil Twinはその前提を飛ばして「セグメントへの参加」自体を騙し取る手法であり、ARPスプーフィングとは別の攻撃ベクトルとして併記・比較する価値がある
- 家庭用ルーターの防御力を評価する際は「Wi-Fi自体への不正接続のしやすさ」と「L2内でのARPスプーフィングへの耐性」を分けて評価するのが妥当

## 報告
- Wi-Fi関連の弱点(WPS有効、弱いパスフレーズ、WPA2フォールバック許可)を確認したら report(recon, ...)
- 実際にhandshake取得・PIN解析・Evil Twin接続に成功したら report(finding, severity="high"〜"critical")
