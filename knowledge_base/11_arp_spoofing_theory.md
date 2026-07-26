# ARPスプーフィングの理論的背景

家庭内MITM実証実験の理論的裏付け。ARPプロトコルの仕組みからSTRIDE分類、検知・対策手法の研究動向までを整理する。

## ARPプロトコルの仕組みと構造的弱点
ARP(Address Resolution Protocol)はIPアドレスをMACアドレスに変換するためのプロトコルだが、**メッセージの送信元を認証する仕組みを持たない**。ARPリクエストを送っていない端末からのARP応答(Gratuitous ARP含む)も無条件に受理してキャッシュを更新してしまう実装が一般的であり、これが攻撃の根本原因になっている。
出典: [Imperva: ARP Spoofing](https://www.imperva.com/learn/application-security/arp-spoofing/), [SentinelOne: ARP Spoofing](https://www.sentinelone.com/cybersecurity-101/threat-intelligence/arp-spoofing/)

## 攻撃の成立条件
1. 攻撃者が被害者と同一のL2セグメント(同じLAN・同じWi-Fi)に存在すること
2. 偽装したARP応答(自分のMACアドレスを、ゲートウェイや対象デバイスのIPアドレスに紐付けたもの)を送信し、被害者のARPキャッシュを書き換える
3. 被害者から見た通信の宛先(ゲートウェイ等)が攻撃者経由になり、通信が攻撃者のマシンを経由して中継される(この時点でMITMが成立)
4. 攻撃者はIPフォワーディングを有効にして通信を中継しつつ、内容の観測・改ざんを行う
出典: [Cyberhaven: ARP Poisoning](https://www.cyberhaven.com/infosec-essentials/arp-poisoning), [Ascendant: ARP Poisoning](https://ascendantusa.com/2025/01/09/arp-poisoning/)

## STRIDEでの分類
- **Spoofing(なりすまし)**: 攻撃者がゲートウェイ/対象デバイスになりすましてARP応答を送る、攻撃の起点そのもの
- **Tampering(改ざん)**: 中継した通信内容を書き換えて転送できる(暗号化・完全性検証がない通信の場合)
- **Information Disclosure(情報漏洩)**: 中継した通信内容を盗聴できる(暗号化されていないMQTT等のプロトコルは特に影響が大きい)
- **Denial of Service(可用性低下)**: 中継を止める、または誤った転送先に誘導することで通信を成立させなくすることも可能
- 家庭内IoT環境では特に S(なりすまし) を起点として I(情報漏洩)・T(改ざん) に波及する構図になりやすく、暗号化・認証・経路の完全性保証がそれぞれ独立して必要になる

## 検知手法の研究動向
- **静的対策**: IP-MACの固定エントリ(static ARP)、DAI(Dynamic ARP Inspection、スイッチ側でDHCPスヌーピング情報と照合してARPパケットの正当性を検証する機能) — ただし家庭用ルーター・スイッチでは対応していない/設定できない機種が多い
- **機械学習ベースの検知**: 2025年以降、ARPヘッダの挙動・トラフィックの時系列異常・アンサンブル学習/深層学習(XGBoost, CNN-LSTM等)を組み合わせた検知手法の研究が進んでいる。従来の「固定IP-MACリスト」「ICMPベースの確認」だけでは大規模・リアルタイム環境で不十分とされている
- **IoT向け軽量検知**: IoT機器はリソース制約があるため、機器側ではなくネットワーク側(ゲートウェイ・ルーター)で検知を行うアプローチが現実的
出典: [arXiv: Intelligent ARP Spoofing Detection using Multi-layered ML for IoT Networks](https://arxiv.org/abs/2507.21087), [Springer: ARP spoofing detection using machine learning classifiers](https://link.springer.com/article/10.1007/s10115-024-02219-y)

## 家庭用ルーター環境での限界
- 家庭用ルーターの多くはDAIのようなL2レベルの防御機能を持たない(業務用スイッチ機能であり、コンシューマ向け製品には基本的に搭載されない)
- そのため家庭内IoT環境の現実的な対策は「ARPスプーフィング自体を防ぐ」より「ARPスプーフィングが成立してもTampering/Information Disclosureの実害を防ぐ」方向(TLS化、VLAN分離によるセグメント限定等)に寄らざるを得ない — これは対策実験(暗号化・認証・VLAN分離)の位置付けを理論的に補強する
