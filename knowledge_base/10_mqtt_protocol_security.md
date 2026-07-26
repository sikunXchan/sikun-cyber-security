# MQTTプロトコルのセキュリティ

家庭内IoT環境のMQTT通信を扱う際の理論的背景。卒論の攻撃実証・対策評価の裏付け資料として、実在する研究・統計を引用する。

## MQTTはデフォルトで平文・認証なし
MQTTはプロトコル仕様として暗号化を必須にしておらず、TLSを明示的に有効化しない限り認証情報を含む全通信が平文で流れる。ブローカー側も匿名接続(`allow_anonymous`)を許可する設定がデフォルトになっているケースが多く、Shodan調査ではユーザー名・パスワードなしでインターネットに公開されているMQTTデバイスが50万台以上確認されている。
出典: [network-king.net MQTT Security](https://network-king.net/mqtt-security-problems-and-proven-solutions-for-iot-infrastructure/), [MQTT.pro Security Best Practices](https://mqtt.pro/mqtt-security/)

## 認証(Authentication)と認可(Authorization)は別問題
- **認証**: ユーザー名/パスワード、またはクライアント証明書によるmTLS(相互TLS)で「誰が接続しているか」を確認する層
- **認可(ACL)**: 認証されたクライアントが「どのトピックをpublish/subscribeできるか」を制限する層
- **重要な点**: 認証を強化しても、ACLが緩い(全クライアントが全トピックを購読できる)場合、正規に認証された低権限デバイス1台の侵害から他デバイスの全データが読み取れてしまう。ワイルドカード(`#`, `+`)を使った購読で意図せず広範囲のトピックにアクセスできてしまう設定ミスも典型的
- 認証・認可・暗号化の3つは独立した対策であり、どれか1つだけを強化しても他の穴は塞がらない(暗号化なしのまま認証だけ強化すると、認証情報自体が盗聴されて突破される、等)
出典: [Analysis of Misconfigured IoT MQTT Deployments (NDSS)](https://www.ndss-symposium.org/wp-content/uploads/sdiotsec25-10.pdf), [Cedalo: MQTT Authentication and Authorization on Mosquitto](https://www.cedalo.com/blog/mqtt-authentication-and-authorization-on-mosquitto)

## TLS/mTLSによる対策
- **サーバー側TLS**: ブローカー~クライアント間の通信を暗号化し、盗聴(ARPスプーフィング等によるMITM含む)による認証情報・ペイロードの平文取得を防ぐ
- **相互TLS(mTLS)**: サーバー証明書に加えクライアント証明書も要求することで、なりすまし接続自体を防ぐ。`use_identity_as_username`のような設定では証明書のCN(Common Name)をそのままMQTTユーザー名として扱い、パスワード管理を証明書管理に一本化できる
- TLSを有効化してもARPスプーフィング自体(L2層の攻撃)を防ぐわけではない点に注意。TLSが防ぐのは「通信内容の窃視・改ざん」であって、経路の乗っ取りそのものではない — MITMの成立は許すが、内容の窃視・改ざんを防ぐ、という切り分けが重要
出典: [Payatu: MQTT Broker Security](https://payatu.com/blog/mqtt-broker-security/), [Shawn Hymel: Mosquitto with SSL/TLS](https://shawnhymel.com/3085/how-to-use-the-mosquitto-mqtt-broker-with-ssl-tls/)

## 既知の脆弱性クラス(2024年以降の報告例)
- **パストラバーサル**(CVE-2024-6786): ブローカー実装によってはトピック名やファイルパス処理に起因する脆弱性
- **ワイルドカード起因の情報露出**(CVE-2024-31409): ACL設計の不備でワイルドカード購読が想定以上の範囲に及ぶ
- **DoS(null dereference等)**(CVE-2024-31041): 不正なパケット処理によるブローカーのクラッシュ
- 実際の対象・実装ではCVE番号そのものより「このクラスの不備がないか」の確認が実務的
出典: [MQTT Security Problems Solved](https://network-king.net/mqtt-security-problems-and-proven-solutions-for-iot-infrastructure/)

## 攻防戦・卒論実験での着眼点
1. ブローカーが匿名接続を許可していないか(`mosquitto_sub -h <target> -t '#' -v` が認証なしで通るか)
2. ACLが正しくトピック単位で分離されているか(ワイルドカードで無関係なデバイスのトピックまで読めないか)
3. TLSが有効か、有効でも証明書検証を省略していないか(自己署名証明書を無条件許可していると中間者攻撃で偽ブローカーに誘導される余地が残る)
4. 認証情報がMQTT接続時にどう送られているか(平文か、TLS内か)をパケットキャプチャで確認する
