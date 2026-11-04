# 接続試験実装とローカル検証

記録日: 2026-11-02。対象: T07〜T11の実装とL層の試験器。実AWSの認証、資格情報読取、API、接続、公開は行っていません。

最終統合後の結果は [実装検証記録](local-validation.md) を参照します。実CLIのlocal-lab分岐も追加し、最終PG2件は成功、保持先 `/tmp/vdg-pg-lab-58PCgZ` と `/tmp/vdg-pg-lab-chw5Pw` は停止確認済みです。以下の以前の保持先も削除していません。

## 実装した範囲

| 項目 | 現在の動作 |
| --- | --- |
| 対象と権限 | 設定/snapshot全対象・hash・鮮度を照合。明示suite/source/allow-networkを要求。local-labはlocalhost/loopbackとlocal証拠種別に限定。liveは固定リージョンのDB名/Proxy名に対応するRDS endpoint形式と非ダミーaccountを要求 |
| 認証 | 通常実行は固定AWS CLI `rds generate-db-auth-token`を使う。注入可能な`SigningTokenProvider`はAWS credential providerからSigV4 query署名を生成。署名serviceは`rds-db`、TTLは900秒。local試験のpasswordは別providerからメモリ上だけで注入 |
| 秘密 | token/providerを証拠へserializeしない。SecretTokenのDebugは固定redaction。driver/CLI stderrをそのまま保存しない。TLS無効負例では正規token/passwordを取得せず、空の認証値だけ送る |
| 接続段階 | DNS→TCP到達→CA/ホスト名検証付きTLS→PostgreSQL認証を区別。後段失敗でもTCP到達を消さない。IO切断等の曖昧な原因を認証/TLS防御の成功にしない |
| 期限/取消し | 接続/SQL/総期限を分離。run取消し後に新しい接続を始めない。SQLはserver側statement_timeoutとclient側期限を併用。CancelRequestは使わない |
| SQL | 固定SQLとbind値のみ。run/path hashから検証済みschemaを作り、既存schemaを再利用しない。合成INSERT/SELECT/UPDATE/DELETE、rollback、commit、途中エラーrollback、別session可視性、prepared statement/session stateを確認 |
| 後条件 | COMMITは一度だけ送る。応答喪失は結果不明とし、元接続を閉じ、新規接続のread-only operation marker照合を行う。再INSERT/再COMMITは行わない。照合不能ならunknown |
| session再利用 | 専用sessionでDISCARD ALL後の設定/prepare消失を照合し、statement_timeoutを復元する。明示recovery profileの時間だけread-only transactionを維持する。任意の業務pool実装の検証とは別 |
| 負例 | 正例を先に取得し、無認証、署名破損、明示した不許可profile/user、期限切れ新規認証、TLS無効、誤CA、別hostnameを別caseにする。未指定actorを勝手に作らない |
| 直接経路 | 明示DB宛deny pathへのTCP到達性を観測。TCP到達はネットワーク閉鎖の違反で、後段の認証拒否を代わりのpassにしない |
| 復帰 | 切断、新規認証、固定read-only sleepの期限/子取消し後に接続を閉じ、SELECT 1による復帰を確認。run自体の取消しは復帰処理を止める |
| token期限 | `allow_token_expiry_wait=true`かつ総期限905000ms以上でのみ長時間試験を許可。既存sessionと保持tokenを使う新規sessionを分け、901秒後に確認。通常実行へ15分待機を暗黙追加しない |
| 性能 | 固定`fixed-select-v1`のみ。接続確立と一つの接続を再利用するSQLを別時系列に保存。同時実行1、再試行なし、warmup/件数上限/総期限を守る。接続確立値には安全なstatement_timeout初期化の往復も含む。driver版は組込Cargo.lock、engine版はSQLから取得し、未知のDB class/pinningは埋めない |
| 集計 | 成功時間列とerror_countを保持。sample_countは成功列長+error_count。経験分位点p50は2件、p95は20件、p99は100件以上だけ算出。標本数で業務性能を保証しない |

一つの接続を再利用したSQLを`pooled_query` caseへ記録しています。アプリ固有のconnection pool、poolの自動resetやProxyのpinningを測ったという意味ではありません。session可視性試験では専用接続を二つ開きますが、SQLの実行は逐次です。

## 実施した検証

環境: macOS ARM64、Rust 1.98.1、tokio-postgres 0.7.18、rustls 0.23.46、PostgreSQL 17.7（既設Nix store）、既設OpenSSL 3.6.4。固定AWS対象のPostgreSQL 16.15とは版が異なり、その互換性やAWS Proxy動作の証明にはしません。

`tests/probes.rs`とprobe内単体試験で、ダミー資格情報のSigV4署名、DB userのqueryエンコード、session token/TTL/署名、期限切れAWS資格情報の拒否、秘密Debugの非出力、実行許可、loopback境界、取消し前停止、TCP到達後handshake timeout、TCP拒否を認証拒否へ変換しないこと、TLS無効時の正規資格情報非取得を検証しました。ダミー資格情報以外は使っていません。

`tests/probes_postgres.rs`は明示実行するignored試験です。新規0700ディレクトリへclusterと一日有効の専用CA/localhost証明書を作り、127.0.0.1だけで起動します。既存clusterは使いません。専用DB/userの合成データだけで次を確認しました。

- 正しいCA/hostnameのTLS成功、TLS無効/誤CA/hostname不一致の個別拒否。
- 合成CRUD、commit後条件、rollback、途中エラーrollback、別session可視性、prepare/session state、DISCARD ALL reset、明示50ms transaction。
- 無認証拒否、明示した不許可DB userの拒否、TCP到達を閉鎖合格にしない分類、切断/期限/取消し後の再接続。
- 接続確立と再利用SQLの各30標本、p95あり/p99なし、server statement_timeout後の復帰。
- TLS暗号文を復号しないloopback fault proxyでCOMMITのserver応答を喪失。結果不明を認識した後、新規接続でoperation markerと行数1を照合。書込を再送していないこと。
- 保存した観測JSONにダミーpasswordが含まれないこと。

実行例:

```sh
cargo test --lib --test probes
PG_BIN=/nix/store/1r3winn5zfalbmwinc6lq88b9xraby8a-postgresql-17.7/bin \
  cargo test --test probes_postgres -- --ignored --nocapture
```

試験後はその新規clusterだけを`pg_ctl stop`で停止します。cluster、証明書、log、合成schema/table、観測JSONは保持し、自動削除しません。通常SQL試験のDELETEは合成CRUD transaction内だけで、そのtransactionはrollbackします。DROP/片付けDELETEを行う機能はありません。保持ディレクトリは試験実行時に表示します。直近の成功記録は`/tmp/vdg-pg-lab-1fyTLi`と`/tmp/vdg-pg-lab-PbZiiD`で、`pg_ctl status`から停止も確認しました。

## 未実施とunknownの境界

- 実AWS、PostgreSQL 16.15、RDS Proxyのprotocol/障害/性能、IAM拒否、15分経過の実sessionは未実施です。対応コードがあることと実AWSで成立したことを分けます。
- Proxy→DBのTLSは、取得可能な`rds.force_ssl`と`pg_stat_ssl`を別のruntime caseで観測します。片方が得られなければunknownで、client→Proxy TLSの代用にしません。
- `V10.aws_credential_expiry`の実AWS実行caseは、AWS CLI token commandからcredentialの期限を観測できないため未実装です。注入SigningTokenProviderが期限切れ資格情報を署名/接続前に拒否することはローカルで確認しました。
- `V11.dns_failure / unreachable`の障害注入と、fault→recovered phaseの実環境照合は未実施です。宣言endpointを無関係な宛先へ置換する機能や、環境のDNS/経路を変更する機能はありません。
- ProxyのpinningはCloudWatch等の対応する実観測をまだ取得しないため、`V13.pinning / V16.pinning`はunknownです。prepareやsession stateが使えた事実からpinningを推定してpassにしません。
- 送信元はdeclaredのままです。ホスト/ENI/SG等の客観照合を行っていません。DNS解決先とhostname検証だけではAWS resourceや実行元の完全な同一性を証明できません。live CLIの直前inventory照合と、実験の前後snapshot/変更管理を別に要求します。
- ライブラリが受け取るsnapshotのhashは真正性を保証しません。live CLIの明示AWS読取と再照合を通すこと、試験計画と参照証拠をreportで確認することが必要です。
- clientのtimeout/切断時点でserverの処理が直ちに止まったとは主張しません。read faultは固定0.2秒のsleepだけを使い、server statement_timeoutと合わせて残実行を有限にします。

## 仕様の根拠

接続とTLS拡張は[tokio-postgres Config](https://docs.rs/tokio-postgres/latest/tokio_postgres/config/struct.Config.html)と[tokio-postgres-rustls](https://docs.rs/tokio-postgres-rustls/latest/tokio_postgres_rustls/)を確認しました。SigV4 query署名は[AWS公式Rust RDS例](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/rust_rds_code_examples.html)、15分tokenと既存sessionの区別は[RDS IAM DB認証](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html)を根拠にしています。PEMは保守終了のrustls-pemfileを使わず、[rustls-pki-types PemObject](https://docs.rs/rustls-pki-types/latest/rustls_pki_types/pem/trait.PemObject.html)を使います。
