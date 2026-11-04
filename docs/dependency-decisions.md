# 依存と実行backendの判断（T02）

## K04追加: transactionalな操作台帳

2026-11-02、`rusqlite = 0.41.0`を版固定して採用しました。続く環境固定の指定により、default featuresを無効にし、範囲検証付き整数変換の`fallible_uint`と、SQLite同梱sourceを使う`bundled`を有効にしています。`libsqlite3-sys 0.39.1`に含まれるSQLite 3.54.1をコンパイルします。独自FFIや独自transaction実装を増やしません。Cargoの解決・ビルドはローカルcacheのみで実施し、新しいcloud接続はありません。

直接crateとnative bindingのMITライセンス、Rust最低版、transaction/型変換の契約はcache内の配布sourceで確認しました。lockfileには依存を固定しています。当初のK04は`/usr/lib/libsqlite3.dylib`へリンクしましたが、現在は同梱SQLiteへ変更し、OS付属版には依存しません。[Rust/miseとSQLiteの固定](build-environment.md)を参照します。他OS向けのbuild・配布確認は今回行っていません。

採用目的はdispatch前記録、desired head CAS、operation version、複数recordのatomic更新です。SQLiteを内部台帳に使うことは保護対象DBとしてSQLiteに対応したという意味ではありません。操作台帳の保存・上限・schemaと未実装のbackup/upgradeは[台帳仕様](core/operation-ledger.md)へ記載します。

確認日: 2026-11-02。Cargo.toml/Cargo.lockの編集は統合担当が行います。以下は公開一次資料とローカル版表示に基づく選定で、解決済みの正確な版・transitive依存・ビルド結果はCargo.lockと検証記録を正とします。

## 1. AWS inventoryはCLI adapterを採用する

初期のAWS構成読取は、既存AWS CLI v2をRustの`Command`引数配列で起動するadapterとします。独自SigV4 HTTP実装や`aws-sdk-rds`/`aws-sdk-ec2`の大きなgenerated依存を初期buildへ持ち込む必要がなく、公式APIのJSONを正規化する責務に集中できます。SDKの重さの比較計測は未実施であり、性能差を実測した判断とは扱いません。CLIのインストール・版管理は外部依存として明示します。

ローカル確認は`/opt/homebrew/bin/aws --version`のみで、`aws-cli/2.36.50 ... source/arm64`でした。AWS認証・API・トークン生成は実行していません。実運用版はT16でも確認し、取得したCLI版を証拠へ記録します。公式`latest`ドキュメントと手元CLIの完全一致は未確認です。

| 許可する固定操作 | 必須の限定入力 | JSON配列キー |
| --- | --- | --- |
| rds describe-db-proxies | db-proxy-name | DBProxies |
| rds describe-db-proxy-targets | db-proxy-name、target-group-name | Targets |
| rds describe-db-proxy-target-groups | db-proxy-name、target-group-name | TargetGroups |
| rds describe-db-instances | db-instance-identifier/ARN | DBInstances |
| rds describe-db-parameters | db-parameter-group-name、必要parameter名 | Parameters |
| ec2 describe-security-groups | group-ids | SecurityGroups |

根拠: [proxies](https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-proxies.html)、[targets](https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-proxy-targets.html)、[target groups](https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-proxy-target-groups.html)、[instances](https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-instances.html)、[parameters](https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-parameters.html)、[security groups](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html)。Proxy系の汎用`--filters`は未対応なので利用しません。

全呼出しで`--region`、`--output json`、`--no-cli-pager`、`--no-cli-auto-prompt`、有限のconnect/read timeoutを固定します。shell、任意subcommand、利用者指定`--query`/endpoint/debug/no-verify-ssl等の引数転送は使いません。OSプロセス全体にも期限、stdout/stderrのbyte上限、kill/waitによる回収を設けます。ページングを途中で止めた結果はpartial扱いにし、全件取得と報告しません。[CLI global options](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-options.html)。

`AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true`で共有config/envの独自endpoint指定を無視する方法が公式にあります。承認済みprofileの既存credential chainは利用できますが、`credential_process`は外部プロセスを実行し得ます。inspectの認証処理にその副作用があることを明記し、今回のfixture試験では実CLIを起動しません。秘密のconfigを読み出して複製せず、stdout/stderr全文や資格情報を保存しません。[endpoint設定](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-endpoints.html)、[credential_process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)。

adapter境界は固定要求とbounded結果を受け渡す最小の`CommandRunner`等とし、fixtureで差し替えます。将来のSDK実装でも同じ正規化snapshotを返せればよく、汎用plugin機構は作りません。CLIの存在確認・process制御・JSON正規化の試験と、AWS実API成功は別の検証です。

## 2. Rust依存の採用判断

| 目的 | 候補と確認版 | 判断 |
| --- | --- | --- |
| CLI | clap 4.6.7 | deriveを必要範囲で使用 |
| 型/JSON | serde 1.0.229、serde_json 1.0.154 | strict型、未知field拒否、JSON証拠 |
| YAML | serde-saphyr 2.0.0 | 採用。重複拒否とderive deny_unknown_fields、byte上限を組み合わせる |
| async/process/期限 | tokio 1.54.1 | 必要featureだけ。processのbounded収集・取消しを含む |
| PostgreSQL | tokio-postgres 0.7.18 | 型付き接続設定、protocol制約と明示的TLS |
| PostgreSQL TLS | tokio-postgres-rustls 0.14.0 + rustls 0.23.46 | ring providerを明示。検証無効化を通常APIへ出さない |
| MySQL | mysql_async =0.37.1（K08） | MIT OR Apache-2.0。default feature無効、minimal-rust／rustls-tls／ring／tls12だけを選択。CA／hostname検証・TLS必須・socket fallback無効を固定 |
| PEM証明書 | rustlsが公開するrustls-pki-typesのPemObject | rustls-pemfileの追加依存を使わず、bounded bytesからCertificateDerを取得 |
| エラー | thiserror 2.0.21 | 内部エラーを固定理由コードへ変換 |
| digest | sha2 0.10.9 | 採用。manifest整合性用で署名ではない |
| 一時領域試験 | tempfile 3.27.0（dev） | 新規証拠保存・symlink/権限の試験 |

確認版はcrates.io公開metadataと著者公開Rustdocで確認しました。公開metadata上のMSRVはtokio-postgres/clap/tokioが1.85、serde-saphyrが1.89、rustlsが1.71で、手元Rust1.98.1以内です。依存解決後のtransitive MSRV・platform対応はローカルbuildで確認します。

公式一次資料: [tokio-postgres](https://docs.rs/tokio-postgres/0.7.18/tokio_postgres/)、[TLS adapter](https://docs.rs/tokio-postgres-rustls/0.14.0/tokio_postgres_rustls/)、[rustls](https://docs.rs/rustls/0.23.46/rustls/)、[clap](https://docs.rs/clap/4.6.7/clap/)、[Tokio](https://docs.rs/tokio/1.54.1/tokio/)、[Serde](https://docs.rs/serde/1.0.229/serde/)、[serde_json](https://docs.rs/serde_json/1.0.154/serde_json/)、[sha2](https://docs.rs/sha2/0.10.9/sha2/)、[thiserror](https://docs.rs/thiserror/2.0.21/thiserror/)、[tempfile](https://docs.rs/tempfile/3.27.0/tempfile/)。

### YAMLの選択条件

`serde_yaml`と`serde_yml`は公開crate文書でunmaintainedとされ、新規採用しません。当初選んだ`serde_yaml_ng`も、transitiveな`unsafe-libyaml`がunmaintainedと監査で判明したため採用を変更しました。`serde-saphyr` 2.0.0のtyped deserializationを採用し、重複キーは既定のerror policy、未知fieldはSerdeのdeny_unknown_fieldsで拒否します。byte上限、単一document、anchor/alias/tag拒否の既存契約と境界回帰を維持します。ライブラリ変更だけで入力の安全性を保証せず、制限値とエラー非出力を試験します。[unsafe-libyamlのRustSec通知](https://rustsec.org/advisories/RUSTSEC-2024-0449.html)、[serde-saphyr一次資料](https://docs.rs/serde-saphyr/2.0.0/serde_saphyr/)。

CFN生成のローカル試験は同じparserから`serde_json::Value`へ読み込みます。CFNの`!Ref`等のintrinsic tagを含むtemplateがparseできることと、必要resource・IAM/TLS・SG分離・既存DB非取込の検査を維持します。これはCloudFormation service側のschema検証やdeployment成功の証拠ではありません。

### driverとTLSの選択条件

K08ではMySQL protocolをPG driverへ流用せず、`mysql_async =0.37.1`を追加しました。ロックファイルへ28 packageを追加し、既存rustls／ringを共有しています。default featureを外し、native TLS、任意LOCAL INFILE handler、socket fallbackを使いません。指定CAだけと元のProxy hostnameでTLSを必須にし、token付き接続設定は外へ出しません。実driverのloopbackでTLS非対応・未知CA・hostname不一致が認証データ送信前に拒否されることを確認しました。実MySQL/RDS互換性は未確認です。[SslOpts](https://docs.rs/mysql_async/0.37.1/mysql_async/struct.SslOpts.html)、[OptsBuilder](https://docs.rs/mysql_async/0.37.1/mysql_async/struct.OptsBuilder.html)、[K08の実装境界](core/k08-mysql.md)を参照します。

tokio-postgresの`ssl_mode`既定はpreferなので、正規probeでRequireを明示します。`ssl_negotiation`既定はpostgresで、Proxyに合わせ通常方式を明示固定します。hostとhostaddrを分けられる設定を利用する場合も、ホスト名検証は維持します。[Config API](https://docs.rs/tokio-postgres/0.7.18/tokio_postgres/config/struct.Config.html)。

tokio-postgres-rustls 0.14.0にはdefault featureがなく、ring/aws-lc-rsのprovider選択が必要です。rustlsはTLS1.2/1.3対応です。providerのplatform対応、CA読込、ホスト名不一致/未知CA拒否、通常SSL negotiationをローカルで確認し、AWS Proxy互換性はM3に残します。クエリtimeout後のCancelRequest成功は前提にしません。

### PEMの移行

`rustls-pemfile`はunmaintainedのため取り除き、既に使っているrustlsの`pki_types::pem::PemObject`と`CertificateDer::pem_slice_iter`を使用します。RustSecは同じunderlying parserを提供するrustls-pki-typesへの移行を案内しています。CAファイルのbyte上限・symlink拒否・秘密非出力は独立に維持します。[RustSec通知](https://rustsec.org/advisories/RUSTSEC-2025-0134.html)、[PemObject一次資料](https://docs.rs/rustls-pki-types/latest/rustls_pki_types/pem/trait.PemObject.html)。

## 3. 見送る依存と未確認

- 初期inventoryにaws-sdk-rds/aws-sdk-ec2を入れない。将来変更時はCLI依存・プロセス境界との比較を実測し、最小traitの内側で差し替える。
- IAMトークンは既存AWS CLI chain経由かaws-sigv4による署名が候補。今回実際の資格情報取得・トークン生成をしない。公開AWS Rust例は署名方式を示しているが、署名に必要な依存一式の採用を強制するものではない。[AWS Rust例](https://docs.aws.amazon.com/code-library/latest/ug/rust_1_rds_code_examples.html)。
- 独自暗号、独自PostgreSQL wire protocol、汎用プロキシ、外部IaC library、常駐daemonは追加しない。
- 各crateの直接licenseは公開metadataで確認できるが、transitive全体のlicense/advisory監査は未完了。解決済みlockfileへの監査結果を別記録にする。
- 資格情報を必要としないCargo取得/buildは実装検証の範囲。AWS API・SSO login・profile列挙/秘密読取・公開/pushは今回の範囲に含めない。
