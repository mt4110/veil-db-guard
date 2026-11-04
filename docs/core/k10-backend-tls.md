# K10：AWS Proxy→DB TLSの取得限界

2026-11-03継続更新: [管理TLS境界と拒否層の設計・実装](k10-trust-and-denial-design.md)へ進みました。旧厳密TLS契約と未対応範囲は維持します。以下は以前の設計・検証の記録です。

AWS RDS Proxyのbackendと、client→ProxyのTLSは別区間です。PGの`pg_stat_ssl`による現在backend SSL、任意選択のMySQL performance schema current-thread `Ssl_cipher`から、取得できた暗号化情報を`TransportFact`へ保存します。MySQLは`mysql.collect_backend_tls: true`を設定した場合だけ追加の固定read-only queryを行います。権限拒否、NULL、型変換失敗、欠落はUnknownです。DB generation、source、endpoint、固定CAによるclient接続の検証は従来どおり必要です。

**暗号化が分かっても、Proxy内部でCAとhostnameを検証した証拠にはしません。** `ca_verified`と`hostname_verified`はNone、backend claimはUnknown、transport assuranceは`unsupported: provider_managed_tls_validation_unobservable`です。区間ごとの実効評価は不足を維持します。これはclient側CA検証の無効化ではありません。

DBProxy APIの`RequireTLS`はProxyへ入る接続の設定です。CloudWatchの`DatabaseConnectionsWithTLS`はbackend接続の集計暗号化指標であり、特定case/sessionのCA/hostname検証証拠ではありません。Proxyを迂回した直接DBの証明書検査でも、観測していないProxy内部の検証を証明できません。このため今回CloudWatch権限や新たなAPI取得を追加していません。

現設計の「その区間のCA・hostname検証を証拠で確認する」を保つ限り、公開interfaceに必要なproducerがありません。解消するには、provider管理の信頼を別契約として認める設計判断、または検証結果を観測できる経路/構成が必要です。いずれも元の要求を満たしたと偽らず、別の設計判断として扱います。

一次資料:

- [AWS DBProxy API](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBProxy.html)：RequireTLSと返却項目。
- [RDS Proxy monitoring](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.monitoring.html)：DatabaseConnectionsWithTLS、debug loggingの用途と制限。
- [RDS Proxy how it works](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.howitworks.html)：client TLSとProxy/backendの区別。
- [MySQL 8.0.43 performance schema実装](https://github.com/mysql/mysql-server/blob/mysql-8.0.43/storage/perfschema/table_status_by_thread.cc)：thread別statusのnullable値。
