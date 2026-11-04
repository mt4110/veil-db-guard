# K10：AWS Proxy backend TLSの明示的なprovider管理契約

2026-11-03。従来の`verified_tls`は、各TLS区間で暗号化・CA・hostname検証の証拠を要求します。AWS Proxy内部の検証を観測できないことは変わりません。新しい`verified_tls_with_aws_rds_proxy_managed_backend_v1`は、利用者がその境界を承認する別契約です。元の要求を満たしたと読み替えません。

## 契約

schema v2のAWS RDS PostgreSQL/MySQL Proxy profileだけで選択できます。client→Proxyは従来の固定CA・hostname検証を維持し、Proxy→DBは次を要求します。

- 同じcaseの現在のDB側暗号化観測が`true`である。
- EC2 native recipeが、client接続の固定CA・hostname検証、現在のprincipal、対象DB generation、Proxy ARN/endpoint、単一の登録DB target、取得前後のnative metadata一致を確認する。
- policyが`aws_rds_proxy_managed_encryption_v1`を明示的に受容している。

backendの`ca_verified`と`hostname_verified`は常に`null`です。`validation_basis`はprovider管理契約の識別子であり、CAやhostnameを検証した事実ではありません。これはprovider内部のidentity handlingを信頼し、その検証結果の観測を要求しない設計上の選択です。

AWS User Guideは、Require Transport Layer Security設定でProxy→DB接続のTLSを強制すると説明しています。一方DBProxy APIの`RequireTLS`はProxyに入る接続について記述します。この説明の粒度差も踏まえ、`RequireTLS=true`だけではbackend行を満たしません。AWSの公開資料でbackendセッションのCA・hostname検証結果を返すinterfaceや、それらの検証を行う明示的保証は今回確認できませんでした。暗号化と証明書の検証を区別します。

一次資料（2026-11-03確認）：

- [RDS Proxy concepts / Using TLS/SSL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.howitworks.html)
- [DBProxy API / RequireTLS](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBProxy.html)

## 承認・受入・評価

policyの`encryption`がpolicy revision hashとchangeのtransport差分digestへ入り、新しいchangeと承認が必要です。`RequestedCase.backend_tls_trust`は承認policyと完全一致させ、backend Transport caseだけへ付けます。plannerはアプリと独立recoveryの双方へ契約を複製します。collectorが契約を選んで要求を緩めることはできません。

trusted normalizerはnative metadataと検証済みclient接続を確認した場合だけ、backend暗号化観測とrequest契約から`Present`を生成します。受入は発行済みrequestと観測のbasis一致を確認し、評価はdesired契約・観測basis・AWS EC2 native recipeを照合します。元のbundle、claim、receiptを書き換える評価上の昇格は行いません。

暗号化が`null`/`false`、MySQLで追加queryが無効・権限拒否・NULL・型不正・欠落、target/principal/route不一致、期限切れ、build/trust変更なら不足を維持します。CloudWatch集計、client TLS、直接DBへの証明書検査、`RequireTLS`だけで代用しません。

`RequiredEffectV2.backend_tls_trust`と`TransportFact.validation_basis`を報告へ残し、Satisfiedがどの契約の要求を満たしたかを示します。独立recovery、全必須区間、更新後freshness、K11 RuntimeBindingの実行gateは減らしません。

## 互換性と移行

旧policyの`verified_tls`は同じ意味・同じhashです。追加のwireフィールドは`None`/空なら省略するため旧request/claimのserializationを維持します。旧binaryは未知のencryption値・追加フィールドを拒否し、新契約を黙って旧要求へ解釈しません。

移行は、明示的なpolicy変更、新しいplan/changeのレビューと承認、現在のcollector/verifier buildの登録、新しいrequestとcaptureを要します。旧bundleは新policy hashの証拠に転用できません。Revoke profileの複製でもencryption契約を保持し、アプリとrecoveryの要求を一致させます。

ローカル検証は合成AWS metadata・署名capture、SQLite/archive受入、loopback fake MySQL、純粋評価の範囲です。実EC2/RDS Proxy/DBへの接続、provider内部動作、実環境の保護成立は未検証です。
