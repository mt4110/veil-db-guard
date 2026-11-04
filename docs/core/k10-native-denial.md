# K10：GCP接続認可ログ候補とoriginの未確認境界

2026-11-03継続更新: Cloud Logging APIによる取得の認証と、個々のentryを実際に生成したproducerの裏付けを分けました。**Cloud SQL connect監査ログは選択候補として保持しますが、Denied/PermissionDeniedやnative boundary decisionへ昇格しません。完全なfield一致と現在の健康接続があっても、この経路はUnknownです。** `NativeLogOriginUnconfirmed`で不足を表示します。[管理TLS境界と直接PG NOLOGINの設計・実装](k10-trust-and-denial-design.md)のNOLOGIN recipeは、固定PG serverの直接応答と独立Recovery catalogに基づく別経路です。

根拠は公式[entries.write](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/write)と[LogEntry](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry)です。write requestはlogNameとLogEntryを入力として受け、logNameの例に`cloudaudit.googleapis.com%2Factivity`を含み、protoPayloadの対応型にAuditLogを記載しています。[Audit Logs overview](https://docs.cloud.google.com/logging/docs/audit)の、Cloud Audit Logsが書いたentryはimmutableという説明だけでは、同じlog IDやfieldを持つ候補のproducerをこのcollectorが検証したことになりません。provider専用のwrite境界またはproducer署名の検証根拠は今回確立できていません。実際に偽entryを書けると実測した意味ではなく、現在の実装がoriginを裏付ける材料を持たないという制約です。

変更履歴: 以前の実装はfield一致した候補をConnectionAuthorization/PermissionDeniedへ正規化していました。この判断を撤回し、取得・選択・保存は維持しつつ判定をUnknownへ修正しました。以前のローカル合成試験の成功はproducer originの証明ではありません。

`adapters/source/denial.rs`は、GCE root host collectorからのCloud SQL PostgreSQL native connector接続失敗について、その試行の条件へfieldが一致するCloud Logging候補を取得・選択します。単一Rust crateのsource adapter内に実装し、coreからネットワークへ依存を追加していません。今回の実行はローカルの合成応答だけで、実Cloud Logging・実GCE・実Proxy・実DBの動作確認は含みません。

## 候補の取得・選択条件

既存の登録済みCloud SQL PG16.15・東京・private-IP・固定Proxy v2.26.3・SHA256確認済みprofileを使います。追加のログ取得は次の明示的なconfigを登録した場合だけ有効です。旧configでは省略でき、falseはserialize時に省略されるため既存config bytesを維持します。

```json
{
  "schema_version": 2,
  "postgres": {
    "proxy_sha256": "配置済みの許可binaryのSHA-256",
    "collect_connect_denial_audit": true
  }
}
```

この断片は完全なcollector configではありません。実際にはcontext/endpoints等が必要です。登録snapshotのconfig digestとcollector buildを更新せずに、旧登録へ追加readを暗黙適用しません。コードはログ読取権限の付与、collectorの配置、Cloud Audit Logの設定変更を実行しません。

1. 既存の固定metadata originから、登録されたsource SAの短期API tokenとIAM login tokenを取得します。ADC・管理者・別SAへのfallbackはありません。
2. 同じAPI tokenによるSQLAdmin instances.getの前後読取りで、対象project/name/region/createTime世代・private IP等を照合します。metadataアクセスも失われて対象が確認できなければUnknownです。
3. 接続試行ごとに新規のprivate Proxy processへ、request nonceとcase idから作るSHA256 markerを`--user-agent=veil-observe/<hash>`で渡します。token・生nonce・SQL・DSNはmarkerへ含めません。固定版Proxyの[公式command資料](https://github.com/GoogleCloudPlatform/cloud-sql-proxy/blob/v2.26.3/docs/cmd/cloud-sql-proxy.md)は追加user-agentのflagを定義しています。
4. 新規接続が失敗した場合に限り、固定HTTPS `https://logging.googleapis.com/v2/entries:list`へ限定した読取りを一度行います。project、resource、SA、marker、接続試行の時刻窓をqueryへ束縛し、最大16件・65536bytes・5秒で打ち切ります。[公式entries.list](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list)は取得用POSTと必要なログ閲覧権限を定義しています。Bearer tokenは環境を消去したcurlのstdin headerだけに渡します。
5. 生のログ本文やエラー文を資料化せず、既知fieldから次の全条件を確認します。
   - `google.cloud.audit.AuditLog`、`cloudsql.googleapis.com`、method `cloudsql.instances.connect`。
   - `principalEmail`と`principalSubject`が登録SAと一致し、impersonation/delegation chainがないこと。
   - `resourceName`とauthorizationInfoのresourceが対象native resourceと完全一致。
   - status code 7、authorizationInfoが厳密に一件でpermission `cloudsql.instances.connect`、granted=false。
   - callerSuppliedUserAgentに当該caseのmarkerが独立したtokenとして存在し、callerIpが登録GCE hostのSSH IPと完全一致し、ログtimestampがその試行の窓内にあること。
   - 対象projectのAdmin Activityログであること。公式[Cloud SQL audit logging](https://docs.cloud.google.com/sql/docs/postgres/audit-logging)はconnect methodとpermissionをAdmin Activity/ADMIN_WRITEへ分類しています。
6. sourceのidentity/context/build/configを検証する既存のsealed verifierを通しても、候補のproducer originは未確認です。NewConnectionsはUnknown/Unclassifiedを維持し、principal・route・transport・completenessは`NativeLogOriginUnconfirmed`です。native boundary decisionの補助claimや参照は生成しません。sourceの署名・時刻やSQLAdminによる対象世代の確認は、その限定した取得事実として別々に保持します。

同markerの成功をqueryで除去しません。返ったentryに異なる認可結果、別主体・対象、欠けた情報がある場合や、paginationが残る場合はUnknownです。配信遅延、権限不足、サイズ制限、取得不能でも再試行や資格情報fallbackをせず、capture内の不足として扱います。実際のPG接続成立を観測した場合はAllowedを保持し、ログ由来の拒否で上書きしません。

## 保証の境界と非対応

`callerSuppliedUserAgent`は[公式AuditLog型](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog)で非認証情報と定義されています。marker自体は主体証明ではありません。source identityは署名済みGCE token/contextで確認しますが、HTTPSで取得したAuditLogのprincipal/callerIp/resource/status等は、origin未確認の候補fieldとして扱います。fieldの一致数を増やすことでproducer認証へ読み替えません。API呼出しのegressが登録SSH IPと異なる構成、共有NAT、redactedなcallerIpでは候補選択自体も不成立です。

- このrecipeは`cloudsql.instances.connect`だけに対応します。instances.get/connectSettingsの403、一般的なPERMISSION_DENIED、SQLSTATE 28000/28P01、IAM認証失敗の文面だけをconnect/login認可拒否へ昇格しません。
- 直接PG16.15 NOLOGIN応答は、固定severity/code/file/routine/role文面の組合せと、独立登録Recovery observerによる[rolcanloginとOID](https://www.postgresql.org/docs/16/view-pg-roles.html)を必要とする別recipeです。一般SQLSTATEだけの推測や管理者fallbackは追加しません。
- Connector必須化のconfig readbackとTCP timeoutだけで、当該sourceのnative route拒否を証明しません。direct-pathのRouteBlocked producerは非対応です。
- IAM login権限の拒否、AWS拒否、委譲・impersonation、ログに必要fieldがない環境は非対応です。これらをK10全体の保護成立や実環境検証済みに含めません。
- Google HTTPSでLoggingの返答を取得した事実は、元の認可decisionのproducer保証やProxy→DB区間のTLS証拠を作りません。

## ローカル検証

専用テストは、exact nonce/case marker・SA・resource・permission・時間・Admin Activity log一致、別主体/別IP/別resource/別permission、granted=true、古いnonce、欠損marker、mixed success、pagination、duplicate known fields、過大応答、閏日、旧config bytesの互換を確認します。完全一致候補でもUnknown・origin未確認・native controlなしを維持すること、欠けた世代とdeadlineのUnknown、Allowed保持を回帰確認します。sealed verifierとSQLite受入・offline評価の統合検証は全体検証記録と合わせて扱います。

実Google token、実Cloud Loggingの配信とfield充足、実Proxyのuser-agent伝達、実PG、実クラウドでの保護は未確認です。追加フィジビリティ、SSH、install、権限変更、cloud/実DB操作、pushは行っていません。
