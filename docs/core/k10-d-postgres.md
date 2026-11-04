# K10-D：PostgreSQL取得・正規化と共通の実効状態評価

更新（2026-11-03）：[EC2 source・AWS PG取得/GCP実行接続の続編](k10-native-source-execution.md)を追加しました。以下は本単位の完了時点の記録と当時の未実装・検証結果を保持します。現在の対応範囲・残差は続編を参照します。

2026-11-03。既存DBを移し替えず保護する本体のため、**GCP Cloud SQL PostgreSQLの取得処理を、K10-B/Cの受入基盤と純粋な評価v2へ接続**しました。単一crate/CLIのモジュラーモノリスを維持しています。今回の実行はmacOS上のローカル検証だけです。実GCE/Linux、実Proxy、実Google token、実Cloud SQLとの接続確認は行っていません。

## 実装した範囲

| 箇所 | 責務 |
| --- | --- |
| `adapters/source/postgres_native.rs` | 固定metadata/SQLAdmin読取り、固定版・SHAを確認したProxy、private Unix socket、新規PG接続、カタログの固定SQL読取り |
| `adapters/source/postgres.rs` | 秘密値を含まない選択結果、SQLSTATE/失敗段階、対象世代・認証主体・TLS区間・実効ACLの正規化 |
| `adapters/source/collector.rs`, `gce_host.rs` | Cのroot host profileから呼出し、context/署名と照合後にclaim化し、sealed verifierからBへ受入 |
| `core/evidence.rs`, `core/admission.rs` | 元の受入期限・capture時刻・build/epochを確認済み型に保持。現在の台帳とartifactを再読取するoffline評価の組立て |
| `core/state_v2.rs` | policyからの必須行生成、独立したassurance、層/対照の用途、部分成功・履歴・矛盾・有限Pending・全体集計 |
| `core/state.rs` | v1/v2で同時刻の選択規則と集計を共有。v1証拠のv2への昇格はしない |

既存依存と標準機能を使い、Cargo依存を増やしていません。coreからSSH/SQLite/provider/CLIへの依存はありません。v1のpolicy/plan/change/approvalのhashと既存readerを維持します。新しいpermission inventoryは省略可能で、旧claimのserialize時に余分なfieldを足しません。

## 認証・対象・取得の境界

初期producerはCのroot管理GCE Linux host profileと、Cloud SQL PostgreSQL **16.15・東京・private IP・native connector**に限定します。

1. 登録VMのmetadataから、明示したサービスアカウントのAPI用tokenとDB login用tokenを取得します。固定metadata origin、Metadata-Flavor、応答サイズ/長さ、期限/型を確認します。ADC/gcloud/管理者資格情報のfallbackはありません。
2. 固定HTTPS originのSQLAdmin `instances.get`を前後で読み、project/name/region/connectionName/createTimeの世代fingerprint、PG major、固定private IPを照合します。SQL sessionのversionも160015へ照合します。
3. 固定path `/usr/local/libexec/cloud-sql-proxy`のroot所有・親directory・SHA-256と版 **2.26.3** を確認します。build metadata付きの同版も、設定へ固定したSHAと一致する場合だけ受け付けます。install/download/設定変更を実行しません。
4. ProxyにはAPI用/DB login用tokenを、環境を消去した子processの専用環境変数で渡します。argv/ファイル/資料へ保存せず、stdout/stderrも資料化しません。SQLAdminのAuthorization headerはcurlのstdinです。
5. `/run`以下に排他的に作るroot private directoryのUnix socketを使います。clientからProxyまでのprivate IPCと、ProxyからCloud SQLまでのTLSを分けます。

Proxyのtoken/login-tokenと環境変数の仕様、TLSの契約は[固定版の公式command資料](https://github.com/GoogleCloudPlatform/cloud-sql-proxy/blob/v2.26.3/docs/cmd/cloud-sql-proxy.md)に基づきます。外部toolはApache-2.0の既存OSSで、配布物を今回追加していません。metadataのscope要求は[Googleのmetadata仕様](https://docs.cloud.google.com/compute/docs/metadata/querying-metadata)に従います。実VM側のscope/権限が満たされることは今回未確認で、取得不能を別資格情報で補いません。

collector configの既存schema 1/`postgres`省略時のbytesは変えません。PG取得にはschema 2と次の追加項目が必要です。これは既存configへの追加項目で、単独で有効なcollector configではありません。

```json
{
  "schema_version": 2,
  "postgres": { "proxy_sha256": "配置済みの許可binaryのSHA-256" }
}
```

config bytes/build/binaryの変更はsource snapshotのdigestとpolicy参照へ反映が必要です。既存source/approvalを暗黙更新しません。既存の内部API `capture_and_admit_gce`の明示read許可が必要で、今回そのnative呼出しはしていません。

## 正規化と評価

- **接続**：PG sessionの成立をAllowedとして保持します。後段のcatalog/metadata読取りに失敗しても、成立した接続をUnknownへ隠しません。ただし対象・主体などのassuranceが不足すれば、そのAllowedだけで保護成立とはしません。
- **拒否原因**：credential、instance metadata、Proxy起動、PG接続、catalog、deadlineを分け、SQLSTATEだけを選択します。生のエラー文を保存しません。28000/28P01、TCP timeout/RST、APIやtokenの取得不能を、確認済みIAM拒否・NOLOGIN・RouteBlockedへ読み替えません。失敗段階が分かっても原因が特定できなければUnknown/Unclassifiedです。[PostgreSQL 16のSQLSTATE](https://www.postgresql.org/docs/16/errcodes-appendix.html)
- **対照**：TargetHealthは別のrecovery sourceでも用途を限定して参照できます。同sourceの到達性や資格情報の対照へ流用しません。Deniedの成立には許可された層と対応するnative decision、適切な対照が必要です。
- **TLS**：native route→DBの暗号化/CA/相手先確認は、許可した固定Proxy・対象照合・成立sessionというrecipeから評価します。これはcollector/OSを信頼するrecipeの保証であり、通信packetの独立観測ではありません。`pg_stat_ssl`のssl=true単独ではTLS検証成立へ昇格しません。private IPCは別行です。
- **SQL**：repeatable-read/read-only transaction、固定search_path、statement/lock timeoutを使い、終了時はrollbackします。session/current user、login/対象objectのOID、USAGE/SET可能なrole contextと実効ACLを読みます。顧客行や任意SQLを実行しません。DB CONNECT、schema USAGE、table SELECT/INSERT/UPDATE/DELETE、role USAGE/SETが初期範囲です。table/columnの権限、PUBLIC・継承・SET可能roleを考慮し、role一覧上限128を超えればAbsentを証明しません。routine等はUnknownです。[権限照会関数](https://www.postgresql.org/docs/16/functions-info.html)
- **所有差分**：owned deltaの回収と現在の実効ACLを別effectにします。旧receiptにOID/世代の根拠がなければ、同名再作成後の所有回収根拠へ昇格しません。ACLのPresentは、RLS・trigger・業務transactionの成功の証明ではありません。
- **必須行**：policyから接続/直通拒否、SQL、TLS/IPC、binding、session/lease等を生成します。producerがないRuntimeBindingや必要なeffectを、集計から落としません。schema v1の要件生成・旧権限回収チェックを内部で再利用し、証拠はv2だけを評価します。

`core::admission::evaluate_admitted_change`はローカル台帳・archiveを再読取りし、trust/build/元の期限/資料の整合を再確認してから共通評価へ渡します。native tool起動、新token取得、capture時刻の更新はしません。cachedな確認済み型も元の期限後はcurrent evidenceになりません。純粋評価器は外部のtrust headを読めないため、現在のstatusに使う際はこの組立てを通します。

## 有限Pending

`PermissionRemovalV2::from_approved_change`は、正確なPreparedChange・approval・operation、Allow→Denyの親子関係、固定addressと期限を確認します。評価時には、同scopeの受入済みの完全なpermission inventoryの前後差分、変更前Allowed、変更後Allowed、鮮度・assuranceを照合します。一つのowner bindingの削除だけではPendingを出しません。期限後は、資料が失効していてもNeedsAction/FailedPartialとなります。

**GCP全体の関連IAM permission inventoryを収集するnative producerは今回追加していません。** そのため今回のPG producerだけから伝播Pendingは生成されません。現在Allowedと不足を示します。完全な入力を用いた分岐と期限処理は、合成証拠でローカル検証しています。offline組立ての通常経路はpermission removalなしで評価し、この前提を偽装しません。

## ローカル検証と残る範囲

証拠は`runs/core-k10-d-local-20261103-1/`に保存します。最終`mise run check`は**446成功・0失敗・2件ignored（45 suites）**。fmt/Clippy（警告をerror扱い）も通過しました。log、source hash、版/build、集計は`summary.json`を参照します。

- PostgreSQLドライバーをloopbackの模擬PG protocol serverへ接続し、固定SQL・read-only/repeatable-read・rollback、識別子へのSQL文字列の非連結を確認。
- テスト専用鍵での署名付き合成PG reply→sealed verifier→実ローカルSQLite/RunWriter受入→offline共通評価を確認。Google発行実token/実PGへの確認ではありません。
- 独立assurance、TLS確認不足、一般loginエラー/metadata失敗、完全/不完全SQL一覧、所有差分の分離、部分Allowed、重複/矛盾、失効と旧scope、目的別対照、有限Pending/期限/不完全差分を確認。
- 元のTCP試験はhost policyがRSTを返すという前提を除き、実loopback接続とnative error種別の決定的な分類を分けて確認。原因不明の拒否をRouteBlockedへ昇格しない条件は維持。
- v1互換性、coreの単独コンパイル、K09の書込みgate、既存GCP/AWS/PG/MySQLのローカル回帰を確認。

現在の実機で、直通拒否を特定するnative境界記録、登録NOLOGIN等を裏付ける完全な拒否recipe、全IAM権限inventory、実runtime bindingは取得していません。該当条件はUnknownです。取消し/SSH途絶等でsource/contextの受入条件そのものが成立しないcaptureは、完了済み証拠として受け入れません。

**残りはK10-EのAWS PostgreSQL→MySQLのsource/normalizer、K10-Fの利用者向けobserve/state/statusとnative executor接続です。** K11の実アプリruntimeも残ります。v2 native dispatchは引き続き停止します。追加フィジビリティ、クラウド操作、実DB操作、配置/権限変更、公開、commit/pushは行っていません。
