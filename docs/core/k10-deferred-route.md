# K10 AWS遅延route証拠の契約とローカル実装

2026-11-03。対象はAWS RDS直通probeに対応する遅延Flow Logs候補の取得・保存・再読取りです。現在の拒否成立を判定するprofileではありません。単一crateのモジュラーモノリス内で、既存のoperation SQLiteとprivate run archiveを使います。

## 時間と信頼の境界

既存のrequest TTL 120秒、capture 45秒、現在証拠の鮮度60秒を変更しません。`observed_at`は元のprobe開始、`probe_finished_at`はその終了、`received_at`は後からCloudWatch応答を受け取ったローカル時刻です。後二者をprobe時刻へ上書きしません。遅延履歴の配信受付期限だけをprobe終了から最大3600秒とし、期限以上の結果は受け入れません。この期限は現行証拠の延命ではありません。

`issue_deferred_probe`は現在有効な既存admissionを`load_admitted`で再検証し、AWS DirectPath case・source/temporal assurance・実取得済みConnectionTupleを要求します。元のrequest・発行nonce・operation/change/policy hash・source snapshot/trust epoch/build・target generationを含むeffect address・TCP 5tuple・probe bundle/admission digest・観測時刻をticketへ固定します。privateな`DeferredProbeTicket`をJSONから生成する入口はありません。tupleがない既存captureや、source/temporal proofがない入力は`VerifierUnavailable`です。target addressを固定することと、実接続先の世代をnative検証したことは区別します。

AWS source collectorのIPv4 DirectPath診断は、登録snapshotのprivate IPへbindしてからconnectし、成功・refusal・timeout等でも発行元portを含むtupleを保持します。この診断はsealed source captureとして既存受入へ進みますが、raw socketの結果だけで拒否causeやroute assuranceを付けません。socketはprobe終了で解放し、集約全体の保持を主張しません。既存IPv6診断は維持し、失敗時にtupleがない場合は遅延ticketを発行できません。

元のnonceはSQLiteでUNIQUEとし、一つのprobe requestにつき一つの遅延ticketだけを発行します。保存済みticketのbody/digest/nonceを再照合し、archive保存後のreceipt INSERTをIMMEDIATE transactionで一回だけ成功させます。並行・再送はConflictです。ネットワーク待ちの間はtransactionを保持しません。archive成功後にSQLiteが失敗した場合は未参照archiveが残り、admissionや保護成立へ昇格しません。自動削除しません。履歴quotaは4096ticketです。

## 取得と照合

public serviceは`issue_deferred_probe` → `collect_deferred_route` → `read_deferred_history`です。CLI/configへ任意URLやverdictを渡す経路を増やしません。

`AwsDeferredRouteProducer`はtyped `CloudWatchFilterLogEvents` portを使い、東京regionの明示log groupとinterface ID、元probeのIP/port/protocol=6を固定したFilterLogEvents要求を作ります。最大4page、各page最大256KiB、合計128eventです。native curl transportは既存の128KiB/5秒上限をさらに適用します。元probeの前後へ広げる検索範囲は集約候補を見つけるためだけであり、capture/現在鮮度の範囲ではありません。

`NativeCloudWatchClient`はsnapshotに明示されたmetadata IAM actorだけをIMDS/STSで認証し、固定`logs.ap-northeast-1.amazonaws.com`へSigV4 JSON POSTします。資格情報はstdinのcurl configへ渡し、argv・環境・archiveへ出しません。SDK/profile/environmentの資格情報fallback、権限変更、logging有効化、collector配置はありません。snapshotにmetadata IAM actorがない場合は未対応です。このclientがcontrollerから動いたことを、probe sourceで動いたnative collector証明とは扱いません。

client生成時にもprobeと設定を渡し、log group・interfaceを含む固定filter・検索windowを保存します。page token以外を変えた要求はclient側で拒否します。public APIの組合せは`DeferredRouteStore::open`、`NativeCloudWatchClient::for_probe(probe, &config, cancellation)`、`AwsDeferredRouteProducer { transport, clock, config }`です。

Flow Logs v2の固定14field、status=OK、TCPの正方向5tuple、account/interface、集約開始/終了、packets/bytesを照合します。集約長600秒以下、probeとの候補範囲60秒以内、受信時刻より未来でないことを要求します。この60秒は候補検索の許容幅であり、native clock精度を検証できたとの主張ではありません。version違い、SKIPDATA/NODATA、型違い、tuple違い、期限切れ等は受け入れません。raw messageやAPI資格情報は保存せず、選択済みfieldと元eventのdigestをarchiveします。flow aggregateは正確な単一packetや一試行の証明ではありません。

actionでREJECTだけを抽出しません。同じtupleのACCEPT候補も保存し、両者の数をreceiptへ表示します。元probeのAllowedは`probe_was_allowed`へ保持します。現在有効な同じeffect addressのAllowed factsがserviceへ渡された場合はそのadmission/claim参照を`current_allowed_claim_refs`へ残します。後から新しいAllowedが得られた場合も、通常の現在評価がそれを独立に扱い、遅延履歴は上書きできません。

`scan_complete`は固定queryのpage走査が末尾へ達した意味だけです。ログ配信完了、native経路の全網羅、拒否成立ではありません。token反復やpage上限ではfalseとし、duplicate eventはdigestで重複排除します。API error JSONを空event成功へ変換しません。

## 成立させていない保証

全receiptへ次の制限を常に付けます。

- `NativeLogOriginUnconfirmed`: HTTPS/SigV4とfield一致だけでは、保存されたlog payloadのAWS生成元を証明しません。
- `AggregateCannotAttributeSingleProbe`: 集約eventとnonceをnativeに結び付ける仕組みはありません。nonceはローカル記録のsingle-useとscope固定に使います。
- `SourcePortReuseNotExcluded`: 元socketを集約範囲全体で隔離した実証はありません。送信元port再利用や別試行を除外できません。
- `HistoricalOnly`: 元の拒否候補は過去の事実候補であり、現在の閉鎖を証明しません。

この型にはVerified、RouteBlocked、NativeBoundaryDecision、VerifiedObservationFactsへの変換がありません。現在のstate evaluatorやnative write gateはこのreceiptを入力として受け取りません。native delayed-denial source execution profileは**Unsupported/Unknown**です。固定JSON client・port・parser・ledger・archiveがあることと、元sourceで遅延native拒否を実証したことは別です。K11のconsumerはこの履歴をclosure許可へ使えません。

## ローカル検証の範囲

`adapters::source::deferred_route::tests`は実SQLite/RunEvidenceArchiveとfake native API応答を使います。既存current admissionからのticket発行、非同期page取得、archive再読取り、nonce再利用、期限切れ、5tuple不一致、operation/change/source/target generation/portのSQLite記録改ざん、archive改ざん、duplicate token/event、API errorの空成功化防止、ACCEPT保持、元Allowed/現在Allowed保持を検証します。local loopbackの実refusalからtupleが残ることも検証します。source verifier自体は明示的なsynthetic verifierです。

実AWS、IMDS/STS/CloudWatch呼出し、実ログ配信、実DB、source配置、権限・設定変更は行っていません。native JSON clientのコード実装とfake応答テストを、実環境での遅延証拠取得成功に数えません。

今回の統合時点で`cargo test --locked --offline`は**620成功・0失敗・実DB用2件ignored（48 result groups）**、遅延route専用は7成功です。fmt checkとall-target Clippy（`-D warnings`）も成功しました。[検証summary](../../runs/core-k10-deferred-local-20261103-1/summary.json)と[テスト出力](../../runs/core-k10-deferred-local-20261103-1/test.log)に保存しています。統合中に見つかった型不一致と、kernel profile追加に伴うfixtureの不足・source snapshot参照の古さは、判定条件を弱めず修正しました。
