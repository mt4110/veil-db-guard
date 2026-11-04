# K10：残producerの実装と観測できない境界

2026-11-03継続更新: [管理TLS境界と拒否層の設計・実装](k10-trust-and-denial-design.md)へ進みました。旧厳密TLS契約と未対応範囲は維持します。以下は以前の設計・検証の記録です。

2026-11-03。既存DBを守る本体のK10継続です。モジュラーモノリスを維持し、追加依存・追加フィジビリティ・クラウド操作を行わず、source取得、sealed受入、共通stateへ接続しました。K11の既存アプリ切替・RuntimeBinding producerは今回の範囲外です。

**K10全体の完了ではありません。** 下表の限定profileは実装しましたが、元の4項目を全provider・全拒否層で満たしたとは扱いません。特にAWS Proxy内部のCA・hostname検証は、現在の公開interfaceからセッションの証拠を得られません。設定受付・暗号化・client側TLSから、存在しない検証結果を生成しません。

| 元の残項目 | 今回実装したもの | 残る境界 |
| --- | --- | --- |
| 拒否原因 | GCP Cloud SQL `instances.connect`監査ログ候補をnonce/case/principal/resource/IP/timeへ照合。継続レビューでorigin不足を検出し、現在はUnknownを維持 | 継続実装でGCP/AWS PG16.15の直接NOLOGIN＋独立catalogを追加。ログ候補はorigin不足、他の一般SQLSTATE・1045・timeout・403のみはUnknown |
| AWS Proxy→DB TLS | PGのbackend SSL、MySQLの任意current-thread `Ssl_cipher`を選択情報として保持し、CA/hostnameは未確認と明示 | Proxy内部の実CA/hostname検証結果は公開APIにない。全区間TLSのSatisfiedにはしない |
| 関連IAM inventory | GCP Troubleshooter v3betaで固定connectorの3permissionのallow/deny/PABを完全評価できた時だけ実効集合とする。承認済みRevoke台帳と前後集合から有限Pendingへ接続 | 不明なgroup/condition/権限不足/取得失敗はUnknown。AWSの完全な実効IAM集合は未対応。全grant path一覧を取得した意味ではない |
| MySQL negative inventory | account＋全role closureのbounded/repeated SHOW GRANTSでnamed base-table actionのACL不在を判定。署名capture→SQLite受入→共通stateまで接続 | bare role単体、既存session、間接データ到達、同名再作成/ABAは証明しない。未対応grant/metadata不足はUnknown |

個別の取得条件、一次資料、Unknownへ戻す条件は[拒否recipe](k10-native-denial.md)、[GCP IAM inventory](k10-iam-inventory.md)、[MySQL inventory](k10-mysql-inventory.md)、[backend TLS](k10-backend-tls.md)を参照します。旧wireで任意項目がない場合のserde default/skipにより、旧設定・source digestの意味は維持します。producerを有効にする場合は設定digest・collector buildが変わるため、source登録と現在buildの照合が必要です。

## 共通評価と実行の境界

元のbundle/claim/receiptは書き換えません。共通評価器の原因付き拒否に対するTargetHealthは、同じoperation/change/policy/target generationの独立source・subjectで、承認したAllowed rowの現在の健康接続だけを`derived_controls`として報告します。古い成功、矛盾、Unknown、明示的だが無効なhealth参照を自動的に置き換えません。native boundary decision自体がなければ拒否を合格にしません。現在のGCP監査ログ候補には生成元の裏付けがなく、当該boundary decisionを作りません。

Pendingは自由入力のremoval参照から生成しません。Completedの旧Allow operationから作った承認済みRevokeと、単一のDisableNativeIdentity dispatch/receipt、現在のdesired head、native postcondition参照、完全な前後集合の真の縮小、変更前Allowed、変更後の現在Allowedを要します。待機期限は承認とoperation時間上限に束縛した観測予算で、providerの反映時間保証ではありません。旧operationの証拠はbefore参照専用poolへ隔離し、現在row、health、after inventoryへ混ぜません。取消し・不明結果・部分失敗・期限切れ・trust/build変更はPendingを認めず、現在Allowedを隠しません。

この接続に必要だったv2 Revoke profileのdenial requirement複製も修正しました。旧profileと同じ承認済み拒否層を新profileへ引き継ぎ、新しいpolicy/change hashと承認を要求します。

K11のRuntimeBindingが欠ける閉鎖、AWS backend TLS確認が必要な条件などは引き続き安全側で停止します。観測・状態表示の改善を、既存アプリの保護成立やnative操作完了へ読み替えません。

## 検証記録

`runs/core-k10-producers-local-20261103-1/`にbaseline、check log、最終summaryを保存します。実SQLite/archive受入と暗号署名はローカルで動かし、nativeデータと監査・IAM返答は合成資料、MySQL protocolはloopback fake serverです。実GCE/EC2/SSH/Cloud SQL/RDS、実監査ログ配信、実IAM反映、実MySQLの挙動は未検証です。実DB用の既存ignored testを自動実行せず、課金やクラウド資源の作成・撤収も発生させていません。

最終検証: `mise run check`のfmt・Clippy（`-D warnings`）は成功。回帰は**561成功・0失敗・実DB用2件ignored（47 suites）**。Rust 1.98.1 / macOS ARM64、locked/offlineです。[検証summary](../../runs/core-k10-producers-local-20261103-1/summary.json)とcheck logに保存しました。初回チェックポイント後、最新IAM補助claim欠落時に古いcompleteを使わない回帰を追加し、全checkを再実行しました。
