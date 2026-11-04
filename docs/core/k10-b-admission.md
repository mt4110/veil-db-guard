# K10-B：証拠の受入台帳・保存・offline再読取

更新（2026-11-03）：[EC2 source・AWS PG取得/GCP実行接続の続編](k10-native-source-execution.md)を追加しました。以下は本単位の完了時点の記録と当時の未実装・検証結果を保持します。現在の対応範囲・残差は続編を参照します。

更新（2026-11-03）：[K10-C](k10-c-source.md)で、初期GCE root host sourceの署名/context確認・固定collectorとB受入接続を実装しました。以下はB完了時点の記録で、当時の未実装事項と392成功を保持します。当時の次単位はDでした。

2026-11-02。K10-Bを実装・ローカル検証しました。既存DBを守る本体へ証拠を接続するため、発行request・nonce・source snapshot/trust epoch・bundleを結び付けます。**native source verifierとcollector、評価v2/CLI接続はC〜Fに残っています。** 今回の合成verifierの成功は、GCE上の実行やDB保護成立の証明ではありません。

## 構成と信頼境界

| 箇所 | 実装した責務 |
| --- | --- |
| [`core/admission.rs`](../../src/core/admission.rs) | issued request、scope/time/payload/assurance確認、保存→受入commitの順序、offline再読取。外部IOはport越し |
| [`core/ports.rs`](../../src/core/ports.rs) | EvidenceLedger、EvidenceArchive、ObservationVerifier、EvidenceClock。coreからSQLite/SSH/CLIへ依存しない |
| [`evidence_store.rs`](../../src/evidence_store.rs) | source snapshotのCAS登録、OS乱数nonceのrequest発行、SQLiteのatomic受入と原時刻の保持 |
| [`adapters/evidence.rs`](../../src/adapters/evidence.rs) | RunWriterによるprivate archive保存、固定fileのdescriptor基準の整合性読取、system clock、未実装native verifier |

単一crate/CLIのモジュラーモノリスを維持しました。SQLiteは既存OperationStoreのprivate file、application ID/版、sidecar確認、上限、FULL同期transactionを再利用します。evidence用table/versionを追加し、旧operation tableのschema/versionは変更しません。evidenceの`open_existing`は未初期化DBへtableを作りません。

`ObservationVerifier`は静的に組み立てるtrustedなRust portです。外部JSON/configのverdict、任意plugin、`confirmed:true`を受け付ける入口はありません。現在提供する`NativeSourceVerifierUnavailable`は必ず拒否します。native channel・VM identity/token・contextを検証して肯定できる実装はCです。テストだけで合成verifierを注入しています。

artifact payloadは、trusted producer/verifierが選択・redactした資料を渡す内部portです。汎用の秘密検出器やraw payloadの公開import commandではありません。token・鍵・credentialをここへ渡さずmemory内へ留める責務は、後続native producerにもあります。payloadのDebugは内容を出力しません。

## 発行と受入

1. 操作台帳のimmutable change/policyからsource参照・target世代・subject/DB identity・route・SQL scopeを照合します。初期GCE sourceはmetadata主体/不変SA ID/credential参照を一致させ、native SDKへの暗黙fallbackを許しません。
2. OSの乱数から256-bit nonceを生成し、request ID/nonce/digestをuniqueに保存します。期限は最大120秒、未完了の有効requestは最大16件です。期限切れの履歴・nonceを削除したり再利用したりしません。
3. request、bundle、固定case、controllerの送受信/monotonic時間、artifactの件数・digestを確認し、trusted verifierを呼びます。collector buildとverifier buildは別の値として照合し、同じ文字列へ書き換えません。
4. bundle・資料・request/snapshotと最終manifestをRunWriterで保存・同期し、保存後の整合性を読み直します。保存時間を経た現在時刻も再取得します。
5. SQLiteのIMMEDIATE transactionで元のrequest、期限、現在のsource snapshot/trust epoch、verifier buildを再確認し、一つのrequest/nonceへ一つのbundle digestを原子的に受け入れます。

同一payloadの再送も新受入として処理せずConflictを返します。期限内の再評価は`load_admitted`を使い、元のreceipt・観測時刻・期限を保持します。別payloadの競合受入は一件だけ確定します。source更新はexpected digestによるCASと増加するtrust epochを要求し、既存approvalへ新snapshotを差し込みません。同じ物理VMを別registration IDへ重複登録することも拒否します。

既定freshnessはcapture開始の保守的な時間境界から60秒、source/controllerの許容skewは5秒です。保存処理中に期限を超えた場合も受入を拒否します。対象や主体が正しくないもの、未承認のSQL scope、意味の定義されていないNotApplicableによる確認省略は受け入れません。

## 途中停止・破損・再読取

保存後、受入commit前に停止・失敗すると、保存runだけが未受入として残ります。自動削除や成功recordの補完はしません。commit前にsource trustが変更された場合も同じです。新しい台帳へbundleだけを持ち込んでも受入記録がないため、確認済み型になりません。

offline再読取は、ローカル台帳の元receiptと現在のsource trust、許可build、期限、保存したmanifest・bundle・全資料のdigestを照合します。観測時刻や受入期限を更新せず、native verifier、資格情報取得、SSH、cloud APIを呼びません。途中でsource trustが変わった場合に備え、資料読取後にも現在のtrustを確認します。

受入済みのmanifest/bundle/資料/configの欠落・差替えはIntegrityErrorです。保存先のroot/run/fileはprivateな所有権とdescriptorを確認し、symlink、hardlink、FIFOを拒否します。FIFOはnonblocking open後のfile種別確認により待ちません。1 runはrequest/config・bundle・JSON化した資料とmanifestを含め8 MiB以内とし、上限超過は未受入/Partialのまま止めます。observe全体の複数source予算・並列取得は後続C/Fの責務です。

`VerifiedCandidate`はDeserialize/public constructorを持ちません。確認済み候補→保存完了→commit→台帳からのoffline読取を通った経路でのみ`VerifiedObservationFacts`を組み立てます。部分captureのAllowedと、個別assuranceのUnconfirmed/Unsupportedを保持し、受入成功を全必須効果のSatisfiedへ変換しません。

## ローカル検証結果

Rust 1.98.1/macOS ARM64、locked/offlineの`mise run check`でformat・Clippy `-D warnings`・回帰を確認しました。**392成功、失敗0、実DB2件ignored、44 test result**です。A時点372成功から、受入の19試験と候補型のcompile-fail doctest1件を追加しました。v1の保存済みpolicy/plan/change/approval、旧state、K09/K10-Aのnative適用停止、core単独コンパイルも回帰しています。

- 同nonceの再送/別payload、新requestへの古いbundle貼付け、foreign source、SQL scope拡大、未実装verifier、無効な確認省略を拒否。
- sourceのCAS/世代・trust更新、保存とcommitの間のtrust変更、保存中の期限切れ、保存のみ/commit失敗、台帳なし持込を検証。
- 部分Allowed保持、collector/verifierの異なるbuild、freshness失効、元receiptの再利用、16件quotaとexpired履歴保持を確認。
- manifest/bundle/資料/configの欠落/変更、symlink/hardlink/FIFO、archive容量超過を確認。
- 同時受入試験で保存先名の時刻依存による衝突を修正し、修正後20回の再検証でも、nonceごとに一件だけが受入確定することを確認。

試験は[`tests/evidence_admission.rs`](../../tests/evidence_admission.rs)、実行記録は`runs/core-k10-b-local-20261102-1/check.log`・`race-summary.json`・`summary.json`です。すべて合成環境のローカル試験で、実native sourceの認証試験ではありません。

依存・lockfile・Rust pinの変更、追加フィジビリティ、実DB接続、クラウド操作、SSH/collector配置、公開、commit/pushは行っていません。

## 現在使える範囲と次の単位

Bは内部port/APIを提供する段階です。`guard observe`やbundleからのv2 state/statusはまだ利用できず、v2 native dispatchも引き続き停止します。**次はK10-C**で、既存GCE sourceの認証channel・native identity/context・固定collectorをこの受入基盤へ接続します。続いてDでPG正規化と共通実効評価へつなぎます。
