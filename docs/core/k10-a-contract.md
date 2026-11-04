# K10-A：source参照・証拠/評価契約の型とv1互換性

更新（2026-11-03）：[EC2 source・AWS PG取得/GCP実行接続の続編](k10-native-source-execution.md)を追加しました。以下は本単位の完了時点の記録と当時の未実装・検証結果を保持します。現在の対応範囲・残差は続編を参照します。

更新：続いて[K10-B](k10-b-admission.md)の受入台帳・保存・offline再読取を実装しました。以下はA完了時点の記録で、当時の未実装事項と372成功の結果を保持します。続いて[Cのsource確認とB接続](k10-c-source.md)も実装・L検証しました。当時の次単位はDでした。

2026-11-02。K10-Aを実装し、必要なローカル検証まで完了しました。単一crate/CLIのモジュラーモノリスを維持しています。既存DBを守る導入・失効操作に、対象・主体・source・経路を正しく結び付けるための契約基盤です。**受入台帳、source取得、評価v2の実行はまだ提供していません。**

## 実装した範囲

| 箇所 | 振る舞い |
| --- | --- |
| [`core/source.rs`](../../src/core/source.rs) | policy内source ID、registration ID、snapshot digest、network境界、許可subject/用途。applicationとrecovery/controlを分け、未解決・重複・管理主体のapp source利用を拒否 |
| [`core/policy.rs`](../../src/core/policy.rs) | schema v1/v2を明示分岐。v2はsource_bindingsとevaluationを必須とし、別domainでcanonical hash。source/拒否層の変更は新plan・差分・承認の対象 |
| [`core/evidence.rs`](../../src/core/evidence.rs) | 版付きrequest/wire、EffectAddress、ObservationClaim、独立assurance、用途別control、TLS区間、SQL catalog context、評価v2の入力型 |
| [`adapters/registry.rs`](../../src/adapters/registry.rs) | `capabilities_for_policy`を追加。旧target単独APIはv1のまま。v2のsource証拠を要するactionは新契約・Planned/coverage None |
| [`adapters/qualification.rs`](../../src/adapters/qualification.rs) | v2は`SourceEvidencePipelineMissing`でnative dispatchを停止。callerが保存descriptorをImplementedにしても、現在codeで再判定 |
| [`core/state.rs`](../../src/core/state.rs) | 旧desired/evaluatorの意味を維持。v2を旧scopeや`identity_confirmed`へ縮約して評価する入力を拒否 |

`SourceRegistrationSnapshot`は初期GCE host network境界の**宣言**を表します。VM世代、host key/build/config/network context digest、実行user、trust epoch、metadata限定credential参照をhashへ束縛します。値が一致してもsource上の実行確認にはなりません。snapshotの永続registryとnative/channel照合は後続です。AWS/self-managedのboundary名をpolicyで表現できることも、それらのsource producer対応を意味しません。

安定した`EffectAddress`はsource snapshotの参照を持ち、policyの許可subject一覧や拒否層は含めません。policy revision、観測層、要求する層を別々に保持し、AllowからDenyへ移ったときに過去claimを書き換える構造を避けています。所有SQL delta、現在の実効SQL権限、binding公開、runtime binding、transportは別effectです。

`ObservationBundleWire`のparseはbyte/件数/時刻範囲/重複ID/参照/循環等の**shape確認だけ**です。未知fieldや`confirmed:true`を拒否しますが、正しいshapeのAllowedも未信頼claimのままです。独立sourceのcontrol参照は用途とbundle digestを保持するだけで、到達性や拒否原因の相関を確認した扱いにはしません。

`VerifiedObservationFacts`はprivate fieldとし、Deserializeもpublic constructorもありません。現段階では生成経路を提供せず、v1 bool、hash、snapshot一致、持込wireから確認済み型へ昇格できません。K10-Bでtrusted verifier/atomic admissionの組立てを追加します。nonceは256-bit相当の表現を要求しますが、乱数生成・再利用防止・現在時刻の失効判定はまだ実装していません。

## 使える範囲

[`examples/core-policy-v2.yaml`](../../examples/core-policy-v2.yaml)はoffline計画用の合成例です。snapshot digestは説明用で、登録済みVMの証拠ではありません。出力先は新しいpathを使います。

```sh
mise exec -- cargo run --locked --offline -- guard plan \
  --policy examples/core-policy-v2.yaml --out runs/policy-v2-review-1
```

plan/差分/未実装理由を保存し、`static_qualified=false`・終了code 3を返します。approve/begin/native applyは現在のqualificationで停止します。`apply-gcp`/`apply-aws`は、台帳へlibrary経由で承認を直接登録した場合も、native config/tool読取り前に停止し、operation/stepを変更しません。

v1のsource_bindings/evaluationは空/なしでのみ有効です。旧serializationには新fieldを出さず、v1 hash domainと旧step parametersを維持します。v1を読み込んで新source snapshotやassuranceを補完するmigrationはありません。v2の`guard observe`、受入済みbundleのstatus/state評価、実source登録/配置はまだ利用できません。

## ローカル検証

Rust 1.98.1/macOS ARM64、locked/offlineの`mise run check`でformat、Clippy `-D warnings`、回帰を確認しました。**372成功・失敗0・実DB2件ignored、43 test result**です。K09時点357成功から、K10契約12件、CLI2件、確認済み型をDeserializeできないcompile-fail doctest1件を追加しました。

- K09で保存したGCP PG/AWS PG/AWS MySQLのprepared changeを凍結fixtureとして読取り、policy hash、plan/change検証、serializationを確認。GCPの旧approvalも当時の有効時刻で検証しました。古い承認を現在の実行に使用していません。
- source snapshot・拒否層変更によるhash/parameters/diff変更と、旧approvalのScopeMismatchを確認しました。
- v2の型・参照・件数/TTL・control graphの境界、部分Allowed保持、v1評価器への誤投入拒否を確認しました。
- CLIはPATHをローカルtrapだけへ限定し、v2の承認/native適用が台帳生成/状態変更/tool呼出し前に停止することを確認しました。
- coreをadapter/SQLite/CLIなしでコンパイルする既存architecture試験も通っています。

実行記録は`runs/core-k10-a-local-20261102-1/check-final.log`と`summary.json`です。凍結fixtureの出典は`runs/core-k09-local-20261102-1/cli-smoke/{gcp-pg,aws-pg,aws-mysql}/supported-plan/prepared-change.json`とGCPの`supported-approval.stdout`です。fixtureは合成設定の互換性証拠で、実cloudの成立証拠ではありません。

依存・Rust pin・lockfileの追加変更、追加フィジビリティ、実cloud API、SSH、DB接続、VM/資源作成、公開、commit/pushは行っていません。テストはローカルです。

## 次の単位

**K10-Bの受入台帳**です。request/nonce/source trust epoch/bundle digestのatomicな結付け、artifact保存と台帳commitの順序、replay/破損/持込拒否、trusted verifierからの確認済み型生成を実装します。その後C/Dでsource取得・PG正規化・共通stateへ接続します。A完了を、K10全体や既存DBの実保護成立として扱いません。
