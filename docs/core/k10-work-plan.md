# K10 作業設計と受入条件

2026-11-03最終引継ぎ: [K10共通基盤のL受入とK11着手条件](k10-k11-handoff.md)を参照します。root probe/過去ログ/限定IAMの保証scopeを固定し、個別profileのUnknown・未対応は維持しました。次の実装はK11-Aです。以下は前チェックポイントの記録です。

2026-11-03継続更新: [管理TLS境界と拒否層の設計・実装](k10-trust-and-denial-design.md)へ進みました。旧厳密TLS契約と未対応範囲は維持します。以下は以前の設計・検証の記録です。

2026-11-03追記: [残producerの実装と観測限界](k10-producer-gaps.md)でGCP connect拒否・限定完全IAM/Pending・MySQL named ACL不在を共通stateへ接続しました。AWS backend CA/hostname証拠など元の要求の残差は維持し、K10全完了とは扱いません。以下は前チェックポイントの記録です。

2026-11-03更新。[EC2 source・PG/MySQL取得とGCP/AWS実行接続](k10-native-source-execution.md)を実装・ローカル検証しました。A〜Fの初期接続が一巡し、AWS sourceは独立したidentity/channelから受け入れます。GCP PGとAWS PG/MySQLは`source-bound-execution-v3`契約で変更前/後を分け、旧v1/evaluation-v2の読取・hash・承認の意味は維持します。新契約には再plan/再承認が必要です。native拒否・backend TLS・完全なinventory等が残り、全体保護の成立やK10全条件の完了とは区別します。実クラウド・SSH・DB操作や追加フィジビリティ試験は行っていません。

## 1. 今回の設計で解決したこと

| 従来の曖昧さ | 固定した方針 |
| --- | --- |
| source IDを誰が確認するか | 登録snapshotとpolicy v2へ固定し、固定collector・認証channel・native VM identity・network contextをverifierが照合 |
| 最初のsource実装 | 既存GCE Linux VMのroot管理host network境界。一般ユーザーのSSH初期化を信頼しない。app PID／containerまでの保証はしない。VM新設を前提にしない |
| 原因不明の拒否 | 層別claimとcontrolの用途を分け、timeout／RST／一般エラーを原因確認済みにしない |
| 旧stateの単一bool・固定層 | assuranceとEffectAddress／ObservationClaimを分離した評価v2。v1の意味を維持 |
| TLS／SQL／bindingの完全性 | 区間別TLSを必須条件へ。所有deltaと実効権限、handoff申告と実runtimeを分離 |
| 持込bundleの信頼 | ローカルのrequest・nonce・registry・受入台帳へ照合。hash／自己署名だけでは昇格しない |
| K10の終わり方 | source確認済みの部分状態と不足を正しく評価できること。未提供binding等を隠して全体greenにしない |

CでJWT検証の既存pin依存、固定配置path、root host profileとbootstrap情報の取得方法を選定しました。一次資料・license・公告の対象範囲を確認し、暗号演算はringへ委譲します。具体的なsourceへの配置・許可build artifact/権限の登録、実sourceの有無・Linux動作は未確認です。実施していない導入作業を完了とは扱いません。

## 2. 実装順序とファイルの責務

Aの`core/source.rs`・`core/evidence.rs`とpolicy/version/qualificationは実装済みです。Bでは`core/admission.rs`・`core/ports.rs`、`evidence_store.rs`、`adapters/evidence.rs`とRunWriterを実装しました。Cは`adapters/source/*`の固定SSH・Google署名/VM/context確認・Linux collectorとB接続を実装しました。初期profileはroot管理のhost network境界で、実GCE/Linuxは未確認です。[DのPG取得/正規化と共通評価](k10-d-postgres.md)も実装・L検証しました。[E/F](k10-ef-observation-cli.md)のPG/MySQL正規化、取得CLI・offline評価・native前段表示も実装しました。EC2 source/PG・MySQL取得とGCP/AWS実行は続編で接続しました。native拒否・backend TLS・完全なinventory等は残ります。controller／collectorも同じcrate内のmodule・固定commandとして分けます。

| 単位 | 所有する範囲の候補 | 出力・完了条件 | 依存 |
| --- | --- | --- | --- |
| K10-A | `core/source.rs`, `core/evidence.rs`, policy/version読取、state共通部、qualification | source参照を含むpolicy v2、版付き評価契約、claim／assuranceの型、旧v1読取・hash・承認の維持。source参照変更で再planが必要 | K09 |
| K10-B | `core/ports.rs`の受入port、SQLite adapter、RunWriter、`adapters/evidence/*` verifier | request・nonce・trust epoch・bundle digestのatomic受入。未検証wireから確認済み型を作れず、移入・replay・破損が昇格しない | A |
| K10-C | `adapters/source/gce_host*`、固定collector、bounded SSH transport | source VMの登録・channel・identity token・network contextと、固定caseの実行を結ぶ。local診断のみをapp sourceへ広げない | A/B |
| K10-D | GCP PG観測／PG catalog読取、証拠normalizer、`core/state*`、state/status presentation | PGの接続・layer・TLS／IPC・SQL・binding不足を正規化。有限PendingとAllowed保持、現在scopeの部分結果が通る | B/C |
| K10-E | AWS PostgreSQL、その後MySQLのsource/normalizer adapter | 同じbundle／評価契約へ接続。AWS固有のsource profile・native拒否recipeが未対応ならそのcoverageをUnsupportedと表示。GCEの証拠を流用しない | D |
| K10-F | CLI・既存native executor・レポート・互換文書 | 明示read取得、offline再評価、現在のstateとoperationの分離。新しいsource証拠を使う閉鎖stepだけ適切に契約更新し、旧approvalを流用しない | D、Eの対応分 |

Aの型・版・互換性と[Bの受入・保存・offline再読取](k10-b-admission.md)に続き、[Cのsource確認/取得とB接続](k10-c-source.md)を初期root host profileで実装・L検証しました。Dの初期PG producer/正規化・共通state接続も実装・L検証しました。EのPG/MySQL正規化とFの取得/offline表示は実装しました。E2/F2も接続済みで、残る中心はnative拒否recipe、backend TLS/完全なinventory等です。A/Bの型とportを固定後、CとDのparser／normalizerは担当を分けられます。同じsourceの本番取得・同一target操作を並列化する承認ではありません。複数担当が同じpolicy／state／CLI fileを同時編集しないよう、合成rootを一人が所有します。

AWS sourceがGCEと異なるため、Eを「同じJWT parserへ条件追加するだけ」と見積もりません。未対応のruntimeはそのままcapability gapです。PGの共通評価を先に完成させ、MySQLのcode追加がPGの完成を待たせない順にします。

## 3. 最初のcollectorの制約

| 項目 | 設計する制約 |
| --- | --- |
| SSH | 絶対pathの許可client、専用known-hosts、厳格host key確認、batch実行。転送・接続共有・agent forwarding・未登録jump／ProxyCommand・暗黙設定を持ち込まない |
| remote command | 固定のcollector pathとprotocol識別だけ。target／SQL／credentialをcommand文字列へ連結しない。requestはboundedなstdin |
| collector信頼 | 許可build／配置をsource登録へ固定。appから変更できるbinary/config、未検証のnamespaceやegress差はContextUnverified |
| context | VM世代、boot/network context、実行user・namespace・interface/route条件の選択値・digestを取得。取得不能なhost policyは推定しない。credentialやappの環境変数を丸ごと読む方式を採らない |
| credentials | sourceのnative credential取得。管理者token転送、秘密値のargv／artifact保存を禁止。collectorにVM変更・IAM変更の権限を要求しない |
| ID token検証 | 許可issuer／alg／key取得先を固定。tokenの`jku/x5u`やaudience URLから任意fetchをしない。未知key・取得不能はUnknownで、検証を無効化しない |
| DB | 既存driverで固定のread-only queryと新規接続だけ。顧客行、任意SQL、GRANT／ALTER／負荷・障害注入をcollectorへ持たせない |
| 終了 | request全体deadline、case上限、取消し、子孫process停止・回収。collector導入／sudo／ログ有効化を観測commandから実行しない |

SSH／JWT／metadataを個々に検証しただけで、侵害されたsource OS上の実行を完全に証明するとは主張しません。信頼する管理者・OS・collectorの前提と、VM network境界という保証範囲を表示します。

## 4. 実装時のローカル受入シナリオ

下記はK10全体の受入計画です。Aではsource/hash変更、v1互換、未信頼入力のshape、v2適用の停止をローカル検証しました。BではE04/E05のnonce・保存/commit・移入/破損境界、E18/E20のbuild/trust/期限/再読取を合成verifierで検証しました。Cではテスト専用鍵によるRS256/VM/SA/audience/期限/context照合とB接続、固定SSH argvとbounded child、loopback TCPを検証しました。実Google発行token・SSH handshake・Linux source・runtime効果まで含む全条件は未実行です。fixtureの成功はproductionのsource確認済み証拠にはなりません。test trust anchorやfake verifierはテスト組立てに限定し、実行configでGoogle等の信頼anchorを任意鍵へ差替えられる入口を作りません。

| ID | 入力・状況 | 必須結果 |
| --- | --- | --- |
| E01 | source登録IDは同じ、snapshot／VM世代／host keyが変わる | 旧policy／approvalで確認済みにせず再planまたはUnknown |
| E02 | claims JSONだけ、一般SA token、誤issuer／alg／audience、期限切れ | VM source確認へ昇格しない。raw tokenを保存しない |
| E03 | 正しいVM tokenでも別context、namespace、未登録proxy／UID別egress不明 | Source/RouteUnconfirmed。署名だけで実行場所を代用しない |
| E04 | 同nonceで別payload、古いsampleの新request貼付け、別sourceの結果 | 受入拒否。正例や新時刻を捏造しない |
| E05 | 受入前crash、保存だけ完了、受入後artifact破損、外部からcopy | 未受入／IntegrityError／履歴のまま。成功記録を作らない |
| E06 | captureの一部だけ成功し、別caseがtimeout／取消し | 受入条件を満たすAllowedを保持。全体はPartial／Unknown |
| E07 | 別sourceの正例をdirect拒否のcontrolへ貼る | negative sourceの到達性やroute拒否として成立させない |
| E08 | DB拒否応答を確認し、独立recoveryは別sourceで成功 | 正例の用途をTargetHealthへ限定。management credentialをapp sourceへ渡さず、適合する拒否recipeだけ評価 |
| E09 | direct TCP timeout／RSTだけ、またはnative拒否記録なし | 原因未確認。RouteBlockedへ昇格しない |
| E10 | login拒否をIAM拒否へ、TLS失敗を不許可主体へ読み替える | WrongDenialLayer／Uncorroborated。要求層を弱めない |
| E11 | DB session SSLは有効だがCA検証不明／local IPC境界不明 | 必須TLS区間・boundaryはUnknown。接続Allowedだけで全体成立にしない |
| E12 | owned SQL deltaは回収済み、先在／継承権限が残る | delta回収と現在Presentを併記。全実効権限Absentにしない |
| E13 | manual cutover checkpointだけ、実runtime証拠なし | Declaredを保持し、RuntimeBindingはUnknown |
| E14 | 同scopeの新しいAllowedとDeniedが重なる | Allowed・Mixed／矛盾を保持。拒否一件で成功を隠さない |
| E15 | 完全な関連permission差分と前後Allowed、期限内／期限後 | 条件が揃う場合だけ有限Pending、期限後NeedsAction／FailedPartial |
| E16 | owner binding削除だけ、別grant・継承permissionが未取得 | 全permission completeへ昇格せず、現在Allowedと不足を保持 |
| E17 | 旧v1 capture／approval／stateを新bundleへ貼る | 自動昇格なし。旧reader／hashとK09のquery-only安全条件を維持 |
| E18 | collectorとverifierが別build、未許可contract、trust epoch失効 | 不適合な行はUnknown／履歴。build IDを書換えて通さない |
| E19 | 未列挙IPv6／alias／batch source、または必須producerが未対応 | coverage不足を行に残し、集計から落としてgreenにしない |
| E20 | 完了operationをstatus、再評価で期限が切れる、export後別hostで読む | operationと現在保護を分離。offline読取からnative tool起動・時刻更新・新受入をしない |
| E21 | DB login／tableが同名再作成され、古い所有receiptを持ち込む | catalog identity／契約根拠不足を表示し、v2の所有回収根拠へ昇格しない |
| E22 | VM metadataと別のADC／gcloud資格情報が環境に存在する | 初期source profileはmetadata限定。暗黙fallback・管理token転送・別principal利用を拒否 |

## 5. K10の完了条件

1. A〜DとFのPG経路で、sourceを確認できる入力と確認できない入力を区別し、正規化・受入・再評価までローカルで検証できる。
2. 新しい要求・証拠・評価契約を文書と型へ固定し、source再束縛・世代差替え・replay・旧v1の昇格を拒否する。
3. SQL／TLS／binding／拒否層を独立に扱い、Allowed・Partial・Unknown・有限Pendingを保持する。
4. 明示取得とoffline statusを分離し、collectorがnative変更を行わず、K09の書込みgate・受付済みqueryを維持する。
5. Eの各provider/runtimeについてImplemented／LocalCovered／Unsupportedを正確に記録する。未実装sourceの汎用対応を宣言しない。

K10全体を「複数配置先へ接続済み」と閉じるには、Eで宣言した対応範囲も完了が必要です。PGの初回縦切り完了を、AWS source・MySQLまで実装済みとは数えません。K11 runtime連携がないbinding、必要なnative拒否記録がない環境等では、K10コードが完成してもそのprofileの全条件成立はUnknownのままです。その不足自体を利用者へ示せることが受入条件です。

実cloud／実DBの受け入れ、実sourceへの配置、必要権限・費用、Linux動作確認は別の実行範囲です。今回の設計完了や、次のローカル実装の開始条件へ追加フィジビリティを戻しません。
