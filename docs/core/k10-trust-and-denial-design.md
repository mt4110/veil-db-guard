# K10：管理TLS境界と拒否層の設計・実装

2026-11-03最終引継ぎ: [K10共通基盤のL受入とK11着手条件](k10-k11-handoff.md)を参照します。root probe/過去ログ/限定IAMの保証scopeを固定し、個別profileのUnknown・未対応は維持しました。次の実装はK11-Aです。以下は前チェックポイントの記録です。

2026-11-03。既存DBを移設せず、正規アプリの経路を維持しながら不許可接続を制限する本体の継続です。単一Rust crateのモジュラーモノリスを維持します。以前の「公開APIで観測できない証拠を要求し続ける」状態から、要求として選ぶ信頼境界と、取得した事実を分離しました。

## 採用したTLS契約

標準の`verified_tls`は変更しません。AWS RDS Proxyを使うschema v2のPG/MySQLに限り、次を明示的に選べます。

```yaml
encryption: verified_tls_with_aws_rds_proxy_managed_backend_v1
```

これはclient→ProxyのCA・hostname検証を必須のまま、Proxy→DBについては「現在の暗号化を観測し、内部の接続先検証はAWSの管理境界へ委ねる」という別契約です。内部CA・hostname検証を実測した意味ではありません。内部の両検証値はNoneを維持し、観測のbasisと要求した契約をreportへ表示します。現在のDB世代・専用Proxyとの結合、native source、client TLS、backend暗号化trueが揃わなければ満たしません。RequireTLSの設定だけで代用しません。

新しいpolicy/change/approval hashと、契約を含むrequest・現在buildでの再取得が必要です。旧厳密policy・承認・requestを自動移行しません。管理復旧用接続のbackendにも同じ契約を適用します。frontend TLSやK11のRuntimeBinding、閉鎖直前の再確認を省略する変更はありません。具体的な成立条件と一次資料は[管理TLS契約](k10-managed-tls-contract.md)に記載します。

## PostgreSQLログイン拒否

GCP/AWS PostgreSQL 16.15で、固定されたnative error recipeを追加しました。一般的な28000・28P01やエラー本文だけは根拠にしません。PG16.15の認証後NOLOGIN検査で生じるFATAL、SQLSTATE、source file/routine、対象roleと完全一致するprimary messageをすべて照合し、選択済みの`authenticated_no_login_v1`だけを保存します。raw error文や資格情報を証拠へ保存しません。Proxyやproviderが応答を書き換えて一致しない場合はUnknownです。

認証後であることは、[PG16.15 postinit.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/init/postinit.c)と[miscinit.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/init/miscinit.c)の実行順序に基づく、固定版recipeの設計上の推論です。providerの改変がないことを実クラウドで検証した意味ではありません。各wire fieldは[PG16 ErrorResponse](https://www.postgresql.org/docs/16/protocol-error-fields.html)に従います。

独立登録したRecovery sourceの現在の成功接続から、同じtarget generationにある承認済みgrantのrole OIDとrolcanloginを読みます。固定parameterized SELECTと既存のread-only/repeatable-read transactionを使い、最大8roleだけを対象にします。[公開pg_roles](https://www.postgresql.org/docs/16/view-pg-roles.html)を読み、管理者資格情報へのfallbackやSET ROLEを追加しません。

catalog対象はrequestに固定し、同じtarget・保護profileの承認済みgrantだけに制限します。取得計画がこの追加readを生成するのは、承認policyが`database_login`拒否層を選んでいる場合です。application sourceへrecovery資格情報を混ぜたり、同じVMを別source名で登録して独立性を偽装したりしません。

同じoperation/change/policy/target generation、別source・別subject、現在のAllowed、近接した時刻、OID非0、対象一致、rolcanlogin=falseをすべて要求します。古い成功、欠けたcatalog、現在のtrueやOID矛盾はUnknownです。元のbundleを変更せず、TargetHealth・CredentialValidityの派生参照を評価結果へ記録します。現在の接続成功を拒否記録で隠しません。

## 直通経路の拒否候補と生成元の境界

GCPは、既存の明示的なsource側EGRESS DENY firewallのログ候補をopt-inで取得・照合します。source socketを予約し、対象IP・port・source IP・port・時刻を一致させ、source VM/network/rule・DB世代の前後読取りへ結びます。HTTP Date、RTT、wall/monotonic整合で時刻差を確認し、その上限を超えてportを隔離します。予約確認不能、後発成功、時計差不足は候補を使いません。ログ有効化やrule作成は行いません。

**ログ候補からRouteBlockedやNativeBoundaryDecisionは生成しません。** [entries.write](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/write)ではlogName・resource・payload等をcallerが指定でき、provider専用namespaceとして書込みを制限する根拠を確認できませんでした。認証済みAPIから取得したことと、providerが生成したことは別です。一致したfieldは診断候補として保持しますが、主・補助claimともUnknown、route/completenessは`NativeLogOriginUnconfirmed`へ留めます。詳細は[取得方式・前提・制限](k10-route-denial.md)に記載します。

前回のGCP IAM監査ログrecipeも同じorigin境界を再点検しました。既存audit entryがimmutableであることは、同じlog IDへ別callerがentryを追加できないという証明ではありません。provider生成の裏付けが足りないため、こちらも監査ログ候補のみでは認可拒否を確認済みにしません。直接のPG NOLOGIN応答に基づくrecipeは別です。偽造を実クラウドで試したという結論ではなく、originを確認済みとする根拠が不足しているという訂正です。

AWS Flow Logsは、配信遅延とtimestamp精度が現行45秒capture・鮮度契約に合わず、現在のprofileでは未対応理由を明示します。globalの時間・鮮度制限は緩めません。一般timeoutやSG設定削除だけで、当該試行がnative境界で拒否されたとは扱いません。

AWSの遅延取得を追加する場合は、probe時の送信元socket/5tuple/target generationを固定した検証済み記録と、後日受け取ったnative eventを別の時刻として受け入れる設計が必要です。記録のsingle-use、ログ集計時間・packet種別、source port再利用、event時刻の誤差、後続の現在接続成功との矛盾を扱い、過去の拒否を現在の保護成立へ昇格させない条件を別途実装します。単にrequest TTLやcapture上限を伸ばす方式は採用しません。

## 今回の完了条件と残り

今回の範囲は、明示的な管理TLS契約、PG NOLOGINの実取得と独立catalog対照、GCP firewallログ候補の取得とorigin不足判定を、固定collector・sealed受入・共通評価へ接続することです。型・資料だけで取得を実装したとは扱いません。

K10全体、全providerの全拒否層、AWSの完全なIAM inventory、AWS直通経路の遅延証拠取得が完成した意味ではありません。K11の実アプリ切替・RuntimeBindingも今回の対象外です。従来の厳密TLS要求や必要な拒否証拠を満たせないprofileは、引き続きUnknown/NeedsActionです。

実Cloud SQL/RDS/GCE/EC2、実ログ配信、実DB、collector配置、権限変更、追加フィジビリティ、公開は行っていません。ローカルの署名、SQLite/archive、fake protocolとnative応答fixtureは、実環境の保護成立と区別します。最終チェックの記録は`runs/core-k10-trust-local-20261103-1/`へ保存します。

## origin不足を解消する次の設計条件

Cloud Logging方式を拒否証拠へ使うには、入力sourceの実効log writer権限、sink・route変更権限、転送元と保存先への全書込経路を含め、untrusted workloadが候補を作れない境界を検証する必要があります。保存先bucketのIAMだけを限定しても、転送前に作られた偽の入力は排除できません。利用者の単一boolean申告をnative origin証拠へ昇格させる方法は採用しません。

代替は、providerが生成元を認証するinterface、あるいは登録root collectorが直接受け取る保護されたOSのenforcement verdictなどです。後者はhostの保護を信頼する別profileであり、クラウドfirewallや全接続元の拒否とは別の保証になります。K10の未完了を解消するには、この取得境界とAWS遅延証拠の契約を実装する必要があります。今回のAPI field一致を合格へ戻すだけでは解決しません。

最終ローカル検証: `mise run check`のfmt・Clippy（`-D warnings`）は成功。**595成功・0失敗・実DB用2件ignored（47 suites）**。Rust 1.98.1 / macOS ARM64、locked/offlineです。[検証summary](../../runs/core-k10-trust-local-20261103-1/summary.json)に保存しました。旧socket保持の仮定で失敗した初回logも残し、OS上の保持を確認できない場合に不適格とする修正後、全checkを再実行しました。
