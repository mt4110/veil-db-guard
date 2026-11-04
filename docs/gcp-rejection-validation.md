# GCPの直通制限と不許可IAM主体の追加検証

実施日: 2026-11-02。[初回フィジビリティ試験](gcp-feasibility.md)で未確認だった、直通経路の拒否原因と、有効な資格情報を持つ不許可IAM主体の拒否を対象にした追試です。製品CLIのGCP adapter実装やAWS M3の完了とは区別します。

## 承認と対象

ユーザーからSol/high・サブエージェント使用、前回分を含む合計50米ドル以内、試験後の撤収までの指定を受けました。新規専用project、Cloud SQL PostgreSQL 16.15、keylessな試験用service account 2個を作成し、このprojectと試験用主体だけの設定を変更しました。

Cloud SQLは東京、Enterprise、2 vCPU/8 GiB、SSD 20 GiB、単一zoneです。TLSは全phaseでENCRYPTED_ONLYを維持しました。直通の正例に必要な一時的な許可は、観測した実行元の外向きIPv4アドレスの/32のみです。共有NATの場合、この/32を一台のMacだけの境界とは扱えません。

操作主体へのtokenCreator付与は試験用SAそれぞれのリソース内に限定しました。SAへのCloud SQL/Service Usageの権限は新規project内だけです。ユーザー管理のSA秘密鍵を発行・ダウンロードせず、既存のユーザー資格情報から短期impersonationを使いました。token/passwordはメモリ上だけで使用し、コマンド引数や証拠へ保存していません。

## 直通経路の対照

同じDB・IP・DBユーザー・CA・TLS条件で、新規接続を比較しました。直通の正例はinstance固有CAを指定したlibpqのverify-caで接続し、DBのidentity・合成markerとpg_stat_sslのSSL有効を照合しました。各phaseの前後にProxy経由の正例も実行しています。

| Phase | Connector必須 | 実際の許可リスト | 直通TCP/SQL | Proxy正例 |
| --- | --- | --- | --- | --- |
| N0 | いいえ | 空 | timeout / 失敗 | 前後とも成功 |
| N1 | いいえ | 実行元/32のみ | 到達 / CA検証付きTLS・SQL成功 | 前後とも成功 |
| N2 | はい | N1と同じ/32 | timeout / 失敗 | 前後とも成功 |
| N3 | いいえ | N1と同じ/32 | 到達 / CA検証付きTLS・SQL成功 | 前後とも成功 |
| N4 | いいえ | 空 | timeout / 失敗 | 前後とも成功 |
| N5 | いいえ | 実行元/32のみ | 到達 / CA検証付きTLS・SQL成功 | 前後とも成功 |

N1/N2/N3のauthorizedNetworksの実値が完全に同じであることと、N0/N4が空、N1/N3/N5が対象/32のみであることを別途機械照合しました。N2ではAPI上の/32は保持されていましたが、Connector必須化により直通接続が止まりました。N3での復元成功も揃っています。これはREQUIREDがauthorized networksを無効化するという公式仕様と整合します。[公式設定手順](https://docs.cloud.google.com/sql/docs/postgres/connect-auth-proxy#enforce-the-use-of-cloud-sql-connectors)

N3→N4→N5はConnectorをNOT_REQUIREDに固定し、許可リストだけを変更した比較です。許可リストが空の場合のtimeoutも独立して再現できました。今回の拒否はDBパスワードの誤りやTLS証明書不一致ではなく、TCP到達段階で止まる接続制限として観測しました。

初回のinstanceは既に削除済みなので、その個体の過去のpacketを遡って証明した結果ではありません。同じ条件を新規instanceで再現し、前回の組合せに含まれていた二つの制限を切り分けた結果です。試験後はREQUIREDかつ許可リスト空への復帰を確認しました。

## IAMの二つの拒否層

両SAへ同じ補助権限Service Usage Consumerを与え、DBにも同じ限定SQL roleでIAMユーザーを登録しました。DBユーザーの未登録、名前の誤り、token発行失敗、quota/API利用権限不足を拒否の証拠に代用しません。

| 条件 | 比較で観測した結果 |
| --- | --- |
| 正規SA: client + instanceUser | IAM DBログイン成功。current_userが当該SAのDBユーザー名と一致 |
| 比較SA: instanceUserあり、clientなし | 有効な短期tokenを取得できるが、Proxyログにcloudsql.instances.connect不足の403。SQL接続失敗 |
| 同じ比較SAへclientを追加 | 同じDBユーザーでログイン成功 |
| 比較SA: clientあり、instanceUserなし | 反映後にIAM service account authentication failedでログイン拒否。同じProxy経路を通した管理用DBログインは成功 |
| 同じ比較SAへinstanceUserを復元 | IAM DBログイン成功 |
| 同じ比較SAからinstanceUserを再削除 | 反映待ち後、3回連続でIAMログイン拒否。同じProxy経路の管理用DBログインと、別の正規SAのIAMログインは成功 |

ProxyとDB login tokenのimpersonation対象を明示し、各試行でProxyを新しく起動してDB接続も新規にしました。project IAM policyを各試行で保存し、後から結果と照合します。SAのDBユーザー名は.gserviceaccount.comを除いた形式です。

### 権限削除は即時遮断ではない

instanceUserの削除がproject policyに現れた後も、しばらく新規ログインの成功を観測しました。最初の削除では、途中に拒否と成功が混在し、その後は連続拒否になりました。拒否が一度出た時刻だけを「反映完了」と扱いません。

IAMは結果整合であり、直接のpolicy変更でも通常約2分、7分以上かかる可能性があると説明されています。これは今回の観測と整合しますが、Cloud SQL固有cacheの正確な内部原因や上限時間を測定したものではありません。tokenを新しく取得できることと、DBログイン権限を持つことも別です。[IAM公式伝播説明](https://docs.cloud.google.com/iam/docs/access-change-propagation)、[Cloud SQLのロール定義](https://docs.cloud.google.com/iam/docs/roles-permissions/cloudsql)

今回の時系列は次のとおりです。時刻差はpolicy削除CLIの完了記録から各試行結果の記録までであり、内部の厳密な権限反映時刻ではありません。

- 最初の削除: 約71秒で初めて拒否が現れましたが、その後の約88秒時点には成功も観測しました。最後は約347/364/382秒時点の3回連続拒否を確認しました。初回分類器の修正待ちを含むため、この遅い3点から反映に必ず約6分かかるとは言いません。
- 復元後の再削除: 約19秒時点まで成功が残り、約36/53/71秒時点で3回連続拒否を確認しました。
- 各拒否では、比較SAのProxy経由でも管理用DBログインは通りました。取得したPostgreSQLの認証診断38件のうち18件には、cloudsql.instances.login不足を示唆するDETAILがありました。project policyと同じSAの権限復元対照を合わせて原因を評価しました。

観測範囲での拒否を確認した結果であり、即時失効や全接続の即時切断を保証する結果にはしません。権限変更の伝播中に成功と拒否が混在する時間帯も含めて記録します。

## 実装上の修正と証拠

この追試の一時的なrunnerで、SAのDBユーザー名を登録時にもsuffixなしにする修正と、実際のエラー文に含まれる「IAM service account authentication failed」を拒否として分類する修正を行いました。最初の分類器は「IAM user」の文面しか対象にせず、拒否が既に起きていたのに待機期限へ達しました。初期試行のsource・結果・生のstderrは保全し、期待する安全条件を弱めずに残りの対照を再開しています。

生のproject ID、identity、IP、設定、各SQL結果、Proxyログ、権限変更の時系列はgit除外のruns/gcp-rejection-20261102-430e55/に保存しました。初期runnerのエラーも履歴として保持しています。final-assessment.jsonを今回の照合結果とし、network-assessment.jsonと元のAPI/SQL/Proxyログを参照します。公開用のこの文書へ完全なidentityやendpointを転記しません。製品コードは変更していません。

## 撤収・費用・最終判断

2026-11-02 13:19 JSTに次を確認しました。

- 試験用SA 2件の削除と、SA一覧からの除去。
- 今回のproject IAM bindingと、SA単位のtokenCreator bindingの除去。全policy内に当該SAのmemberが残っていないことも照合。
- ユーザー管理のSA keyは0件。
- 削除前のDB backup一覧は0件。自動backup/final backupを作らない試験構成を維持。
- instance削除operationのDONEと、Cloud SQL instance一覧0件。
- billingEnabled=false、専用projectのlifecycleState=DELETE_REQUESTED。物理的な完全消去や、既発行tokenの即時失効の証明ではない。
- 試験用Proxyは各試行終了時に停止し、ローカル証拠を保持。

専用projectの作成から撤収確認までは約25.8分、instance作成要求から削除確認までは約23.4分です。確認済みの東京のCPU・メモリ・SSD単価による今回のDB/storage概算は **約0.0728米ドル**、前回と合わせた同じ項目の累計は **約0.1076米ドル** です。通信・ログ・税・割引等を含む実請求額ではなく、実請求額は未取得です。[料金の根拠](multicloud-preparation.md#料金の確認と見積もりの境界)

予算は前回分を含む合計50米ドル、今回の管理枠は最大5米ドル/4時間で実施しました。課金継続につながる今回のCloud SQL instanceを残さず、専用projectの課金紐付けも解除しました。

**今回の二つの確認対象は完了しました。** この実行元・instance・設定で、許可リストとConnector必須化による直通制限、有効だが権限のないIAM主体へのconnect/login拒否を対照付きで確認しました。権限削除後の即時遮断には使えない時間帯も実測したため、GCP側の設計にはこの伝播特性を含める必要があります。全エンジン・全ネットワークへの一般化、既存接続の即時切断、自動token更新、製品CLIのGCP対応は今回の結果には含みません。

分担: 主担当がクラウド操作と実機観測、検証担当が対照・合否・撤収記録を独立レビューし、重大な偽pass・残存・表現の過大化は見つかりませんでした。技術調査担当は公式仕様と伝播条件を調査しました。文書6ファイルの参照・空白・非公開識別子、当該runのtoken/秘密鍵パターンと記録済みProxy portの停止を確認し、不備は見つかりませんでした。既存の未コミット成果と初期失敗の記録を保持し、AWS/Cloudflare/Azureの資源変更、push・公開はしていません。
