# K10: GCPのfirewallログ候補の取得とorigin未確認

2026-11-03。`adapters/source/route_denial.rs`は、登録GCE root hostからCloud SQL PostgreSQL 16.15 private IPへのTCP試行と一致する、legacy VPC firewallのEGRESS DENYを報告する**ログ候補**を取得・照合します。取得したログがproviderによって生成されたことの根拠は未確立なので、RouteBlockedへ昇格しません。単一crateのsource adapterで完結し、実クラウド・SSH・実DBは操作していません。

**現在の正規化はUnknown/Unclassifiedです。** HTTPSでの取得は保存されたログのfieldを認証しても、その生成主体を認証しません。公式[entries.write](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/write)と[LogEntry型](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry)はcaller指定のlogName/resource/jsonPayload/timestamp/insertIdを受け付けます。firewallのlog IDがprovider専用である制約は今回確認できませんでした。したがって、fieldが完全一致する候補もNativeBoundaryDecisionに使わず、route/completeness assuranceへ`NativeLogOriginUnconfirmed`を保持します。auxiliary claimもUnknownであり、native拒否controlを生成しません。

## 設定と取得

既存collector configの任意の`route_denial`で有効にします。省略時は旧configのserialize bytesと一般TCP診断を維持します。この断片に加え、既存context、endpoints、source登録が必要です。

```json
{
  "route_denial": {
    "source_ip": "10.0.0.2",
    "instance_name": "application-vm",
    "network_name": "application",
    "subnetwork_name": "application-subnet",
    "firewall_name": "deny-direct-postgres",
    "firewall_priority": 900
  }
}
```

有効化には変更後config digest、collector binary digest/buildを登録へ固定します。既存metadata SAに、対象のSQLAdmin instances.get、source VMのCompute instances.get、Cloud Logging entries.listに必要な読取り権限とscopeが既にあることが前提です。別SA、ADC、管理者、一般privileged observerへのfallbackはありません。コードは権限・firewall・loggingの設定やcollector配置を変更しません。

1. 固定metadata originで、登録source SAの短期cloud-platform tokenを取得します。固定SQLAdmin APIの読取りでnative target、世代、private IP、PG16、regionを確認します。
2. 固定Compute APIで登録VMを読み、署名snapshotのimmutable instance IDと一致すること、登録primary private IPv4、network/subnetworkが同じprojectのnative interfaceに一意に存在することを確認します。Shared VPC、alias IP、NAT、IPv6、別projectのnetworkはこのrecipeの対象外です。
3. `TcpSocket`を登録source IPとOS割当portにbindします。前回のport使用をprovider時計差で誤照合しないよう、未送信で既存profileの最大時計差5秒を超えるまで（通常6秒）quarantineしてから一度だけ接続します。予約時刻`port_reserved_at`を署名captureに含め、sealed受入もcapture開始以後・probe開始の5秒超前であることを検証します。`F_DUPFD_CLOEXEC`による同じsocketのdescriptorを保持し、接続失敗後にもkernelがlocal tupleのbindを保持し、reuse flagなしの別socketがEADDRINUSEで失敗することを取得前後で確認します。保持できなければUnsupported/Unknownです。3秒timeout後のconnect taskはnative取得と並行監視し、後発成功をTCPConnectedとして残して拒否を生成しません。taskは終了時・取消し時にabortします。
4. 固定`https://logging.googleapis.com/v2/entries:list`に、project、TCP 5tuple、probeの時刻窓を束縛した読取りを一度行います。3秒、65536bytes、16件以内で打切ります。ComputeとLoggingの固定HTTPS読取りは、認証済みresponseの単一HTTP Dateを分離してUTCへ変換します。local送受信時刻に対するprovider offset区間`[Date-localEnd, Date+1秒-localStart]`全体が±5秒内、RTTが3秒以内、wall時計とmonotonic経過の差が100ms以内の時だけ資料を受け入れます。Date欠損・重複・不正、時計のjump、遅すぎる応答はUnknownです。3回の選択ClockBoundを保存しsealed受入で再検証します。queryでDENIEDや特定ruleだけに絞らず、同じtupleの矛盾する結果も選択器へ渡します。
5. 全entryについて、`compute.googleapis.com/firewall`、`gce_subnetwork`、VMのproject/name/zone/region、network/subnetwork、5tuple、`DENIED`、rule action `DENY`、direction `EGRESS`、登録rule referenceとpriority、probe時刻窓内を厳密に照合します。全件一致し、paginationがない場合だけ選択します。
6. source networkとtarget instanceを再読取りし、前後が一致することを確認します。raw token、providerエラー文、raw log全体は保存せず、選択情報とentry IDのdigestを既存署名source proofに含めます。GCE tokenの署名、SSH peer、context、request digest、config/build pinを検証するsealed verifierで、取得・対応付けだけを確認します。主claimとauxiliary claimはUnknown/Unclassifiedで、NativeBoundaryDecision controlを作りません。

公式[VPC firewall log形式](https://docs.cloud.google.com/firewall/docs/vpc-log-format)は5tuple、VM/network metadata、rule reference/priority/action/directionを定義しています。[Logging entries.list](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list)が限定取得のAPIです。source IDとinterfaceの照合には[Compute instances.get](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/get)のresponseを使用します。

## Unknownと保証の範囲

未配信、権限不足、欠損metadata、別source、別rule、別port、別時刻、mixed ALLOWED、pagination、過大応答、読戻し不一致、deadline、取消しは原因付き拒否を生成しません。TCP成功を拒否で上書きしません。実際の配信速度・field充足は未検証であり、一度の取得でログが来る保証はありません。45秒captureと5秒clock skewを緩めません。HTTP DateはTLS認証したAPI frontendの現在時刻を検査する手段で、ログ生成timestampとfrontendの時刻源が同一であるSLAを新たに主張しません。providerのUTCログtimestampの信頼はnative記録を用いるprofileの前提です。

候補のfieldは**source側firewallが当該経路を拒否したこと**を報告しますが、origin未確認なので実際の拒否原因とは扱いません。Cloud SQLの`connectorEnforcement=REQUIRED`の設定受付・読戻しや一般timeoutから、connector必須化の拒否は生成しません。DB login/IAM認可の拒否、全経路不存在、既存session停止、全期間の継続遮断も保証しません。trusted root collector/hostの範囲を超えた侵害耐性は主張しません。

network拒否はDB credentialを使う前の観測なので、CredentialValidityは作りません。transport assuranceはnative metadata/decisionを取得した固定provider HTTPS経路についての保証であり、DB接続のTLS成立ではありません。route claimにはTLS transport factを入れません。現在の共通stateはdirect DeniedにNativeBoundaryDecisionを要求し、このproducerはその条件を満たしません。独立した現在TargetHealthを要求する評価条件の強化とは分けます。

AWSは`aws_flow_log_window_exceeds_capture_contract`をstructured support reasonとして返します。[AWS Flow log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)では、timestampの最大60秒の差、best effortの配信遅延、接続終了後packetを含むREJECTを定義しています。現在の45秒/5秒契約を変更せず、Flow Log一般REJECTやSG設定だけから原因付きRouteBlockedを作りません。AWS全方式の不可能という意味ではなく、遅延取得とtuple予約を結ぶ別の証拠契約が必要です。

## ローカル検証

選択器はexact tuple/VM/network/rule、field変更・欠損、mixed、pagination、古い時刻、duplicate known fields、サイズ上限を検証します。native source readbackのimmutable VM ID・primary interface、前後世代変更、接続成功との矛盾も検証します。GCE署名fixtureからsealed verifier、実SQLite・archive受入、offline共通stateまで接続し、完全一致候補があってもorigin不足のUnknownを維持することを検証します。providerデータは合成資料であり、実GCPでの動作・実保護の証明には含めません。macOS loopbackではECONNREFUSED後にdup descriptorがあってもportを再bindできることを観測したため、このkernelでのそのcaptureはUnsupportedに落とします。Linux collectorでの実kernel予約保持と実ログ配信は未確認です。pure bound socketの予約検査、取消し、Dateの欠損・重複・clock offset/RTT/jump、2秒進んだ旧tupleログの誤照合防止も回帰対象です。

将来の昇格には、field照合に加えて、対象ログnamespaceへ一般writerがprovider生成記録と区別不能なentryを書けないことを確認するverifierが必要です。destinationのIAM設定だけでは生成元の保証になりません。保護されたnamespace・writer制約・provider発行の検証可能な証明等の根拠がない間、ログ候補を拒否の合格へ変換しません。
