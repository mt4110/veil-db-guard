# K10 origin契約：保護されたhost kernel probeとapp scopeの分離

2026-11-03。今回の実装は、登録済みGCE root collectorからのnative syscall応答を、生成元を確認したprobe観測として取得する。**root probeの拒否を対象applicationの接続拒否へ昇格しない。** Cloud Loggingの候補をprovider生成と扱う変更でもない。

## Cloud Logging方式で未確認の境界

[entries.write](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/write)はlogName・resource・payloadなどをcallerが指定できる。APIを認証して読めることと、entryがproviderによって生成されたことは別である。

Cloudログから拒否を認定するには、少なくとも保護対象とするuntrusted actorの集合、委任・impersonation・継承権限、入力writer、転送元・route・sinkとその変更者、転送先writer、権限を変更できる主体を結び、候補entryの生成・注入経路を閉じる必要がある。source projectと保存先bucketのIAMだけを列挙しても、この閉包を確認したことにならない。現在のcollectorはこの全経路を取得・確認しないため、GCP audit/firewall候補は`NativeLogOriginUnconfirmed`を維持する。operatorの単一booleanや「bucketだけread-only」という申告は証拠にならない。

## 実装した別の生成元契約

root-owned collector設定で、次のenumを明示的に選択する。

```json
"kernel_origin": {
  "contract": "linux_root_connect_v1",
  "source_ip": "10.0.0.2"
}
```

この設定全体のdigestとcollector binary/buildは登録snapshotとrequestに固定する。従来のGCP firewall-log設定`route_denial`との同時指定は拒否する。Linux以外、root以外、必要なprocfs contextを取得できない環境はUnsupported。設定・collectorの配置、権限付与、firewall変更はこの実装に含まない。

固定collectorは既存のDirectPath caseのendpointへ、指定source IPにbindしたAF_INET/SOCK_STREAMの非blocking socketで`connect(2)`を呼ぶ。direct syscallから同期的に返った`EPERM`だけを`HostKernelProbeDenied`へ選択する。EACCES、timeout、refused、その他errno、接続後のSO_ERRORを同じ意味へまとめない。非同期の接続成功を監視し、成功はConnectedとして保持する。キャンセル時はsocketをdropし、正の拒否証拠を残さない。

[connect(2)](https://man7.org/linux/man-pages/man2/connect.2.html)はEPERM/EACCESについてlocal firewallなど複数の原因を示す。[Linux v6.12 tcp_v4_connect](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_ipv4.c)ではTCP broadcast/multicastをENETUNREACHとし、[ICMP errno変換](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/icmp.c)にEPERMはない。[nf_hook_slow](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/core.c)にはNF_DROPをEPERMへ変換する経路がある。これは取得方式の設計根拠であり、EPERMを特定firewall rule・cloud firewall・DB認証拒否と同定する根拠ではない。LSM、seccomp、cgroup/BPFなどのhost policyもprobe結果へ影響し得る。

## 取得・検証される範囲

各probeの前後で次を選択し、同一であることを要求する。

- UID/EUID、GID/EGID、network/user/mount namespace、kernel release。
- exact cgroupファイルdigestと、既存host profileとの対応用cgroup class。
- LSM current labelと、UID/GID/supplementary groups、capability、NoNewPrivs、Seccomp各fieldから計算したsecurity context digest。

security context digestは選択したstatus/LSM labelのdigestであり、seccomp filter program、LSM policy、BPF program全体のdigestではない。値の一致だけでは同じ許可関数が適用されることを証明できない。

recordはcase・request nonce側のdigest、source revision、時間窓、固定endpoint・port、5tupleと結び、既存pinned SSH channel、root collector、Google VM identity verifierから受け取る。controllerはrecordの重複、前後contextの相違、登録host namespace/UIDとの相違、diagnosticとの時刻・tuple・outcomeの相違、EPERM選択の矛盾を拒否する。Cloud firewall候補との同一case混在も拒否する。

このroot/kernel/adminの信頼境界では、untrusted workloadにroot、collector binary/config、SSH channel、kernel/procfs、ptrace、適用policyを変更する権限を与えない。これらの管理者を敵対者に含める保証ではない。Cloud Logging writerがentryを注入できる問題はこの経路に入らないが、host管理者の完全性を新たに実証した意味でもない。

選択したrecordは標準evidence payloadに保存され、bundle artifact digestとsource verifierへ結ぶ。`GceCapture::host_kernel_probes()`はpublic constructor/Deserializeを持たない`VerifiedHostKernelProbe`を返し、request/source/proof digestを参照できる。この型は**capture-authenticated**であり、admission済み・fresh・app scope一致を意味しない。saved JSONから型を復元してauthorityを作るAPIはない。K11が利用する際は通常のadmission、原request・source登録・trust epoch・鮮度を再確認し、payload digestを照合する必要がある。

## application scopeとK11

root probeとapplicationではUID、cgroup、LSM/seccomp policyなどが異なる。host network namespaceの一致だけでは、同じ宛先へ同じ許可判定が適用されるとはいえない。従って今回のnormalizerはNewConnections claimをUnknownのままにし、route/completenessを`RuntimeBindingUnverified`とする。`NativeBoundaryDecision`、`RouteBlocked`、`NewConnectionsDenied`を生成しない。target generationをnative readで再確認した意味もない。

K11がapplicationへのscope一致を示すには、実際のruntime identity/contextとprobe contextの関係、適用されるpolicy、target generation、直前の再確認、時刻と後続の成功矛盾を別に解決する必要がある。単に同じVM上のroot socketを対象appの実行とみなす結合はしない。このsliceはその比較に必要な元の観測を取得し、誤って保護成立へ昇格しない境界を準備したものである。

## ローカル検証と残り

native取得経路は実syscallを呼び、テスト用booleanやJSON結果の取り込みをproducerに設けない。synthetic EPERM recordでpinned capture checkerとsealed fact/Unknown normalizerの経路を試験し、改変されたUID/ns/security context、errno、tuple、時刻、outcome、重複を拒否する。Unix loopback上の実socketで成功・refused・キャンセルを確認する。EPERMの実firewall生成、Linux/GCE配置、実Cloud/DB、application runtime scope一致は未検証であり、この実装のローカル試験をそれらの合格扱いにしない。
