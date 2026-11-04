use super::model::*;

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
        .replace('[', "&#91;")
        .replace(']', "&#93;")
        .replace(['\r', '\n'], " ")
}
fn route(r: GcpRoute) -> &'static str {
    match r {
        GcpRoute::Proxy => "Cloud SQL Auth Proxy経由",
        GcpRoute::Direct => "DBへの直接接続",
    }
}
fn access(a: GcpAccess) -> &'static str {
    match a {
        GcpAccess::Allowed => "最後の観測では接続できる",
        GcpAccess::Denied => "今回の試行では拒否された",
        GcpAccess::Unknown => "接続可否・拒否原因を確定できない",
    }
}
fn verdict(v: GcpVerdict) -> &'static str {
    match v {
        GcpVerdict::Pass => "確認済み",
        GcpVerdict::Fail => "期待条件を満たしていない",
        GcpVerdict::Pending => "反映確認待ち",
        GcpVerdict::Unknown => "未確認",
    }
}
fn reason(r: GcpReason) -> &'static str {
    match r {
        GcpReason::None => "正規接続の成功を確認しました。",
        GcpReason::PermissionDenied => "対象の接続・認証層で拒否を観測しました。",
        GcpReason::AccessStillAllowed => {
            "拒否したい接続が、最後の観測では成功しています。保護成立とは扱いません。"
        }
        GcpReason::PropagationPending => {
            "過去と現在の実測role差分が、宣言した権限変更に対応しています。現在は接続できる／保護成立未確認。反映遅延を確定原因とは扱いません。"
        }
        GcpReason::MissingEvidence => "必要な実接続の記録がありません。",
        GcpReason::StaleEvidence => "記録が古いか、観測時刻が整合していません。",
        GcpReason::FixtureOnly => {
            "fixtureの記録です。実環境の保護成立や反映待ちの根拠には使いません。"
        }
        GcpReason::IncoherentSnapshot => {
            "試行前後で設定またはroleが変わっています。同じ保護条件の結果として評価できません。"
        }
        GcpReason::IncompleteInventory => {
            "captureが未完了、または必要な設定・安全条件を確認できていません。"
        }
        GcpReason::IdentityMismatch => {
            "SQL接続の主体またはdatabaseを、指定した対象と照合できません。"
        }
        GcpReason::WrongDenialLayer => "拒否は観測しましたが、期待した拒否層とは一致していません。",
        GcpReason::NetworkCauseUnconfirmed => {
            "timeoutや到達不能だけでは、ネットワーク保護による拒否と確定できません。"
        }
        GcpReason::ChangeUncorroborated => "宣言した権限変更に対応する実測差分がありません。",
        GcpReason::MixedHistory => "過去の接続成功と拒否が混在しています。",
        GcpReason::UnclassifiedFailure => "操作失敗の原因を分類できていません。",
        GcpReason::TargetMismatch => "記録の対象が設定と一致しません。",
        GcpReason::ConfigMismatch => "記録の設定hashが評価設定と一致しません。",
        GcpReason::BuildMismatch => "記録と評価器のbuildが一致しません。",
        GcpReason::InvalidEvidence => "記録・識別子・参照・重複等の整合条件を満たしていません。",
    }
}
fn next(c: &GcpCaseAssessment) -> &'static str {
    match c.denied_permission {
        Some(GcpPermission::ServiceUsage) => {
            "Service Usage Consumerとquota projectの設定を確認してください。"
        }
        Some(GcpPermission::TokenCreation) => {
            "対象SAだけに設定したtokenCreatorと短期tokenの取得経路を確認してください。"
        }
        Some(GcpPermission::InstanceLogin) => {
            "Cloud SQL Instance UserとSAのDBユーザー登録・SQL権限を確認してください。"
        }
        Some(GcpPermission::InstanceConnect | GcpPermission::InstanceGet) => {
            "Cloud SQL Clientと対象instanceへの接続認可を確認してください。"
        }
        None => match c.expected_denial {
            Some(GcpDenial::ConnectIam) => {
                "対象SAのCloud SQL Client変更と、新規Proxy接続の結果を確認してください。"
            }
            Some(GcpDenial::LoginIam) => {
                "対象SAのCloud SQL Instance User変更、DBユーザー登録と、新規SQL接続を確認してください。"
            }
            Some(GcpDenial::NetworkBlocked) => {
                "Connector必須設定・実際のallowlist・送信元とProxy正例を照合してください。timeoutだけを合格にしないでください。"
            }
            None if c.route == GcpRoute::Direct => {
                "直接接続先・CA検証・Connector設定・allowlistを確認してください。"
            }
            None => "対象SAのCloud SQL Client/Instance User、DB登録とSQL権限を確認してください。",
        },
    }
}
pub fn exit_code(a: &GcpAssessment) -> i32 {
    match a.verdict {
        GcpVerdict::Pass => 0,
        GcpVerdict::Fail => 1,
        GcpVerdict::Pending | GcpVerdict::Unknown => 3,
    }
}
pub fn render_markdown(a: &GcpAssessment) -> String {
    let mut s = format!(
        "# GCP接続保護の確認\n\n対象: {} / {} / {}  \n評価時刻（Unix秒）: {}  \n評価: {}  \n定義したcaseの保護条件: {}\n\n",
        escape(&a.target.project_id),
        escape(&a.target.instance_id),
        escape(&a.target.database),
        a.evaluated_at,
        verdict(a.verdict),
        if a.protected {
            "今回の観測範囲で確認済み"
        } else {
            "成立未確認"
        }
    );
    for c in &a.cases {
        s.push_str(&format!("## {}\n\n{} の{}を{}したい設定です。\n\n{}。評価は **{}**、保護条件は **{}** です。{}\n\n次の確認: {}\n\n最後の観測（Unix秒）: {:?} / 操作状態: {:?}\n\n",
            escape(&c.case_id),escape(&c.principal_id),route(c.route),if c.expected==GcpExpectation::Allow{"許可"}else{"拒否"},access(c.observed),verdict(c.verdict),if c.protected{"今回確認済み"}else{"成立未確認"},reason(c.reason),next(c),c.observed_at,c.execution));
        if c.mixed_history {
            s.push_str("履歴に接続成功と拒否が混在しています。現在の評価で過去の成功を消していません。\n\n");
        }
        if !c.evidence_runs.is_empty() {
            s.push_str(&format!(
                "根拠run（現在のcaptureと、反映待ちに対応付けた履歴）: {}\n\n",
                c.evidence_runs
                    .iter()
                    .map(|r| escape(r))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if c.consecutive_denials > 0 {
            s.push_str(&format!("直近の拒否観測は{}回連続です。即時失効、反映時間の上限、将来の安定拒否、既存接続の切断を保証しません。\n\n",c.consecutive_denials));
        }
    }
    s.push_str("このコマンドは構築や設定変更を行いません。未定義の主体・経路、全体の最小権限、継承・groupの実効権限を網羅していません。project roleの選択情報と実際の接続結果を分け、入力記録の真正性を署名で保証するものとは扱いません。\n");
    s
}
