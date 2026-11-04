//! Markdown presentation of the same structured assessment; no external reads.
use crate::domain::{Assessment, Verdict};

fn escaped(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| match c {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '|' => "&#124;".chars().collect(),
            '\n' | '\r' => " ".chars().collect(),
            '`' => "&#96;".chars().collect(),
            '[' => "&#91;".chars().collect(),
            ']' => "&#93;".chars().collect(),
            c if c.is_control() => vec![],
            c => vec![c],
        })
        .collect()
}

pub fn exit_code(a: &Assessment) -> i32 {
    match a.verdict {
        Verdict::Pass => 0,
        Verdict::Fail => 1,
        Verdict::Unknown | Verdict::NotApplicable => 3,
    }
}

pub fn render_markdown(a: &Assessment) -> String {
    let mut out = format!(
        "# Veil DB Guard 評価\n\n対象: {}\n\nProfile: {:?}  \n評価時刻（Unix秒）: {}  \n判定: {:?}  \n構成: {:?} / 接続: {:?}\n\n判定は記録された対象・条件・時点の範囲です。ローカルfixtureの結果はAWS防御成立を示しません。入力証拠の真正性を署名で保証するものではありません。\n\n| 検証 / case | path | 判定 | 理由 | 証拠種別 | 実行状態 | 観測 | 試験元 / 照合 | run |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
        escaped(&a.target_id),
        a.profile,
        a.evaluated_at,
        a.verdict,
        a.configuration_verdict,
        a.connection_verdict
    );
    for c in &a.cases {
        out.push_str(&format!(
            "| {} / {} | {} | {:?} | {:?} | {:?} | {:?} | {:?} | {} / {:?} | {} |\n",
            escaped(&c.verification_id),
            escaped(&c.case_id),
            escaped(&format!(
                "{} / {}",
                c.path_id,
                c.phase_id.as_deref().unwrap_or("current")
            )),
            c.verdict,
            c.reason_code,
            c.evidence_kinds,
            c.executions,
            c.outcomes,
            c.source_ids
                .iter()
                .map(|s| escaped(s))
                .collect::<Vec<_>>()
                .join(", "),
            c.source_verifications,
            c.evidence_runs
                .iter()
                .map(|s| escaped(s))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out.push_str("\n未実施・不足・非対応のcaseはUnknownのままです。各caseの理由に対応する証拠を揃えて再評価してください。phase/epochをまたぐ評価には事前計画、参照の一致した前後snapshot、実観測と後条件・比較条件の一致を要求します。\n");
    if !a.limitations.is_empty() {
        out.push_str(&format!("\n制限: {:?}\n", a.limitations));
    }
    out
}
