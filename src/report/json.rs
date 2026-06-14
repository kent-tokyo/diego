use super::Report;

pub fn generate(report: &Report) -> anyhow::Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}
