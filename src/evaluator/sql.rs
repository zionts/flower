//! Opt-in SQL catalog metadata. No collection is exposed by default.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[cfg(feature = "sql")]
pub(crate) const NATIVE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "sql")]
pub(crate) const BRIDGE_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "sql")]
pub(crate) const SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
pub(crate) const MAX_SOURCE_ROWS: usize = 10_000;
pub(crate) const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
#[cfg(feature = "sql")]
pub(crate) const MAX_PROVIDER_ROWS: usize = 20_000;
#[cfg(feature = "sql")]
pub(crate) const MAX_PROVENANCE_BYTES: usize = 256 * 1024;
#[cfg(feature = "sql")]
pub(crate) const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub(crate) const BATCH_ROWS: usize = 32;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Catalog {
    pub name: String,
    pub version: String,
    pub authority: String,
    pub tables: Vec<Table>,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Table {
    pub name: String,
    pub sources: Vec<Source>,
    pub columns: Vec<Column>,
    #[serde(default)]
    pub indexes: Vec<Index>,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Source {
    pub name: String,
    #[serde(default)]
    pub json_key: bool,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ColumnType {
    Integer,
    Real,
    Text,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: ColumnType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_key: Option<bool>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Index {
    pub name: String,
    pub columns: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Relationship {
    pub name: String,
    pub from_table: String,
    pub from_columns: Vec<String>,
    pub to_table: String,
    pub to_columns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

pub(crate) fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && ![
            "sql_tables",
            "sql_columns",
            "sql_relationships",
            "sqlite_master",
            "sqlite_schema",
            "sqlite_temp_master",
            "sqlite_temp_schema",
        ]
        .contains(&name)
}
fn distinct<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}
fn text(value: &Option<String>) -> bool {
    value.as_ref().is_none_or(|value| value.len() <= 16384)
}
impl Catalog {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if serde_json::to_vec(self).map_or(true, |bytes| bytes.len() > 128 * 1024) {
            return Err("SQL catalog metadata exceeds 128 KiB");
        }
        if self.name.is_empty()
            || self.name.len() > 128
            || self.version.is_empty()
            || self.version.len() > 128
            || self.authority.is_empty()
            || self.tables.is_empty()
            || self.tables.len() > 64
            || self.relationships.len() > 128
            || !distinct(self.tables.iter().map(|table| table.name.as_str()))
        {
            return Err("Invalid SQL catalog");
        }
        for table in &self.tables {
            if !identifier(&table.name)
                || table.provider.is_empty()
                || table.sources.is_empty()
                || table.sources.len() > 8
                || table.sources.iter().any(|source| source.name.is_empty())
                || !distinct(table.sources.iter().map(|source| source.name.as_str()))
                || table.columns.is_empty()
                || table.columns.len() > 64
                || !distinct(table.columns.iter().map(|column| column.name.as_str()))
                || table.indexes.len() > 16
                || !text(&table.description)
                || !text(&table.grain)
                || !text(&table.coverage)
            {
                return Err("Invalid SQL table");
            }
            for column in &table.columns {
                if !identifier(&column.name)
                    || column.source_field.as_ref().is_some_and(String::is_empty)
                    || column.source_key == Some(false)
                    || (column.source_key.is_some() && column.source_field.is_some())
                    || (column.source_key == Some(true) && column.column_type != ColumnType::Text)
                    || !text(&column.description)
                    || !text(&column.logical_type)
                    || !text(&column.unit)
                {
                    return Err("Invalid SQL column");
                }
            }
            for index in &table.indexes {
                if index.name.is_empty()
                    || index.columns.is_empty()
                    || !distinct(index.columns.iter().map(String::as_str))
                    || index.columns.iter().any(|name| {
                        !table
                            .columns
                            .iter()
                            .any(|column| column.name == *name && column.source_field.is_some())
                    })
                {
                    return Err("Invalid SQL index");
                }
            }
        }
        if !distinct(
            self.relationships
                .iter()
                .map(|relationship| relationship.name.as_str()),
        ) {
            return Err("Duplicate SQL relationship");
        }
        for relationship in &self.relationships {
            if !identifier(&relationship.name)
                || relationship.from_columns.is_empty()
                || relationship.from_columns.len() != relationship.to_columns.len()
                || !text(&relationship.description)
            {
                return Err("Invalid SQL relationship");
            }
            for (name, columns) in [
                (&relationship.from_table, &relationship.from_columns),
                (&relationship.to_table, &relationship.to_columns),
            ] {
                let Some(table) = self.tables.iter().find(|table| table.name == *name) else {
                    return Err("Invalid SQL relationship table");
                };
                if !distinct(columns.iter().map(String::as_str))
                    || columns
                        .iter()
                        .any(|name| !table.columns.iter().any(|column| column.name == *name))
                {
                    return Err("Invalid SQL relationship column");
                }
            }
        }
        Ok(())
    }
    pub(crate) fn allocation_cost(&self) -> usize {
        serde_json::to_vec(self).map_or(usize::MAX, |encoded| {
            encoded.len().saturating_mul(8).saturating_add(4096)
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TerminalMethod {
    pub catalog: String,
    pub operation: Operation,
    pub finalizer: String,
    #[serde(default)]
    pub signing_keys: Vec<serde_json::Value>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Operation {
    Query,
    Explain,
    Catalog,
    Cancel,
}

impl TerminalMethod {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if !identifier(&self.catalog)
            || self.finalizer.is_empty()
            || self.finalizer.len() > 256
            || self.signing_keys.len() > 8
        {
            return Err("Invalid terminal SQL metadata");
        }
        if !distinct(
            self.signing_keys
                .iter()
                .filter_map(|key| key["name"].as_str()),
        ) || self.signing_keys.iter().any(|key| {
            !key["usages"]
                .as_array()
                .is_some_and(|usages| usages.iter().any(|usage| usage == "sign"))
        }) {
            return Err("Invalid terminal SQL signing keys");
        }
        Ok(())
    }
}
