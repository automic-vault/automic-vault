use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

const USAGE: &str = "usage: av dotenv resolve --schema PATH --item NAME --key NAME";

struct Options {
    schema: PathBuf,
    item: String,
    key: String,
}

pub(super) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let options = match parse(args) {
        Ok(options) => options,
        Err(err) => {
            let _ = writeln!(stderr, "av dotenv: {err}\n{USAGE}");
            return 2;
        }
    };
    match crate::secrets::resolve_dotenv_secret(
        &options.schema.to_string_lossy(),
        &options.item,
        &options.key,
    ) {
        Ok(value) => match stdout.write_all(value.as_bytes()) {
            Ok(()) => 0,
            Err(err) => {
                let _ = writeln!(stderr, "av dotenv: failed to write resolved value: {err}");
                1
            }
        },
        Err(err) => {
            let _ = writeln!(stderr, "av dotenv: {err}");
            1
        }
    }
}

fn parse(args: Vec<OsString>) -> Result<Options, String> {
    let mut args = args.into_iter();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("resolve")) {
        return Err("expected `resolve`".into());
    }
    let mut schema = None;
    let mut item = None;
    let mut key = None;
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {}", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--schema") if schema.is_none() => schema = Some(value),
            Some("--item") if item.is_none() => item = value.into_string().ok(),
            Some("--key") if key.is_none() => key = value.into_string().ok(),
            _ => return Err(format!("unexpected option {}", flag.to_string_lossy())),
        }
    }
    let schema = std::fs::canonicalize(schema.ok_or_else(|| "missing --schema".to_string())?)
        .map_err(|err| format!("failed to resolve schema: {err}"))?;
    if schema.file_name().and_then(|name| name.to_str()) != Some(".env.schema") || !schema.is_file()
    {
        return Err("schema must be a regular file named .env.schema".into());
    }
    let item = item.ok_or_else(|| "missing or invalid --item".to_string())?;
    let key = key.ok_or_else(|| "missing or invalid --key".to_string())?;
    super::inject::validate_key_name(&item)?;
    super::inject::validate_key_name(&key)?;
    Ok(Options { schema, item, key })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_a_real_root_schema_and_static_keys() {
        let dir = std::env::temp_dir().join(format!("av-dotenv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let schema = dir.join(".env.schema");
        std::fs::write(&schema, "SECRET=av()\n").unwrap();

        let options = parse(vec![
            "resolve".into(),
            "--schema".into(),
            schema.as_os_str().into(),
            "--item".into(),
            "SECRET".into(),
            "--key".into(),
            "VAULT_SECRET".into(),
        ])
        .unwrap();
        assert_eq!(options.schema, std::fs::canonicalize(&schema).unwrap());
        assert_eq!(options.item, "SECRET");
        assert_eq!(options.key, "VAULT_SECRET");
        assert!(
            parse(vec![
                "resolve".into(),
                "--schema".into(),
                schema.as_os_str().into(),
                "--item".into(),
                "dynamic-name".into(),
                "--key".into(),
                "SECRET".into(),
            ])
            .is_err()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
