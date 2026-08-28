use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

fn findings(text: &str) -> Vec<&'static str> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();

    if lower.contains("http://") {
        out.push("MCP001 plaintext HTTP endpoint detected");
    }
    if lower.contains("\"command\"")
        && (lower.contains("bash") || lower.contains("powershell") || lower.contains("/bin/sh"))
    {
        out.push("MCP002 shell-capable server command detected");
    }
    if lower.contains("\"token\"") || lower.contains("\"api_key\"") || lower.contains("\"api-key\"")
    {
        out.push("MCP003 possible inline credential field detected");
    }
    if lower.contains("\"/\"") && (lower.contains("filesystem") || lower.contains("allowed")) {
        out.push("MCP004 possible filesystem-root access detected");
    }

    out
}

fn extract_json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let colon = rest.find(':')?;
    let mut chars = rest[colon + 1..].char_indices();
    let (_, first) = chars.find(|(_, ch)| !ch.is_whitespace())?;
    if first != '"' {
        return None;
    }

    let value_start = rest[colon + 1..].find('"')? + colon + 2;
    let value = &rest[value_start..];
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some(value[..index].to_owned()),
            _ => {}
        }
    }
    None
}

fn executable_path(command: &str) -> Option<PathBuf> {
    let path = Path::new(command);
    if command.contains('/') {
        return path.exists().then(|| path.to_path_buf());
    }

    let path_env = env::var_os("PATH")?;
    for directory in env::split_paths(&path_env) {
        let candidate = directory.join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("failed to read '{}': {error}", path.display()))
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create '{}': {error}", parent.display()))?;
        }
    }

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "baseline path has no UTF-8 file name".to_owned())?;
    let temp = path.with_file_name(format!(".{file_name}.tmp.{}", process::id()));
    fs::write(&temp, content)
        .map_err(|error| format!("failed to write '{}': {error}", temp.display()))?;
    fs::rename(&temp, path)
        .map_err(|error| format!("failed to replace '{}': {error}", path.display()))?;
    Ok(())
}

fn save_baseline(config: &Path, baseline: &Path) -> Result<usize, String> {
    if config == baseline {
        return Err("config and baseline paths must be different".to_owned());
    }
    let content = read_bytes(config)?;
    atomic_write(baseline, &content)?;
    Ok(content.len())
}

fn first_difference(left: &[u8], right: &[u8]) -> Option<usize> {
    let shared = left.len().min(right.len());
    for index in 0..shared {
        if left[index] != right[index] {
            return Some(index);
        }
    }
    (left.len() != right.len()).then_some(shared)
}

fn line_at_byte(content: &[u8], byte: usize) -> usize {
    content[..byte.min(content.len())]
        .iter()
        .filter(|value| **value == b'\n')
        .count()
        + 1
}

fn check_baseline(config: &Path, baseline: &Path) -> Result<Option<(usize, usize, usize)>, String> {
    let current = read_bytes(config)?;
    let expected = read_bytes(baseline)?;
    let Some(byte) = first_difference(&current, &expected) else {
        return Ok(None);
    };
    let line = line_at_byte(&current, byte);
    Ok(Some((byte, line, current.len())))
}

fn scan_config(path: &str) -> Result<i32, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("failed to read '{path}': {error}"))?;
    let found = findings(&text);
    if found.is_empty() {
        println!("PASS: no current security/configuration rule matched");
        return Ok(0);
    }
    for item in found {
        println!("WARN: {item}");
    }
    Ok(3)
}

fn doctor(path: &str) -> Result<i32, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("failed to read '{path}': {error}"))?;
    println!("CONFIG      ✓ readable: {path}");

    let found = findings(&text);
    if found.is_empty() {
        println!("SECURITY    ✓ no current rule matched");
    } else {
        println!("SECURITY    ⚠ {} review signal(s)", found.len());
        for item in &found {
            println!("            - {item}");
        }
    }

    let mut failed = !found.is_empty();
    match extract_json_string(&text, "command") {
        Some(command) => {
            println!("COMMAND     ✓ detected: {command}");
            match executable_path(&command) {
                Some(path) => println!("EXECUTABLE  ✓ {}", path.display()),
                None => {
                    println!("EXECUTABLE  ✗ not found in PATH: {command}");
                    failed = true;
                }
            }
        }
        None => {
            println!("COMMAND     · no top-level command string detected");
            println!("EXECUTABLE  · not checked");
        }
    }

    println!("NETWORK     · no server process was launched");
    println!("HANDSHAKE   · not performed in safe doctor mode");
    println!("RESULT      {}", if failed { "REVIEW" } else { "PASS" });
    Ok(if failed { 3 } else { 0 })
}

fn baseline_command(args: &[String]) -> Result<i32, String> {
    if args.len() != 4 {
        return Err("expected 'baseline <init|update|check> <CONFIG> <BASELINE>'".to_owned());
    }
    let config = Path::new(&args[2]);
    let baseline = Path::new(&args[3]);
    match args[1].as_str() {
        "init" | "update" => {
            let bytes = save_baseline(config, baseline)?;
            println!("BASELINE: wrote {bytes} byte(s) to {}", baseline.display());
            Ok(0)
        }
        "check" => match check_baseline(config, baseline)? {
            None => {
                println!("UNCHANGED: config matches baseline");
                Ok(0)
            }
            Some((byte, line, current_len)) => {
                println!(
                    "CHANGED: first difference near byte {byte}, line {line}; current size {current_len} byte(s)"
                );
                Ok(3)
            }
        },
        _ => Err("baseline action must be init, update, or check".to_owned()),
    }
}

fn help() {
    println!(
        "MCPDoctor 0.2.0-dev\n\nUSAGE:\n  mcpdoctor scan <CONFIG>\n  mcpdoctor doctor <CONFIG>\n  mcpdoctor baseline init <CONFIG> <BASELINE>\n  mcpdoctor baseline update <CONFIG> <BASELINE>\n  mcpdoctor baseline check <CONFIG> <BASELINE>\n\n`doctor` performs safe local diagnostics without launching the configured MCP server. Baseline commands integrate the configuration-drift direction previously explored by MCPWatch."
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        help();
        return;
    }
    if matches!(args[0].as_str(), "--version" | "-V") {
        println!("mcpdoctor 0.2.0-dev");
        return;
    }

    let result = match args[0].as_str() {
        "scan" if args.len() == 2 => scan_config(&args[1]),
        "doctor" if args.len() == 2 => doctor(&args[1]),
        "baseline" => baseline_command(&args),
        "scan" => Err("expected 'scan <CONFIG>'".to_owned()),
        "doctor" => Err("expected 'doctor <CONFIG>'".to_owned()),
        _ => Err("unsupported command; use --help".to_owned()),
    };

    match result {
        Ok(code) if code != 0 => process::exit(code),
        Ok(_) => {}
        Err(error) => {
            eprintln!("mcpdoctor: {error}");
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_json_string, findings, first_difference, line_at_byte};

    #[test]
    fn flags_plain_http() {
        assert!(!findings(r#"{"url":"http://localhost:3000"}"#).is_empty());
    }

    #[test]
    fn flags_shell_server() {
        assert!(!findings(r#"{"command":"bash"}"#).is_empty());
    }

    #[test]
    fn accepts_minimal_stdio_example() {
        assert!(findings(r#"{"command":"node","args":["server.js"]}"#).is_empty());
    }

    #[test]
    fn extracts_command_string() {
        assert_eq!(
            extract_json_string(r#"{"command":"node","args":["server.js"]}"#, "command"),
            Some("node".to_owned())
        );
    }

    #[test]
    fn identical_content_has_no_difference() {
        assert_eq!(first_difference(b"abc", b"abc"), None);
    }

    #[test]
    fn detects_first_changed_byte() {
        assert_eq!(first_difference(b"abc", b"axc"), Some(1));
    }

    #[test]
    fn reports_human_line_number() {
        assert_eq!(line_at_byte(b"one\ntwo\nthree", 5), 2);
    }
}
