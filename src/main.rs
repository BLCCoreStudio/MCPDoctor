use std::{env, fs, process};

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
    if lower.contains("\"token\"") || lower.contains("\"api_key\"") || lower.contains("\"api-key\"") {
        out.push("MCP003 possible inline credential field detected");
    }
    if lower.contains("\"/\"") && (lower.contains("filesystem") || lower.contains("allowed")) {
        out.push("MCP004 possible filesystem-root access detected");
    }

    out
}

fn help() {
    println!("MCPDoctor 0.1.0-dev\n\nUSAGE:\n  mcpdoctor scan <CONFIG>\n\nCurrent rules are conservative development-preview heuristics.");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        help();
        return;
    }
    if args[0] == "--version" || args[0] == "-V" {
        println!("mcpdoctor 0.1.0-dev");
        return;
    }
    if args.len() != 2 || args[0] != "scan" {
        eprintln!("mcpdoctor: expected 'scan <CONFIG>'");
        process::exit(2);
    }

    let text = match fs::read_to_string(&args[1]) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("mcpdoctor: failed to read '{}': {err}", args[1]);
            process::exit(2);
        }
    };

    let found = findings(&text);
    if found.is_empty() {
        println!("PASS: no current development-preview rule matched");
        return;
    }

    for item in &found {
        println!("WARN: {item}");
    }
    process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::findings;

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
}
