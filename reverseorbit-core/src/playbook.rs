use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::models::*;

// ── Keyword lists ─────────────────────────────────────────────────────────────

pub fn suspicious_import_keywords() -> &'static [&'static str] {
    &[
        // ── Network ──────────────────────────────────────────────────────────
        "socket",
        "connect",
        "send",
        "recv",
        "bind",
        "listen",
        "accept",
        "wsastartup",
        "wsaconnect",
        "wsasend",
        "wsarecv",
        "internetopen",
        "internetconnect",
        "internetreadfile",
        "urldownloadtofile",
        "winhttpopenrequest",
        // ── Process / code execution ─────────────────────────────────────────
        "exec",
        "system",
        "popen",
        "fork",
        "createprocess",
        "shellexecute",
        "winexec",
        "createthread",
        "createremotethread",
        "resumethread",
        "rtlcreateuserthread",
        // ── Anti-debug / anti-analysis (critical for crackmes) ───────────────
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "ntsetinformationthread",
        "outputdebugstringa",
        "outputdebugstringw",
        "findwindowa",
        "findwindoww",
        "getforegroundwindow",
        "blockinput",
        "debugactiveprocess",
        "ptrace",
        "sysctl",
        "getppid",
        // ── String comparison (KEY crackme indicator) ────────────────────────
        "strcmp",
        "strcmpi",
        "stricmp",
        "strncmp",
        "strncmpi",
        "_strcmp",
        "_stricmp",
        "_strncmp",
        "_strnicmp",
        "lstrcmpa",
        "lstrcmpw",
        "lstrcmpia",
        "lstrcmpiw",
        "memcmp",
        "bcmp",
        "rtlcomparememory",
        "rtlequalememory",
        "comparedstring",
        "comparestringa",
        "comparestringw",
        // ── User input capture (crackme serial entry) ────────────────────────
        "getwindowtexta",
        "getwindowtextw",
        "getdlgitemtexta",
        "getdlgitemtextw",
        "getdlgitemint",
        "readconsolea",
        "readconsolew",
        "scanfa",
        "scanf",
        "gets",
        "fgets",
        // ── Memory manipulation ──────────────────────────────────────────────
        "virtualalloc",
        "virtualprotect",
        "virtualallocex",
        "virtualprotectex",
        "writeprocessmemory",
        "readprocessmemory",
        "mprotect",
        "mmap",
        // ── Dynamic loading / injection ──────────────────────────────────────
        "loadlibrary",
        "loadlibrarya",
        "loadlibraryw",
        "loadlibraryex",
        "getprocaddress",
        "dlopen",
        "dlsym",
        "ldrloaddll",
        "ldrgetprocedureaddress",
        // ── Crypto ───────────────────────────────────────────────────────────
        "cryptcreatehash",
        "crypthashdata",
        "cryptderivekey",
        "cryptencrypt",
        "cryptdecrypt",
        "cryptgenrandom",
        "bcryptcreatehash",
        "bcryptfinishhash",
        // ── Registry ─────────────────────────────────────────────────────────
        "regsetvalue",
        "regqueryvalue",
        "regopenkey",
        "regcreatekey",
        // ── Persistence ──────────────────────────────────────────────────────
        "launchctl",
        "crontab",
        "chmod",
        "chown",
    ]
}

pub fn suspicious_string_keywords() -> &'static [&'static str] {
    &[
        // ── Network indicators ────────────────────────────────────────────────
        "http://",
        "https://",
        "ws://",
        "wss://",
        "ftp://",
        // ── Credentials ───────────────────────────────────────────────────────
        "token",
        "secret",
        "password",
        "api_key",
        "passwd",
        // ── Crypto / encoding markers ─────────────────────────────────────────
        "base64",
        "aes",
        "rsa",
        "sha1",
        "sha256",
        "sha512",
        "md5",
        "rc4",
        "xor",
        "encode",
        "decode",
        "encrypt",
        "decrypt",
        // ── Crackme validation messages (most important) ──────────────────────
        "correct",
        "wrong",
        "congratulation",
        "nice try",
        "bad boy",
        "good boy",
        "bad girl",
        "good girl",
        "you win",
        "you lose",
        "you did it",
        "great job",
        "well done",
        "access denied",
        "access granted",
        "unlocked",
        "key valid",
        "key invalid",
        "invalid key",
        "valid key",
        "serial valid",
        "serial invalid",
        "invalid serial",
        "license valid",
        "license invalid",
        "invalid license",
        "try again",
        "try harder",
        "registration successful",
        "thank you for registering",
        "unregistered",
        "registered",
        // ── Crackme input prompts ─────────────────────────────────────────────
        "enter your",
        "enter the",
        "your serial",
        "your key",
        "your name",
        "your password",
        "enter serial",
        "enter key",
        "enter password",
        "serial number",
        "serial:",
        "key:",
        "username:",
        "password:",
        "registration code",
        "enter code",
        "activation code",
        // ── License / protection ──────────────────────────────────────────────
        "serial",
        "license",
        "keygen",
        "crack",
        "patch",
        "activation",
        "activate",
        "registration",
        "shareware",
        "trial",
        "evaluation",
        "buy now",
        // ── System / persistence ──────────────────────────────────────────────
        "launchctl",
        "crontab",
        "/tmp/",
        "curl ",
        "wget ",
        "debug",
        "proxy",
        // ── Suspicious paths ──────────────────────────────────────────────────
        "system32",
        "appdata",
        "temp\\",
        "programdata",
    ]
}

// ── Teaching summaries ────────────────────────────────────────────────────────

pub fn finding_teaching_summary(finding: &Finding) -> String {
    match finding.category.as_str() {
        "anti_debug" => {
            "Anti-debug technique detected. Crackmes use these to exit or behave differently when a debugger is attached. \
             Use xrefs to find the check, then patch the conditional jump (JZ→JNZ or NOP the call) or set a breakpoint \
             before it and modify EAX/RAX to spoof the result."
        }
        "string_comparison" => {
            "A string or memory comparison function was imported. This is the most direct crackme indicator — \
             the serial/key you enter is very likely compared here. Use xrefs to find which function calls this import, \
             then disassemble it: the valid key is often passed as one of the arguments to strcmp/memcmp."
        }
        "input_capture" => {
            "The binary captures user input (dialog text, console input). The value entered by the user flows from \
             here into the key-validation logic. Trace the return value forward with xrefs to find the comparison site."
        }
        "crackme_validation" => {
            "A validation response string was found embedded in the binary. Strings like 'Correct!' or 'Bad Boy!' \
             mark the two branches of the key check. Use string xrefs to find the conditional jump that decides which \
             branch is taken, then trace backwards to the comparison that drives it."
        }
        "license_check" => {
            "License/registration terminology detected. This often points to a serial-number or name-based key check. \
             Search for xrefs to these strings and work backwards through the call chain to the validation logic."
        }
        "code_injection" | "memory_manipulation" => {
            "Memory protection or process-memory API detected. This is used for self-modifying code, packing, or \
             injecting shellcode. The code may decrypt or unpack itself at runtime — set a breakpoint on VirtualProtect \
             and dump the unpacked image after it executes."
        }
        "crypto_operation" => {
            "Cryptographic API detected. The binary may hash the entered key and compare it to a stored hash, or \
             use a derived key to decrypt a payload. Find what is hashed (the user input?) and what it is compared against."
        }
        "dynamic_loading" => {
            "Dynamic library loading detected. APIs may be resolved at runtime to evade static analysis. \
             Set a breakpoint on GetProcAddress and log all resolved names to build the real import table."
        }
        "network_behavior" | "network_indicator" => {
            "Network indicator found. Trace xrefs to find where traffic originates and what data is transmitted."
        }
        "execution_chain" => {
            "Process execution primitive detected. Trace callers to identify how commands are composed."
        }
        "credential_indicator" => {
            "Credential-like strings found. Track references to learn whether values are hardcoded or runtime."
        }
        "crypto_indicator" => {
            "Cryptography markers found. Follow references to see what is being protected."
        }
        _ => {
            "ReverseOrbit produced a finding. Follow evidence references and next actions to validate it."
        }
    }.to_string()
}

// ── Main analysis engine ──────────────────────────────────────────────────────

pub fn generate_findings_and_actions(
    case_id: &str,
    snapshot: &NormalizedSnapshot,
) -> (Vec<Finding>, Vec<NextAction>) {
    let mut findings = Vec::new();
    let mut actions = Vec::new();

    // ── Import-based findings ─────────────────────────────────────────────────
    for import_name in &snapshot.suspicious_imports {
        let lower = import_name.to_ascii_lowercase();

        let (category, title, severity, rationale) = categorize_import(&lower, import_name);
        let finding_id = Uuid::new_v4().to_string();
        let rule_id = format!("import.{category}");

        let action = NextAction {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            title: format!("Inspect xrefs for {import_name}"),
            why: "Pivot from the imported capability to every function that depends on it.".to_string(),
            how: "Collect radare2 xrefs and disassemble the most relevant callers.".to_string(),
            action_type: "inspect_xrefs".to_string(),
            params: json!({ "target": import_name, "target_kind": "import" }),
            related_entity_ids: vec![import_name.clone()],
            related_finding_ids: vec![finding_id.clone()],
            generated_from: Some(rule_id.clone()),
            skip_consequences: "Skipping hides the calling context that turns an indicator into confirmed behavior.".to_string(),
            execution_path: Vec::new(),
            created_at: Utc::now(),
            status: NextActionStatus::Pending,
        };

        let confidence = match category {
            "string_comparison" | "input_capture" | "crackme_validation" => 0.91,
            "anti_debug" | "code_injection" | "memory_manipulation" => 0.88,
            "crypto_operation" | "dynamic_loading" => 0.82,
            _ => 0.76,
        };

        findings.push(Finding {
            id: finding_id,
            case_id: case_id.to_string(),
            title,
            summary: format!(
                "{import_name} triggered a deterministic reverse-engineering playbook."
            ),
            category: category.to_string(),
            severity,
            status: FindingStatus::New,
            rationale,
            confidence,
            source: "radare2".to_string(),
            tags: vec!["import".to_string(), category.to_string()],
            entity_refs: vec![EntityRef {
                kind: "import".to_string(),
                id: import_name.clone(),
                label: Some(import_name.clone()),
            }],
            evidence: vec![EvidenceItem {
                label: "Suspicious import".to_string(),
                entity_id: Some(import_name.clone()),
                artifact_id: None,
                snippet: Some(import_name.clone()),
                metadata: json!({ "import": import_name }),
            }],
            playbook_rule_id: rule_id,
            playbook_rule_kind: Some(PlaybookRuleKind::SuspiciousImport),
            inference_chain: import_inference_chain(import_name, category),
            confidence_rationale:
                "Confidence weighted by deterministic keyword match and expected pivot value."
                    .to_string(),
            counter_evidence: vec![
                "No runtime validation yet; indicator may be dead code.".to_string(),
            ],
            next_action_ids: vec![action.id.clone()],
            created_at: Utc::now(),
        });
        actions.push(action);
    }

    // ── String-based findings ─────────────────────────────────────────────────
    for string in &snapshot.suspicious_strings {
        let lower = string.to_ascii_lowercase();
        let (category, severity, why) = categorize_string(&lower);
        let finding_id = Uuid::new_v4().to_string();
        let rule_id = format!("string.{category}");

        let action = NextAction {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            title: format!("Inspect xrefs for string `{}`", truncate_for_title(string)),
            why: "Find every function that references this string to reach the validation logic.".to_string(),
            how: "Use radare2 xref collection and follow the call chain into the key-check function.".to_string(),
            action_type: "inspect_xrefs".to_string(),
            params: json!({ "target": string, "target_kind": "string" }),
            related_entity_ids: vec![string.clone()],
            related_finding_ids: vec![finding_id.clone()],
            generated_from: Some(rule_id.clone()),
            skip_consequences: "Skipping string xrefs can miss the branch that distinguishes valid from invalid input.".to_string(),
            execution_path: Vec::new(),
            created_at: Utc::now(),
            status: NextActionStatus::Pending,
        };

        findings.push(Finding {
            id: finding_id,
            case_id: case_id.to_string(),
            title: format!("Interesting string: {}", truncate_for_title(string)),
            summary: "ReverseOrbit flagged this string because it matches a crackme or suspicious pattern.".to_string(),
            category: category.to_string(),
            severity,
            status: FindingStatus::New,
            rationale: why,
            confidence: match category {
                "crackme_validation" => 0.93,
                "license_check" => 0.87,
                "credential_indicator" => 0.84,
                _ => 0.71,
            },
            source: "radare2".to_string(),
            tags: vec!["string".to_string(), category.to_string()],
            entity_refs: vec![EntityRef {
                kind: "string".to_string(),
                id: string.clone(),
                label: Some(truncate_for_title(string)),
            }],
            evidence: vec![EvidenceItem {
                label: "Suspicious string".to_string(),
                entity_id: Some(string.clone()),
                artifact_id: None,
                snippet: Some(string.clone()),
                metadata: json!({ "string": string }),
            }],
            playbook_rule_id: rule_id,
            playbook_rule_kind: Some(PlaybookRuleKind::SuspiciousString),
            inference_chain: string_inference_chain(string, category),
            confidence_rationale: "Confidence combines keyword specificity and likelihood of active use.".to_string(),
            counter_evidence: vec!["No call-site verification yet; may be unused resource data.".to_string()],
            next_action_ids: vec![action.id.clone()],
            created_at: Utc::now(),
        });
        actions.push(action);
    }

    // ── Hot-function CFG expansion actions ────────────────────────────────────
    for function in snapshot.functions.iter().take(5) {
        let action = NextAction {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            title: format!("Expand CFG for {}", function.name),
            why: "Hot functions with high cyclomatic complexity or call degree often contain orchestration logic or key checks.".to_string(),
            how: "Collect function disassembly and CFG JSON from radare2 to expose branch structure.".to_string(),
            action_type: "expand_cfg".to_string(),
            params: json!({ "function": function.name, "addr": function.addr }),
            related_entity_ids: vec![function.name.clone()],
            related_finding_ids: Vec::new(),
            generated_from: Some("function.hot_function_heuristic".to_string()),
            skip_consequences: "Skipping CFG expansion hides branch structure and control transitions inside high-impact functions.".to_string(),
            execution_path: Vec::new(),
            created_at: Utc::now(),
            status: NextActionStatus::Pending,
        };
        actions.push(action);
    }

    (findings, actions)
}

// ── Import categorisation ──────────────────────────────────────────────────────

fn categorize_import(lower: &str, name: &str) -> (&'static str, String, FindingSeverity, String) {
    // String comparison — most direct crackme indicator
    if lower.contains("strcmp")
        || lower.contains("strcmpi")
        || lower.contains("stricmp")
        || lower.contains("lstrcmp")
        || lower.contains("memcmp")
        || lower.contains("bcmp")
        || lower.contains("rtlcompare")
        || lower.contains("comparestring")
    {
        return (
            "string_comparison",
            format!("Key comparison function imported: {name}"),
            FindingSeverity::Critical,
            "This function directly compares strings or memory blocks. In crackmes it is almost always \
             the comparison between the entered key and the expected value. Trace xrefs to find the call site."
                .to_string(),
        );
    }
    // Input capture
    if lower.contains("getwindowtext")
        || lower.contains("getdlgitemtext")
        || lower.contains("getdlgitemint")
        || lower.contains("readconsole")
        || lower.contains("scanf")
        || lower.contains("fgets")
    {
        return (
            "input_capture",
            format!("User input capture function: {name}"),
            FindingSeverity::High,
            "This function retrieves text typed by the user. The returned value feeds into the key-validation logic."
                .to_string(),
        );
    }
    // Anti-debug
    if lower.contains("isdebuggerpresent")
        || lower.contains("checkremotedebugger")
        || lower.contains("ntqueryinformationprocess")
        || lower.contains("ntsetinformationthread")
        || lower.contains("outputdebugstring")
        || lower.contains("findwindow")
        || lower.contains("ptrace")
        || lower.contains("sysctl")
        || lower.contains("getppid")
    {
        return (
            "anti_debug",
            format!("Anti-debug technique detected: {name}"),
            FindingSeverity::High,
            "Anti-debugging or environment-detection API. Patch the conditional branch after this call or \
             spoof the return value to bypass the check."
                .to_string(),
        );
    }
    // Memory manipulation
    if lower.contains("virtualprotect")
        || lower.contains("virtualalloc")
        || lower.contains("writeprocessmemory")
        || lower.contains("readprocessmemory")
        || lower.contains("mprotect")
        || lower.contains("mmap")
    {
        return (
            "memory_manipulation",
            format!("Memory manipulation API: {name}"),
            FindingSeverity::Critical,
            "Memory protection or cross-process memory API. Used for self-modifying code, packers, and injection."
                .to_string(),
        );
    }
    // Crypto
    if lower.contains("crypt") || lower.contains("bcrypt") || lower.contains("hash") {
        return (
            "crypto_operation",
            format!("Cryptographic API: {name}"),
            FindingSeverity::Medium,
            "Cryptographic operation detected. The binary may hash the user input and compare the digest."
                .to_string(),
        );
    }
    // Dynamic loading
    if lower.contains("loadlibrary")
        || lower.contains("getprocaddress")
        || lower.contains("dlopen")
        || lower.contains("dlsym")
        || lower.contains("ldrloaddll")
    {
        return (
            "dynamic_loading",
            format!("Dynamic API resolution: {name}"),
            FindingSeverity::Medium,
            "APIs are resolved at runtime, hiding the real import table from static analysis."
                .to_string(),
        );
    }
    // Network
    if lower.contains("socket")
        || lower.contains("connect")
        || lower.contains("send")
        || lower.contains("recv")
        || lower.contains("internetopen")
        || lower.contains("urldownload")
    {
        return (
            "network_behavior",
            format!("Network-capable import: {name}"),
            FindingSeverity::Medium,
            "Import can initiate or sustain network communication.".to_string(),
        );
    }
    // Execution
    if lower.contains("exec")
        || lower.contains("system")
        || lower.contains("popen")
        || lower.contains("createprocess")
        || lower.contains("shellexecute")
        || lower.contains("createthread")
    {
        return (
            "execution_chain",
            format!("Execution primitive: {name}"),
            FindingSeverity::High,
            "Import can spawn commands, processes, or threads.".to_string(),
        );
    }
    (
        "suspicious_import",
        format!("Suspicious import: {name}"),
        FindingSeverity::Low,
        "Import matched a static suspicion keyword.".to_string(),
    )
}

// ── String categorisation ─────────────────────────────────────────────────────

fn categorize_string(lower: &str) -> (&'static str, FindingSeverity, String) {
    // Crackme validation responses (highest priority)
    if lower.contains("correct")
        || lower.contains("wrong")
        || lower.contains("congratul")
        || lower.contains("bad boy")
        || lower.contains("good boy")
        || lower.contains("bad girl")
        || lower.contains("good girl")
        || lower.contains("you win")
        || lower.contains("you lose")
        || lower.contains("well done")
        || lower.contains("you did it")
        || lower.contains("great job")
        || lower.contains("try again")
        || lower.contains("try harder")
        || lower.contains("access granted")
        || lower.contains("access denied")
        || lower.contains("key valid")
        || lower.contains("key invalid")
        || lower.contains("serial valid")
        || lower.contains("invalid serial")
        || lower.contains("invalid key")
    {
        return (
            "crackme_validation",
            FindingSeverity::Critical,
            "This string is a validation response — it marks the 'success' or 'failure' branch of the key check. \
             Use xrefs to find the conditional jump that decides which branch runs."
                .to_string(),
        );
    }
    // License / serial check
    if lower.contains("serial")
        || lower.contains("license")
        || lower.contains("keygen")
        || lower.contains("crack")
        || lower.contains("patch")
        || lower.contains("registered")
        || lower.contains("registration")
        || lower.contains("activation")
        || lower.contains("enter your")
        || lower.contains("your key")
        || lower.contains("your serial")
        || lower.contains("enter serial")
        || lower.contains("enter key")
        || lower.contains("serial:")
        || lower.contains("enter code")
        || lower.contains("activation code")
    {
        return (
            "license_check",
            FindingSeverity::High,
            "License, serial, or registration terminology. Likely close to the key-validation entry point."
                .to_string(),
        );
    }
    // Network
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
        || lower.starts_with("ftp://")
    {
        return (
            "network_indicator",
            FindingSeverity::High,
            "Embedded URL or endpoint. Trace xrefs to find where the request is made.".to_string(),
        );
    }
    // Credentials
    if lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("api_key")
        || lower.contains("passwd")
    {
        return (
            "credential_indicator",
            FindingSeverity::High,
            "Credential-like string. May be a hardcoded secret or runtime placeholder.".to_string(),
        );
    }
    // Crypto markers
    if lower.contains("aes")
        || lower.contains("rsa")
        || lower.contains("rc4")
        || lower.contains("sha")
        || lower.contains("md5")
        || lower.contains("xor")
        || lower.contains("base64")
        || lower.contains("encrypt")
        || lower.contains("decrypt")
    {
        return (
            "crypto_indicator",
            FindingSeverity::Medium,
            "Cryptographic or encoding marker. May indicate key derivation or payload protection."
                .to_string(),
        );
    }
    (
        "suspicious_string",
        FindingSeverity::Low,
        "String matched a static suspicion keyword and may expose execution intent.".to_string(),
    )
}

// ── Inference chain builders ───────────────────────────────────────────────────

fn import_inference_chain(name: &str, category: &str) -> Vec<InferenceStep> {
    vec![
        InferenceStep {
            premise: format!("Import `{name}` is present in the binary's import table."),
            conclusion: "This API is available to the binary and may be called at runtime."
                .to_string(),
            confidence_contribution: 0.45,
        },
        InferenceStep {
            premise: format!("Import matched deterministic rule for category `{category}`."),
            conclusion: format!("Create xref pivot action to locate call sites of `{name}`."),
            confidence_contribution: 0.40,
        },
    ]
}

fn string_inference_chain(s: &str, category: &str) -> Vec<InferenceStep> {
    vec![
        InferenceStep {
            premise: format!(
                "String `{}` present in extracted string table.",
                truncate_for_title(s)
            ),
            conclusion: "String contains suspicious tokens or validation markers.".to_string(),
            confidence_contribution: 0.42,
        },
        InferenceStep {
            premise: format!("String matched deterministic policy for category `{category}`."),
            conclusion: "Create xref pivot to identify referencing functions.".to_string(),
            confidence_contribution: 0.35,
        },
    ]
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn truncate_for_title(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() > 48 {
        format!("{}...", &trimmed[..48])
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::models::*;
    use chrono::Utc;

    use super::{finding_teaching_summary, suspicious_import_keywords, suspicious_string_keywords};

    #[test]
    fn all_crackme_imports_flagged() {
        let crackme = [
            "strcmp",
            "lstrcmpa",
            "GetWindowTextA",
            "IsDebuggerPresent",
            "memcmp",
        ];
        for kw in crackme {
            let lower = kw.to_ascii_lowercase();
            let found = suspicious_import_keywords()
                .iter()
                .any(|k| lower.contains(k));
            assert!(found, "crackme import `{kw}` should be in the keyword list");
        }
    }

    #[test]
    fn crackme_strings_flagged() {
        let strings = [
            "Correct!",
            "Wrong key",
            "Bad Boy",
            "Congratulations",
            "Enter your serial",
        ];
        for s in strings {
            let lower = s.to_ascii_lowercase();
            let found = suspicious_string_keywords()
                .iter()
                .any(|k| lower.contains(k));
            assert!(found, "crackme string `{s}` should be in the keyword list");
        }
    }

    #[test]
    fn teaching_summary_for_string_comparison_is_specific() {
        let finding = Finding {
            id: "f1".into(),
            case_id: "c1".into(),
            title: "test".into(),
            summary: "test".into(),
            category: "string_comparison".into(),
            severity: FindingSeverity::Critical,
            status: FindingStatus::New,
            rationale: "test".into(),
            confidence: 0.9,
            source: "test".into(),
            tags: vec![],
            entity_refs: vec![],
            evidence: vec![],
            playbook_rule_id: "".into(),
            playbook_rule_kind: None,
            inference_chain: vec![],
            confidence_rationale: "".into(),
            counter_evidence: vec![],
            next_action_ids: vec![],
            created_at: Utc::now(),
        };
        let summary = finding_teaching_summary(&finding);
        assert!(summary.contains("strcmp") || summary.contains("comparison"));
    }

    #[test]
    fn teaching_summary_crackme_validation_mentions_branch() {
        let finding = Finding {
            id: "f2".into(),
            case_id: "c1".into(),
            title: "test".into(),
            summary: "test".into(),
            category: "crackme_validation".into(),
            severity: FindingSeverity::Critical,
            status: FindingStatus::New,
            rationale: "test".into(),
            confidence: 0.9,
            source: "test".into(),
            tags: vec![],
            entity_refs: vec![],
            evidence: vec![],
            playbook_rule_id: "".into(),
            playbook_rule_kind: None,
            inference_chain: vec![],
            confidence_rationale: "".into(),
            counter_evidence: vec![],
            next_action_ids: vec![],
            created_at: Utc::now(),
        };
        let summary = finding_teaching_summary(&finding);
        assert!(!summary.is_empty());
    }
}
