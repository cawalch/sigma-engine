//! Test data generation utilities for SIGMA engine benchmarks.

use serde_json::{json, Value};

/// Generate realistic test events for benchmarking.
pub fn create_test_events(count: usize) -> Vec<Value> {
    let event_templates = [
        // Windows Security Events
        json!({
            "EventID": "4624",
            "EventRecordID": "12345",
            "ProcessName": "svchost.exe",
            "CommandLine": "C:\\Windows\\System32\\svchost.exe -k NetworkService",
            "User": "SYSTEM",
            "LogonType": "3",
            "SourceIP": "192.168.1.100",
            "DestinationIP": "10.0.0.1",
            "Port": "445",
            "Protocol": "TCP",
            "Timestamp": "2023-01-01T12:00:00Z"
        }),
        json!({
            "EventID": "4625",
            "EventRecordID": "12346",
            "ProcessName": "winlogon.exe",
            "CommandLine": "winlogon.exe",
            "User": "Administrator",
            "LogonType": "2",
            "SourceIP": "192.168.1.101",
            "FailureReason": "Unknown user name or bad password",
            "Timestamp": "2023-01-01T12:01:00Z"
        }),
        json!({
            "EventID": "4648",
            "EventRecordID": "12347",
            "ProcessName": "lsass.exe",
            "CommandLine": "C:\\Windows\\System32\\lsass.exe",
            "User": "SYSTEM",
            "TargetUser": "service_account",
            "LogonType": "3",
            "Timestamp": "2023-01-01T12:02:00Z"
        }),
        json!({
            "EventID": "4672",
            "EventRecordID": "12348",
            "ProcessName": "explorer.exe",
            "User": "Administrator",
            "PrivilegeList": "SeDebugPrivilege",
            "LogonType": "2",
            "Timestamp": "2023-01-01T12:03:00Z"
        }),
        // Process Creation Events
        json!({
            "EventID": "4688",
            "EventRecordID": "12349",
            "ProcessName": "cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "User": "user1",
            "ParentProcessName": "explorer.exe",
            "ProcessId": "1234",
            "ParentProcessId": "5678",
            "Timestamp": "2023-01-01T12:04:00Z"
        }),
        json!({
            "EventID": "4688",
            "EventRecordID": "12350",
            "ProcessName": "powershell.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File script.ps1",
            "User": "user2",
            "ParentProcessName": "cmd.exe",
            "ProcessId": "2345",
            "ParentProcessId": "1234",
            "Timestamp": "2023-01-01T12:05:00Z"
        }),
        // Network Events
        json!({
            "EventID": "5156",
            "EventRecordID": "12351",
            "ProcessName": "chrome.exe",
            "User": "user1",
            "SourceIP": "192.168.1.100",
            "DestinationIP": "8.8.8.8",
            "SourcePort": "54321",
            "DestinationPort": "443",
            "Protocol": "TCP",
            "Direction": "Outbound",
            "Timestamp": "2023-01-01T12:06:00Z"
        }),
        // File System Events
        json!({
            "EventID": "4663",
            "EventRecordID": "12352",
            "ProcessName": "notepad.exe",
            "User": "user1",
            "ObjectName": "C:\\Users\\user1\\Documents\\sensitive.txt",
            "AccessMask": "0x2",
            "AccessList": "WriteData",
            "Timestamp": "2023-01-01T12:07:00Z"
        }),
    ];

    (0..count)
        .map(|i| {
            let mut event = event_templates[i % event_templates.len()].clone();
            
            // Add some variation to make events unique
            if let Some(record_id) = event.get_mut("EventRecordID") {
                *record_id = json!(format!("{}", 12345 + i));
            }
            
            // Vary some fields for realistic diversity
            match i % 4 {
                0 => {
                    if let Some(source_ip) = event.get_mut("SourceIP") {
                        *source_ip = json!(format!("192.168.1.{}", 100 + (i % 155)));
                    }
                }
                1 => {
                    if let Some(user) = event.get_mut("User") {
                        *user = json!(format!("user_{}", i % 10));
                    }
                }
                2 => {
                    if let Some(process_id) = event.get_mut("ProcessId") {
                        *process_id = json!(format!("{}", 1000 + i));
                    }
                }
                3 => {
                    if let Some(port) = event.get_mut("Port") {
                        *port = json!(format!("{}", 8000 + (i % 1000)));
                    }
                }
                _ => {}
            }
            
            event
        })
        .collect()
}

/// Generate test rules with realistic patterns and overlapping conditions.
pub fn generate_test_rules(count: usize) -> Vec<String> {
    let mut rules = Vec::new();

    // Common fields that will create shared primitives
    let event_ids = ["4624", "4625", "4648", "4672", "4688", "5156", "4663"];
    let process_names = [
        "svchost.exe",
        "winlogon.exe", 
        "lsass.exe",
        "explorer.exe",
        "cmd.exe",
        "powershell.exe",
        "chrome.exe",
        "notepad.exe"
    ];
    let users = ["SYSTEM", "Administrator", "Guest", "user1", "user2"];

    for i in 0..count {
        let event_id = event_ids[i % event_ids.len()];
        let process_name = process_names[i % process_names.len()];
        let user = users[i % users.len()];

        let rule = match i % 5 {
            0 => {
                // Simple rule with single condition
                format!(
                    r#"
title: Simple Test Rule {}
id: test-rule-{:04}
status: experimental
description: Simple test rule for benchmarking
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: {}
    condition: selection
"#,
                    i + 1, i, event_id
                )
            }
            1 => {
                // Rule with two conditions (AND)
                format!(
                    r#"
title: Two Condition Test Rule {}
id: test-rule-{:04}
status: experimental
description: Two condition test rule for benchmarking
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: {}
        ProcessName: {}
    condition: selection
"#,
                    i + 1, i, event_id, process_name
                )
            }
            2 => {
                // Rule with three conditions (AND)
                format!(
                    r#"
title: Three Condition Test Rule {}
id: test-rule-{:04}
status: experimental
description: Three condition test rule for benchmarking
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: {}
        ProcessName: {}
        User: {}
    condition: selection
"#,
                    i + 1, i, event_id, process_name, user
                )
            }
            3 => {
                // Rule with OR conditions
                format!(
                    r#"
title: OR Condition Test Rule {}
id: test-rule-{:04}
status: experimental
description: OR condition test rule for benchmarking
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: {}
        ProcessName: {}
    selection2:
        EventID: {}
        User: {}
    condition: selection1 or selection2
"#,
                    i + 1, i, event_id, process_name, 
                    event_ids[(i + 1) % event_ids.len()], user
                )
            }
            4 => {
                // Complex rule with mixed conditions
                format!(
                    r#"
title: Complex Test Rule {}
id: test-rule-{:04}
status: experimental
description: Complex test rule for benchmarking
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: {}
        ProcessName: {}
    selection2:
        User: {}
    selection3:
        EventID: {}
    condition: (selection1 and selection2) or selection3
"#,
                    i + 1, i, event_id, process_name, user,
                    event_ids[(i + 2) % event_ids.len()]
                )
            }
            _ => unreachable!(),
        };

        rules.push(rule);
    }

    rules
}

/// Create a single realistic test event for simple benchmarks.
pub fn create_single_test_event() -> Value {
    json!({
        "EventID": "4624",
        "EventRecordID": "12345",
        "ProcessName": "svchost.exe",
        "CommandLine": "C:\\Windows\\System32\\svchost.exe -k NetworkService",
        "User": "SYSTEM",
        "LogonType": "3",
        "SourceIP": "192.168.1.100",
        "DestinationIP": "10.0.0.1",
        "Port": "445",
        "Protocol": "TCP",
        "Timestamp": "2023-01-01T12:00:00Z"
    })
}

/// Create test events with specific patterns for targeted benchmarking.
pub fn create_pattern_test_events(pattern: &str, count: usize) -> Vec<Value> {
    match pattern {
        "login_events" => (0..count)
            .map(|i| {
                json!({
                    "EventID": if i % 2 == 0 { "4624" } else { "4625" },
                    "EventRecordID": format!("{}", 12345 + i),
                    "User": format!("user_{}", i % 5),
                    "LogonType": format!("{}", (i % 3) + 1),
                    "SourceIP": format!("192.168.1.{}", 100 + (i % 155)),
                    "Timestamp": "2023-01-01T12:00:00Z"
                })
            })
            .collect(),
        "process_events" => (0..count)
            .map(|i| {
                json!({
                    "EventID": "4688",
                    "EventRecordID": format!("{}", 12345 + i),
                    "ProcessName": format!("process_{}.exe", i % 10),
                    "CommandLine": format!("process_{}.exe --arg{}", i % 10, i),
                    "User": format!("user_{}", i % 3),
                    "ProcessId": format!("{}", 1000 + i),
                    "Timestamp": "2023-01-01T12:00:00Z"
                })
            })
            .collect(),
        "network_events" => (0..count)
            .map(|i| {
                json!({
                    "EventID": "5156",
                    "EventRecordID": format!("{}", 12345 + i),
                    "ProcessName": "chrome.exe",
                    "SourceIP": format!("192.168.1.{}", 100 + (i % 155)),
                    "DestinationIP": format!("10.0.0.{}", 1 + (i % 254)),
                    "SourcePort": format!("{}", 50000 + (i % 15000)),
                    "DestinationPort": if i % 3 == 0 { "80" } else if i % 3 == 1 { "443" } else { "8080" },
                    "Protocol": "TCP",
                    "Timestamp": "2023-01-01T12:00:00Z"
                })
            })
            .collect(),
        _ => create_test_events(count),
    }
}
