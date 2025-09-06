use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::{json, Value};
use sigma_engine::dag::engine::{DagEngine, DagEngineConfig};
use sigma_engine::ir::{CompiledRuleset, Primitive};
use std::hint::black_box;
use std::time::Duration;

/// Real-world SIGMA rule patterns based on the SigmaHQ repository
/// These represent actual security detection patterns used in production
/// Create realistic non-matching events that represent normal system activity
/// These events should be filtered out by the prefilter, demonstrating its effectiveness
/// IMPORTANT: These events are carefully crafted to avoid ALL patterns in our comprehensive ruleset
fn create_non_matching_events(count: usize) -> Vec<Value> {
    // Use completely benign processes that are NOT in our suspicious_processes list
    let benign_processes = [
        "notepad",
        "calculator",
        "mspaint",
        "wordpad",
        "charmap",
        "magnify",
        "osk",
        "narrator",
        "snip",
        "write",
    ];

    // Use event IDs that are NOT in our security_events list (avoid 4624, 4625, 4648, etc.)
    let benign_event_ids = [
        "100", "101", "102", "103", "104", "105", "106", "107", "108", "109",
    ];

    // Use users that don't trigger security alerts
    let benign_users = ["alice", "bob", "charlie", "diana", "eve"];

    // Use IPs that are NOT in our suspicious_ips list
    let benign_ips = [
        "203.0.113.1",
        "198.51.100.1",
        "203.0.113.5",
        "198.51.100.10",
    ];

    (0..count)
        .map(|i| {
            let process = benign_processes[i % benign_processes.len()];
            let event_id = benign_event_ids[i % benign_event_ids.len()];
            let user = benign_users[i % benign_users.len()];
            let ip = benign_ips[i % benign_ips.len()];

            json!({
                "EventID": event_id,
                "ProcessName": process,
                // Avoid .exe extension and suspicious paths - use simple names
                "CommandLine": format!("C:\\Program Files\\Office\\{}", process),
                "User": user,
                "Computer": format!("DESKTOP-{:03}", (i % 100) + 1),
                "LogonType": 1, // Use logon type not in our rules
                "SourceIP": ip,
                "DestinationIP": "203.0.113.100", // Benign test IP
                "Port": 8000 + (i % 100), // Use high ports not in our rules
                "Protocol": "UDP", // Different protocol
                "Timestamp": format!("2024-01-01T{:02}:{:02}:{:02}Z",
                                   (i / 3600) % 24, (i / 60) % 60, i % 60),
                // Avoid suspicious paths and extensions
                "Image": format!("C:\\Program Files\\Office\\{}", process),
                "ParentImage": "C:\\Program Files\\Office\\launcher",
                "IntegrityLevel": "Medium", // Not "System" or "High"
                "LogonId": format!("0x{:x}", 2000 + i),
            })
        })
        .collect()
}

/// Create realistic matching events that actually match rules and produce detections
/// These events should trigger the prefilter AND produce actual rule matches
fn create_matching_events(count: usize) -> Vec<Value> {
    // Create events that will actually match our primitive patterns
    // Focus on simple patterns that are guaranteed to match
    let matching_patterns = [
        // Match EventID primitives directly
        ("4624", "explorer.exe", "C:\\Windows\\explorer.exe"),
        (
            "4625",
            "winlogon.exe",
            "C:\\Windows\\System32\\winlogon.exe",
        ),
        ("4648", "lsass.exe", "C:\\Windows\\System32\\lsass.exe"),
        (
            "4672",
            "services.exe",
            "C:\\Windows\\System32\\services.exe",
        ),
        ("4720", "svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
        // Match ProcessName contains patterns
        (
            "1000",
            "powershell.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ),
        ("1001", "mimikatz.exe", "C:\\Tools\\mimikatz.exe"),
        ("1002", "psexec.exe", "C:\\Tools\\psexec.exe"),
        (
            "1003",
            "rundll32.exe",
            "C:\\Windows\\System32\\rundll32.exe",
        ),
        (
            "1004",
            "regsvr32.exe",
            "C:\\Windows\\System32\\regsvr32.exe",
        ),
        // Match CommandLine contains patterns
        ("1005", "cmd.exe", "cmd.exe /c whoami"),
        (
            "1006",
            "powershell.exe",
            "powershell.exe -ExecutionPolicy Bypass",
        ),
        ("1007", "net.exe", "net.exe user administrator"),
        ("1008", "schtasks.exe", "schtasks.exe /create /tn test"),
        ("1009", "netsh.exe", "netsh.exe firewall set opmode disable"),
    ];

    (0..count)
        .map(|i| {
            let (event_id, process, image_path) = &matching_patterns[i % matching_patterns.len()];

            json!({
                "EventID": event_id,
                "ProcessName": process,
                "Image": image_path,
                "CommandLine": image_path,
                "User": "Administrator",
                "Computer": format!("WORKSTATION-{:03}", (i % 10) + 1),
                "LogonType": 3,
                "Timestamp": format!("2024-01-01T{:02}:{:02}:{:02}Z",
                                   (i / 3600) % 24, (i / 60) % 60, i % 60),
                "ParentImage": "C:\\Windows\\System32\\services.exe",
                "IntegrityLevel": "High",
                "LogonId": format!("0x{:x}", 0x10000 + i),
                "ProcessId": 2000 + (i % 8000),
                "ParentProcessId": 1000,
            })
        })
        .collect()
}

/// Create a comprehensive real-world ruleset based on actual SIGMA detection patterns
/// This represents a realistic security monitoring setup with hundreds of detection rules
fn create_real_world_ruleset() -> CompiledRuleset {
    let mut primitives = Vec::new();

    // 1. Windows Security Events (Authentication & Authorization)
    let security_events = [
        "4624", "4625", "4648", "4672", "4720", "4726", "4728", "4732", "4756", "4768", "4769",
        "4771", "4776", "4778", "4779", "4781", "4782", "4793",
    ];
    for event_id in &security_events {
        primitives.push(Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec![event_id.to_string()],
            Vec::new(),
        ));
    }

    // 2. PowerShell Attack Detection (Based on real SIGMA rules)
    let powershell_processes = [
        "powershell.exe",
        "pwsh.exe",
        "PowerShell_ISE.exe",
        "powershell_ise.exe",
    ];
    for process in &powershell_processes {
        primitives.push(Primitive::new(
            "ProcessName".to_string(),
            "contains".to_string(),
            vec![process.to_string()],
            Vec::new(),
        ));
        primitives.push(Primitive::new(
            "Image".to_string(),
            "endswith".to_string(),
            vec![process.to_string()],
            Vec::new(),
        ));
    }

    let powershell_flags = [
        "-ExecutionPolicy",
        "-EncodedCommand",
        "-WindowStyle",
        "-NoProfile",
        "-NonInteractive",
        "-Bypass",
        "-Hidden",
        "-ep",
        "-enc",
        "-w",
        "-nop",
        "-noni",
    ];
    for flag in &powershell_flags {
        primitives.push(Primitive::new(
            "CommandLine".to_string(),
            "contains".to_string(),
            vec![flag.to_string()],
            Vec::new(),
        ));
    }

    let powershell_commands = [
        "Invoke-Expression",
        "IEX",
        "DownloadString",
        "WebClient",
        "Invoke-WebRequest",
        "Start-Process",
        "Get-Process",
        "Stop-Process",
        "Invoke-Command",
        "Enter-PSSession",
        "New-Object",
        "Add-Type",
        "Reflection.Assembly",
        "System.Net.WebClient",
    ];
    for cmd in &powershell_commands {
        primitives.push(Primitive::new(
            "CommandLine".to_string(),
            "contains".to_string(),
            vec![cmd.to_string()],
            Vec::new(),
        ));
    }

    // 3. Malicious Process Detection (Living off the Land)
    let suspicious_processes = [
        "mimikatz.exe",
        "procdump.exe",
        "psexec.exe",
        "wce.exe",
        "fgdump.exe",
        "cachedump.exe",
        "gsecdump.exe",
        "secretsdump.exe",
        "lsadump.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "cscript.exe",
        "wscript.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "netsh.exe",
        "at.exe",
        "schtasks.exe",
    ];
    for process in &suspicious_processes {
        primitives.push(Primitive::new(
            "ProcessName".to_string(),
            "contains".to_string(),
            vec![process.to_string()],
            Vec::new(),
        ));
        primitives.push(Primitive::new(
            "Image".to_string(),
            "endswith".to_string(),
            vec![process.to_string()],
            Vec::new(),
        ));
    }

    // 4. Command Line Injection Patterns
    let injection_patterns = [
        "cmd.exe /c",
        "cmd /c",
        "powershell -c",
        "wmic process call create",
        "net user",
        "net localgroup",
        "whoami",
        "systeminfo",
        "tasklist",
        "netstat",
        "ipconfig",
        "arp -a",
        "route print",
        "net view",
    ];
    for pattern in &injection_patterns {
        primitives.push(Primitive::new(
            "CommandLine".to_string(),
            "contains".to_string(),
            vec![pattern.to_string()],
            Vec::new(),
        ));
    }

    // 5. File System & Registry Persistence
    let persistence_paths = [
        "\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "\\System\\CurrentControlSet\\Services",
        "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    ];
    for path in &persistence_paths {
        primitives.push(Primitive::new(
            "TargetObject".to_string(),
            "contains".to_string(),
            vec![path.to_string()],
            Vec::new(),
        ));
        primitives.push(Primitive::new(
            "CommandLine".to_string(),
            "contains".to_string(),
            vec![path.to_string()],
            Vec::new(),
        ));
    }

    let suspicious_extensions = [
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".pif", ".com",
        ".hta", ".wsf", ".jse", ".vbe",
    ];
    for ext in &suspicious_extensions {
        primitives.push(Primitive::new(
            "TargetFilename".to_string(),
            "endswith".to_string(),
            vec![ext.to_string()],
            Vec::new(),
        ));
    }

    // 6. Network & Lateral Movement Detection
    let network_tools = [
        "psexec", "winrm", "wmic", "net.exe", "netsh", "ping", "telnet", "ssh", "scp", "ftp",
        "tftp", "nc.exe", "ncat", "socat",
    ];
    for tool in &network_tools {
        primitives.push(Primitive::new(
            "ProcessName".to_string(),
            "contains".to_string(),
            vec![tool.to_string()],
            Vec::new(),
        ));
    }

    let suspicious_ips = [
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "169.254.169.254",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
    ];
    for ip in &suspicious_ips {
        primitives.push(Primitive::new(
            "DestinationIp".to_string(),
            "equals".to_string(),
            vec![ip.to_string()],
            Vec::new(),
        ));
    }

    // 7. Credential Access Patterns
    let credential_tools = [
        "mimikatz",
        "sekurlsa",
        "kerberos",
        "lsadump",
        "procdump",
        "comsvcs.dll",
        "ntdsutil",
        "vssadmin",
        "wbadmin",
        "diskshadow",
    ];
    for tool in &credential_tools {
        primitives.push(Primitive::new(
            "CommandLine".to_string(),
            "contains".to_string(),
            vec![tool.to_string()],
            Vec::new(),
        ));
    }

    // 8. Add some regex patterns (should be excluded from prefilter)
    let regex_patterns = [
        r".*\.exe\s+-[a-zA-Z]+.*",
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        r"^[A-Za-z]:\\.*\.exe$",
        r".*powershell.*-enc.*[A-Za-z0-9+/]{50,}.*",
    ];
    for pattern in &regex_patterns {
        primitives.push(Primitive::new(
            "CommandLine".to_string(),
            "regex".to_string(),
            vec![pattern.to_string()],
            Vec::new(),
        ));
    }

    // Build primitive map - each primitive gets a unique ID
    let mut primitive_map = std::collections::HashMap::new();
    for (i, primitive) in primitives.iter().enumerate() {
        primitive_map.insert(primitive.clone(), i as u32);
    }

    CompiledRuleset {
        primitives,
        primitive_map,
    }
}

/// Comprehensive benchmark comparing prefilter vs no prefilter with real-world data
fn benchmark_real_world_prefilter_effectiveness(c: &mut Criterion) {
    let ruleset = create_real_world_ruleset();

    println!("📊 Real-World Benchmark Configuration:");
    println!("  Total primitives: {}", ruleset.primitives.len());

    // Count literal vs regex patterns
    let literal_count = ruleset
        .primitives
        .iter()
        .filter(|p| {
            matches!(
                p.match_type.as_str(),
                "equals" | "contains" | "startswith" | "endswith"
            )
        })
        .count();
    let regex_count = ruleset
        .primitives
        .iter()
        .filter(|p| p.match_type.as_str() == "regex")
        .count();

    println!("  Literal patterns: {literal_count} (prefilter eligible)");
    println!("  Regex patterns: {regex_count} (prefilter excluded)");

    // Create engines with and without prefilter
    let config_with_prefilter = DagEngineConfig {
        enable_prefilter: true,
        ..Default::default()
    };

    let config_without_prefilter = DagEngineConfig {
        enable_prefilter: false,
        ..Default::default()
    };

    let mut engine_with_prefilter =
        DagEngine::from_ruleset_with_config(ruleset.clone(), config_with_prefilter)
            .expect("Failed to create engine with prefilter");

    let mut engine_without_prefilter =
        DagEngine::from_ruleset_with_config(ruleset, config_without_prefilter)
            .expect("Failed to create engine without prefilter");

    // Print prefilter statistics
    if let Some(stats) = engine_with_prefilter.prefilter_stats() {
        println!("  Prefilter patterns: {}", stats.pattern_count);
        println!("  Prefilter fields: {}", stats.field_count);
        println!(
            "  Estimated selectivity: {:.1}%",
            (1.0 - stats.estimated_selectivity) * 100.0
        );
        println!("  Performance summary: {}", stats.performance_summary());
    }
    println!();

    // Test with realistic event volumes
    let event_counts = [100, 500, 1000, 2000, 5000];

    // Benchmark 1: Non-matching events (where prefilter should excel)
    let mut group = c.benchmark_group("real_world_non_matching_events");
    group.measurement_time(Duration::from_secs(15));

    for &event_count in &event_counts {
        let events = create_non_matching_events(event_count);

        group.throughput(Throughput::Elements(event_count as u64));

        group.bench_with_input(
            BenchmarkId::new("with_prefilter", event_count),
            &events,
            |b, events| {
                b.iter(|| {
                    for event in events {
                        let _result = engine_with_prefilter.evaluate(black_box(event)).unwrap();
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("without_prefilter", event_count),
            &events,
            |b, events| {
                b.iter(|| {
                    for event in events {
                        let _result = engine_without_prefilter.evaluate(black_box(event)).unwrap();
                    }
                });
            },
        );
    }
    group.finish();

    // Benchmark 2: Matching events (where prefilter passes through to full evaluation)
    let mut group = c.benchmark_group("real_world_matching_events");
    group.measurement_time(Duration::from_secs(10));

    for &event_count in &[100, 500, 1000] {
        let events = create_matching_events(event_count);

        group.throughput(Throughput::Elements(event_count as u64));

        group.bench_with_input(
            BenchmarkId::new("with_prefilter", event_count),
            &events,
            |b, events| {
                b.iter(|| {
                    for event in events {
                        let _result = engine_with_prefilter.evaluate(black_box(event)).unwrap();
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("without_prefilter", event_count),
            &events,
            |b, events| {
                b.iter(|| {
                    for event in events {
                        let _result = engine_without_prefilter.evaluate(black_box(event)).unwrap();
                    }
                });
            },
        );
    }
    group.finish();
}

/// Benchmark specifically designed to prove prefilter effectiveness in realistic SOC scenarios
/// Tests 95% non-matching vs 5% matching events to demonstrate real-world performance gains
fn benchmark_soc_realistic_selectivity(c: &mut Criterion) {
    let ruleset = create_real_world_ruleset();

    // Create engines with and without prefilter
    let config_with_prefilter = DagEngineConfig {
        enable_prefilter: true,
        enable_optimization: true,
        optimization_level: 2,
        ..Default::default()
    };

    let config_without_prefilter = DagEngineConfig {
        enable_prefilter: false,
        enable_optimization: true,
        optimization_level: 2,
        ..Default::default()
    };

    let mut engine_with_prefilter =
        DagEngine::from_ruleset_with_config(ruleset.clone(), config_with_prefilter)
            .expect("Failed to create engine with prefilter");
    let mut engine_without_prefilter =
        DagEngine::from_ruleset_with_config(ruleset, config_without_prefilter)
            .expect("Failed to create engine without prefilter");

    // Print configuration
    if let Some(stats) = engine_with_prefilter.prefilter_stats() {
        println!("🎯 SOC Realistic Selectivity Benchmark:");
        println!("  Prefilter patterns: {}", stats.pattern_count);
        println!("  Expected selectivity: 95% filtered out, 5% pass through");
        println!("  Performance summary: {}", stats.performance_summary());
        println!();
    }

    let total_events = 1000;
    let matching_events = total_events / 20; // 5%
    let non_matching_events = total_events - matching_events; // 95%

    // Create realistic SOC workload
    let mut soc_events = Vec::new();
    soc_events.extend(create_non_matching_events(non_matching_events));
    soc_events.extend(create_matching_events(matching_events));

    // Shuffle events to simulate realistic ordering
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    soc_events.sort_by_key(|event| {
        let mut hasher = DefaultHasher::new();
        event.to_string().hash(&mut hasher);
        hasher.finish()
    });

    // Verify actual selectivity before benchmarking
    let mut filtered_count = 0;
    for event in &soc_events {
        let result = engine_with_prefilter.evaluate(event).unwrap();
        // Correct logic: prefilter miss = nodes_evaluated: 1 + no matches
        if result.nodes_evaluated == 1 && result.matched_rules.is_empty() {
            filtered_count += 1;
        }
    }
    let actual_selectivity = (filtered_count as f64 / total_events as f64) * 100.0;
    println!(
        "✅ Verified selectivity: {actual_selectivity:.1}% filtered out ({filtered_count}/{total_events})"
    );

    let mut group = c.benchmark_group("soc_realistic_95_5_split");
    group.measurement_time(Duration::from_secs(20));
    group.throughput(Throughput::Elements(total_events as u64));

    // Benchmark WITH prefilter (should be much faster for 95% non-matching events)
    group.bench_function("with_prefilter_95_5_split", |b| {
        b.iter(|| {
            for event in &soc_events {
                let _result = engine_with_prefilter.evaluate(black_box(event)).unwrap();
            }
        });
    });

    // Benchmark WITHOUT prefilter (baseline performance)
    group.bench_function("without_prefilter_95_5_split", |b| {
        b.iter(|| {
            for event in &soc_events {
                let _result = engine_without_prefilter.evaluate(black_box(event)).unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_real_world_prefilter_effectiveness,
    benchmark_soc_realistic_selectivity
);
criterion_main!(benches);
