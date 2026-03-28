use std::process::Command;

use anyhow::{bail, Context};
use chrono::Utc;

use crate::models::{
    CommandExecutionResult, ConnectionCommandAction, ConnectionCommandRequest,
};

pub fn get_established_connections_report() -> anyhow::Result<CommandExecutionResult> {
    let script = concat!(
        "$ErrorActionPreference = 'Stop'; ",
        "if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) { ",
        "  Get-NetTCPConnection -State Established | ",
        "    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ",
        "    Sort-Object OwningProcess,LocalPort | ",
        "    Format-Table -AutoSize | Out-String -Width 240 ",
        "} else { ",
        "  netstat -ano | Select-String ESTABLISHED | ForEach-Object { $_.Line } | Out-String -Width 240 ",
        "}"
    );

    run_powershell(
        "Established TCP connections",
        "Get-NetTCPConnection -State Established",
        script,
    )
}

pub fn run_connection_command(
    request: &ConnectionCommandRequest,
) -> anyhow::Result<CommandExecutionResult> {
    match request.action {
        ConnectionCommandAction::ViewProcess => {
            let filter = format!("PID eq {}", request.pid);
            run_process(
                Command::new("tasklist").args(["/FI", &filter]),
                "View process",
                format!("tasklist /FI \"{}\"", filter),
            )
        }
        ConnectionCommandAction::GetExecutablePath => run_powershell(
            "Executable path",
            &format!("Get-Process -Id {} | Select-Object Path", request.pid),
            &format!(
                "$ErrorActionPreference = 'Stop'; Get-Process -Id {} | Select-Object Path | Format-List | Out-String -Width 240",
                request.pid
            ),
        ),
        ConnectionCommandAction::CheckSvchostServices => {
            ensure_svchost(request)?;
            let filter = format!("PID eq {}", request.pid);
            run_process(
                Command::new("tasklist").args(["/svc", "/FI", &filter]),
                "svchost hosted services",
                format!("tasklist /svc /FI \"{}\"", filter),
            )
        }
        ConnectionCommandAction::GetSvchostServiceDetails => {
            ensure_svchost(request)?;
            run_powershell(
                "svchost service details",
                &format!(
                    "Get-CimInstance Win32_Service | Where-Object {{ $_.ProcessId -eq {} }} | Select Name,DisplayName,PathName",
                    request.pid
                ),
                &format!(
                    "$ErrorActionPreference = 'Stop'; Get-CimInstance Win32_Service | Where-Object {{ $_.ProcessId -eq {} }} | Select Name,DisplayName,PathName | Format-Table -AutoSize | Out-String -Width 240",
                    request.pid
                ),
            )
        }
    }
}

fn ensure_svchost(request: &ConnectionCommandRequest) -> anyhow::Result<()> {
    if !request.process_name.eq_ignore_ascii_case("svchost.exe") {
        bail!("This action is only available for svchost.exe.");
    }
    Ok(())
}

fn run_powershell(
    title: &str,
    display_command: &str,
    script: &str,
) -> anyhow::Result<CommandExecutionResult> {
    run_process(
        Command::new("powershell.exe").args(["-NoProfile", "-Command", script]),
        title,
        display_command.to_string(),
    )
}

fn run_process(
    command: &mut Command,
    title: &str,
    display_command: String,
) -> anyhow::Result<CommandExecutionResult> {
    let output = command
        .output()
        .with_context(|| format!("running command: {display_command}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    let combined = match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!("{stdout}\n\n{stderr}"),
        (false, true) => stdout,
        (true, false) => stderr,
        (true, true) => "No output returned.".to_string(),
    };

    Ok(CommandExecutionResult {
        title: title.to_string(),
        command: display_command,
        output: combined,
        success: output.status.success(),
        executed_at: Utc::now(),
    })
}
