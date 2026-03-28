use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    process::Command,
    sync::{mpsc, Arc},
    thread,
};

use anyhow::Context;
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sysinfo::System;

use crate::models::ProcessIdentity;

#[derive(Debug, Clone, Default)]
pub struct SignatureInfo {
    pub signer: Option<String>,
    pub publisher: Option<String>,
    pub is_signed: bool,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone)]
enum CacheEntry {
    Pending,
    Ready(SignatureInfo),
}

#[derive(Debug, Clone)]
enum ServiceCacheEntry {
    Pending,
    Ready(Vec<String>),
}

#[derive(Debug)]
pub struct ProcessEnricher {
    signature_cache: Mutex<HashMap<PathBuf, CacheEntry>>,
    job_sender: mpsc::Sender<PathBuf>,
    result_receiver: Mutex<mpsc::Receiver<(PathBuf, SignatureInfo)>>,
    service_cache: Mutex<HashMap<u32, ServiceCacheEntry>>,
    service_job_sender: mpsc::Sender<u32>,
    service_result_receiver: Mutex<mpsc::Receiver<(u32, Vec<String>)>>,
}

impl Default for ProcessEnricher {
    fn default() -> Self {
        let (job_sender, job_receiver) = mpsc::channel::<PathBuf>();
        let (result_sender, result_receiver) = mpsc::channel::<(PathBuf, SignatureInfo)>();
        let shared_receiver = Arc::new(Mutex::new(job_receiver));
        let (service_job_sender, service_job_receiver) = mpsc::channel::<u32>();
        let (service_result_sender, service_result_receiver) = mpsc::channel::<(u32, Vec<String>)>();

        for _ in 0..2 {
            let receiver = Arc::clone(&shared_receiver);
            let sender = result_sender.clone();
            thread::spawn(move || {
                loop {
                    let next_path = {
                        let queue = receiver.lock();
                        queue.recv()
                    };

                    let Ok(path) = next_path else {
                        break;
                    };

                    let resolved = read_signature(&path).unwrap_or_default();
                    let _ = sender.send((path, resolved));
                }
            });
        }

        {
            let sender = service_result_sender.clone();
            thread::spawn(move || {
                while let Ok(pid) = service_job_receiver.recv() {
                    let resolved = read_hosted_services(pid).unwrap_or_default();
                    let _ = sender.send((pid, resolved));
                }
            });
        }

        Self {
            signature_cache: Mutex::new(HashMap::new()),
            job_sender,
            result_receiver: Mutex::new(result_receiver),
            service_cache: Mutex::new(HashMap::new()),
            service_job_sender,
            service_result_receiver: Mutex::new(service_result_receiver),
        }
    }
}

impl ProcessEnricher {
    pub fn resolve_process(&self, system: &System, pid: u32) -> ProcessIdentity {
        self.drain_completed();

        let default = ProcessIdentity {
            pid,
            name: "unknown".to_string(),
            exe_path: None,
            user: None,
            parent_pid: None,
            parent_name: None,
            signer: None,
            is_signed: false,
            publisher: None,
            sha256: None,
            metadata_pending: false,
            hosted_services: Vec::new(),
            service_context_pending: false,
        };

        let process = system.process(sysinfo::Pid::from_u32(pid));
        let Some(process) = process else {
            return default;
        };

        let parent_pid = process.parent().map(|value| value.as_u32());
        let parent_name = parent_pid
            .and_then(|value| system.process(sysinfo::Pid::from_u32(value)))
            .map(|parent| parent.name().to_string_lossy().to_string());
        let exe_path = process.exe().map(|path| path.to_path_buf());
        let (signature, metadata_pending) = exe_path
            .as_deref()
            .map(|path| self.signature_for(path))
            .unwrap_or_else(|| (SignatureInfo::default(), false));
        let (hosted_services, service_context_pending) = if process
            .name()
            .to_string_lossy()
            .eq_ignore_ascii_case("svchost.exe")
        {
            self.services_for(pid)
        } else {
            (Vec::new(), false)
        };

        ProcessIdentity {
            pid,
            name: process.name().to_string_lossy().to_string(),
            exe_path: exe_path.as_ref().map(|path| path.display().to_string()),
            user: process.user_id().map(|user| user.to_string()),
            parent_pid,
            parent_name,
            signer: signature.signer,
            is_signed: signature.is_signed,
            publisher: signature.publisher,
            sha256: signature.sha256,
            metadata_pending,
            hosted_services,
            service_context_pending,
        }
    }

    fn signature_for(&self, path: &Path) -> (SignatureInfo, bool) {
        {
            let cache = self.signature_cache.lock();
            if let Some(entry) = cache.get(path) {
                return match entry {
                    CacheEntry::Pending => (SignatureInfo::default(), true),
                    CacheEntry::Ready(signature) => (signature.clone(), false),
                };
            }
        }

        self.signature_cache
            .lock()
            .insert(path.to_path_buf(), CacheEntry::Pending);
        let _ = self.job_sender.send(path.to_path_buf());
        (SignatureInfo::default(), true)
    }

    fn services_for(&self, pid: u32) -> (Vec<String>, bool) {
        {
            let cache = self.service_cache.lock();
            if let Some(entry) = cache.get(&pid) {
                return match entry {
                    ServiceCacheEntry::Pending => (Vec::new(), true),
                    ServiceCacheEntry::Ready(services) => (services.clone(), false),
                };
            }
        }

        self.service_cache
            .lock()
            .insert(pid, ServiceCacheEntry::Pending);
        let _ = self.service_job_sender.send(pid);
        (Vec::new(), true)
    }

    fn drain_completed(&self) {
        let mut completed = Vec::new();
        {
            let receiver = self.result_receiver.lock();
            while let Ok((path, signature)) = receiver.try_recv() {
                completed.push((path, signature));
            }
        }

        if !completed.is_empty() {
            let mut cache = self.signature_cache.lock();
            for (path, signature) in completed {
                cache.insert(path, CacheEntry::Ready(signature));
            }
        }

        let mut resolved_services = Vec::new();
        {
            let receiver = self.service_result_receiver.lock();
            while let Ok((pid, services)) = receiver.try_recv() {
                resolved_services.push((pid, services));
            }
        }

        if resolved_services.is_empty() {
            return;
        }

        let mut service_cache = self.service_cache.lock();
        for (pid, services) in resolved_services {
            service_cache.insert(pid, ServiceCacheEntry::Ready(services));
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SignaturePayload {
    status: Option<String>,
    subject: Option<String>,
    issuer: Option<String>,
}

fn read_signature(path: &Path) -> anyhow::Result<SignatureInfo> {
    let escaped = path.display().to_string().replace('\'', "''");
    let command = format!(
        "$s = Get-AuthenticodeSignature -LiteralPath '{escaped}'; \
         $c = $s.SignerCertificate; \
         [pscustomobject]@{{ \
           Status = \"$($s.Status)\"; \
           Subject = if ($c) {{ $c.Subject }} else {{ '' }}; \
           Issuer = if ($c) {{ $c.Issuer }} else {{ '' }} \
         }} | ConvertTo-Json -Compress"
    );

    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &command])
        .output()
        .context("executing Get-AuthenticodeSignature")?;

    let payload: SignaturePayload = if output.status.success() {
        serde_json::from_slice(&output.stdout).unwrap_or(SignaturePayload {
            status: None,
            subject: None,
            issuer: None,
        })
    } else {
        SignaturePayload {
            status: None,
            subject: None,
            issuer: None,
        }
    };

    Ok(SignatureInfo {
        signer: payload.subject.as_deref().and_then(extract_common_name),
        publisher: payload.issuer.as_deref().and_then(extract_common_name),
        is_signed: payload.status.as_deref() == Some("Valid"),
        sha256: hash_file(path).ok(),
    })
}

fn extract_common_name(value: &str) -> Option<String> {
    value.split(',')
        .find_map(|segment| segment.trim().strip_prefix("CN=").map(|item| item.to_string()))
}

fn hash_file(path: &Path) -> anyhow::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn read_hosted_services(pid: u32) -> anyhow::Result<Vec<String>> {
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $services = Get-CimInstance Win32_Service | Where-Object {{ $_.ProcessId -eq {pid} }} | Select-Object -ExpandProperty Name; \
         if ($null -eq $services) {{ '[]' }} else {{ $services | ConvertTo-Json -Compress }}"
    );

    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .context("executing svchost service lookup")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let payload = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(parse_service_payload(&payload))
}

fn parse_service_payload(payload: &str) -> Vec<String> {
    if payload.is_empty() {
        return Vec::new();
    }

    match serde_json::from_str::<serde_json::Value>(payload) {
        Ok(serde_json::Value::String(value)) => vec![value],
        Ok(serde_json::Value::Array(values)) => values
            .into_iter()
            .filter_map(|value| value.as_str().map(ToString::to_string))
            .collect(),
        _ => Vec::new(),
    }
}
