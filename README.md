# Sentinel Desk

Sentinel Desk es una app de escritorio Windows-first hecha con Tauri, React y Rust para vigilar conexiones de red del host, enriquecerlas con contexto local y externo, y asignarles un nivel de riesgo entendible.

No inspecciona paquetes ni pretende ser un IDS completo. Trabaja sobre sockets del sistema operativo, procesos propietarios, firmas, hashes, baseline local y reputacion opcional.

## Que hace

- Muestra conexiones vivas y sesiones TCP establecidas.
- Genera alertas para trafico `unknown` o `suspicious`.
- Guarda actividad reciente: `opened`, `updated`, `closed`.
- Permite crear reglas de confianza persistentes.
- Aprende patrones locales para reducir ruido.
- Enriquece destinos con DNS/ASN y reputacion opcional.

## Stack

- Frontend: React 19, TypeScript, Vite 7
- Desktop shell: Tauri 2
- Backend: Rust 2021
- Persistencia: SQLite con `rusqlite`
- Recoleccion: `netstat2`, `sysinfo`

## Requisitos

- Windows 10 u 11
- PowerShell disponible
- Node.js + npm
- Rust estable
- Prerrequisitos de Tauri para Windows

La implementacion usa comandos y APIs del propio sistema como `Get-AuthenticodeSignature`, `Resolve-DnsName`, `Get-NetTCPConnection`, `Get-CimInstance` y `tasklist`.

## Desarrollo rapido

Instalar dependencias:

```bash
npm install
```

Levantar la app de escritorio:

```bash
npm run tauri:dev
```

Build del frontend:

```bash
npm run build
```

Bundle nativo:

```bash
npm run tauri:build
```

Tests del backend:

```bash
cd src-tauri
cargo test
```

`npm run dev` solo arranca Vite. La app real depende del bridge de Tauri, asi que para desarrollo normal usa `npm run tauri:dev`.

## Interfaz

La navegacion principal queda asi:

- `Dashboard`: vista compacta con resumen, alertas, sesiones establecidas y tabla live.
- `Alerts`: panel completo de alertas.
- `Established connections`: panel completo de sesiones TCP establecidas.
- `Live connections`: panel completo de conexiones vivas.
- `Activity history`: historial reciente.
- `Trusted rules`: reglas aprobadas por el analista.
- `Engine settings`: configuracion del motor.

Las tres pestanas de conexiones comparten:

- filtros por `state`
- filtros por `direction`
- `sort`
- `search`

Cuando varias conexiones o alertas pertenecen al mismo proceso o PID, la UI las agrupa en desplegables para reducir duplicados visuales.

Al seleccionar una conexion se abre un panel de detalle con:

- score y confianza
- ruta del ejecutable
- firma, hash, parent process y user
- servicios alojados por `svchost.exe`
- destino remoto, ASN, dominio y pais
- razones del scoring
- timeline de alerta
- acciones del host como `tasklist`, consultas PowerShell y copia de sugerencia de firewall

## Como funciona

El backend corre un bucle de monitorizacion y, en cada ciclo:

1. Lee sockets TCP/UDP del host.
2. Resuelve el proceso propietario.
3. Enriquece path, firma, hash, parent, user y servicios.
4. Enriquece el destino remoto si aplica.
5. Clasifica la conexion con una heuristica explicable.
6. Guarda cambios en SQLite y emite eventos a la UI.

La UI escucha `monitor://connection` y tambien hace reconciliacion periodica para evitar desincronizaciones.

## Scoring y persistencia

El clasificador devuelve:

- `safe`
- `unknown`
- `suspicious`

Para calcularlo usa, entre otros:

- estado del socket
- tipo de listener o conexion activa
- path del ejecutable
- firma y hash
- parent process y user context
- puertos sensibles
- baseline local
- allow rules
- reputacion externa opcional

La base de datos local es `sentinel-desk.db` y se guarda en el directorio de datos de Tauri, normalmente bajo una ruta similar a:

```text
%APPDATA%\com.asier.sentineldesk\sentinel-desk.db
```

Tablas principales:

- `settings`
- `allow_rules`
- `connection_events`
- `alerts`
- `alert_timeline_events`
- `activity_events`
- `baseline_patterns`
- `destination_cache`
- `reputation_cache`

Valores por defecto importantes:

- `pollingIntervalSecs`: `2`
- `retentionDays`: `30`
- `baselineLearningThreshold`: `3`
- `alertCooldownMinutes`: `20`
- enriquecimiento de destino activado
- reputacion externa desactivada por defecto

## Estructura del repo

```text
src/
  App.tsx
  components/
  lib/
  styles.css
  types.ts

src-tauri/
  src/
    lib.rs
    monitor.rs
    classifier.rs
    db.rs
    process_info.rs
    destination.rs
    reputation.rs
    command_runner.rs
  Cargo.toml
  tauri.conf.json
```

Archivos clave:

- `src/App.tsx`: orquestacion de tabs, filtros, suscripciones y estado global.
- `src/components/`: paneles de UI y modal de detalle.
- `src/lib/tauri.ts`: wrapper del bridge Tauri.
- `src/lib/processGrouping.ts`: agrupacion de conexiones y alertas por proceso/PID.
- `src-tauri/src/monitor.rs`: bucle principal del monitor.
- `src-tauri/src/classifier.rs`: scoring y razones explicables.
- `src-tauri/src/db.rs`: persistencia SQLite.

## Integraciones externas

Opcionales:

- `ipwho.is` para ASN, dominio, organizacion y pais
- AbuseIPDB para reputacion

Si trabajas en un entorno cerrado, puedes desactivar ambos y seguir usando solo contexto local.

## Calidad actual

Existe:

- `npm run build`
- `cargo test`

No existe ahora mismo:

- `lint` en `package.json`
- tests del frontend
- pruebas end-to-end

## Limitaciones

- Proyecto claramente orientado a Windows.
- No captura payload de red.
- La parte web sola no representa el producto completo sin Tauri.
- El scoring es heuristico; ayuda al triage, no sustituye una plataforma EDR/IDS.
- Los tipos existen en Rust y TypeScript sin generacion automatica.
