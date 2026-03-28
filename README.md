# Nyx Net Sentinel

Nyx Net Sentinel es una aplicacion de escritorio para Windows pensada para dar visibilidad clara, rapida y accionable sobre las conexiones de red del host. Convierte sockets y procesos en una vista investigable, con contexto, scoring explicable y una interfaz preparada para triage real.

Si alguna vez has querido responder con rapidez a preguntas como "que proceso esta hablando con esta IP", "por que esta conexion parece sospechosa" o "como reduzco ruido sin quedarme ciego", ese es exactamente el espacio en el que se mueve Nyx Net Sentinel.

Autor: Asier Gonzalez  
GitHub: https://github.com/asier-toraya

## Por que Nyx Net Sentinel

La mayoria de herramientas muestran conexiones. Nyx Net Sentinel intenta mostrar criterio.

- Prioriza el contexto del proceso, no solo el socket.
- Clasifica cada conexion en `safe`, `unknown` o `suspicious`.
- Explica el por que de cada score con razones legibles.
- Agrupa conexiones repetidas por proceso o PID para reducir fatiga visual.
- Permite confiar una conexion concreta o un proceso completo, segun el caso.
- Combina enrichment local con inteligencia externa opcional.

El resultado es una experiencia mas cercana a una consola de investigacion ligera que a una simple tabla de puertos.

## Lo que ofrece hoy

- Monitorizacion de sockets TCP y UDP en tiempo real.
- Dashboard con resumen visual por nivel de riesgo.
- Pestanas dedicadas para `Alerts`, `Established connections` y `Live connections`.
- `Activity history` para revisar aperturas, actualizaciones y cierres recientes.
- `Trusted rules` para construir una politica de confianza persistente.
- `Engine settings` para ajustar collection, baseline, enrichment y reputacion.
- Tema `light` y `dark`.
- Persistencia local con SQLite.

## Lo que hace especial a la experiencia

### Riesgo explicable

Cada conexion se clasifica con un nivel de riesgo y una lista de razones. No solo ves un color: ves la logica que hay detras.

### Vista centrada en el proceso

Cada detalle relevante queda reunido en un solo lugar:

- nombre del proceso
- ruta del ejecutable
- firma y publisher
- hash
- usuario
- parent process
- servicios alojados por `svchost.exe`
- contexto del destino remoto

### Menos ruido, mejor lectura

Cuando un proceso abre muchas conexiones similares, la interfaz las agrupa para que el analista pueda ver el patron sin ahogarse en duplicados.

### Trust con dos niveles

- `Mark as trusted` para confiar una conexion concreta.
- `Trust whole process` para aprobar el proceso completo como una regla separada.

Esto permite una politica de confianza mas fina y mucho mas util en escenarios reales como navegadores, agentes o herramientas del sistema.

## Recorrido rapido por la interfaz

### Dashboard

Es la vista de entrada para triage rapido. Reune:

- summary por riesgo
- alertas abiertas
- sesiones TCP establecidas
- conexiones vivas

Desde aqui puedes filtrar por:

- riesgo
- `state`
- `direction`
- `sort`
- `search`

### Alerts

Una vista centrada en investigaciones activas. Ideal para revisar señales abiertas sin el split del dashboard.

### Established connections

Una vista completa para sesiones TCP establecidas, con mas espacio para leer y comparar.

### Live connections

Inventario completo de conexiones vivas con filtros y busqueda pensados para exploracion.

### Activity history

Timeline reciente de cambios capturados por el collector:

- `opened`
- `updated`
- `closed`

### Trusted rules

Panel para gestionar las reglas aprobadas por el analista y mantener el entorno afinado.

### Engine settings

Centro de control del motor para collection cadence, learning, destination enrichment y reputacion externa.

## Quick start

Instalar dependencias:

```bash
npm install
```

Levantar la aplicacion de escritorio:

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

Nota util:

- `npm run dev` solo arranca Vite.
- Para trabajar con la app real usa `npm run tauri:dev`.

## Stack

- React 19
- TypeScript
- Vite 7
- Tauri 2
- Rust 2021
- SQLite con `rusqlite`
- `netstat2` y `sysinfo` para recoleccion local

## Como funciona internamente

Nyx Net Sentinel sigue un flujo sencillo y potente:

1. Lee sockets TCP y UDP del host.
2. Resuelve el proceso propietario.
3. Enriquece la identidad del proceso con firma, hash, parent, usuario y servicios.
4. Enriquece el destino remoto cuando aplica.
5. Clasifica la conexion con una heuristica explicable.
6. Guarda el estado relevante en SQLite.
7. Emite actualizaciones a la interfaz mediante `monitor://connection`.

La interfaz escucha esos eventos, hace reconciliacion periodica y presenta la informacion en vistas pensadas para investigacion, no solo para inventario.

## Enrichment y scoring

El motor combina senales locales y, si quieres, contexto externo.

### Enrichment local

- identidad del proceso
- firma y publisher
- hash SHA-256
- usuario y parent process
- contexto de servicios en `svchost.exe`

### Enrichment remoto opcional

- `ipwho.is` para ASN, organizacion, dominio y pais
- AbuseIPDB para reputacion IP

### Niveles de riesgo

- `safe`
- `unknown`
- `suspicious`

El score tiene en cuenta, entre otros:

- estado del socket
- tipo de listener o conexion activa
- firma y ruta del ejecutable
- baseline local
- puertos vigilados
- reglas `trusted`
- reputacion externa opcional

## Persistencia

La aplicacion guarda de forma local:

- settings
- reglas de confianza
- eventos de conexion
- alertas
- timeline de alertas
- actividad reciente
- baseline patterns
- cache de destino
- cache de reputacion

Valores por defecto del motor:

- `pollingIntervalSecs`: `2`
- `retentionDays`: `30`
- `baselineLearningThreshold`: `3`
- `alertCooldownMinutes`: `20`
- `enableDestinationEnrichment`: `true`
- `destinationProvider`: `ipwhois + reverse dns`
- `destinationTtlMinutes`: `1440`
- `enableReputation`: `false`
- `reputationProvider`: `abuseipdb`
- `reputationTtlMinutes`: `1440`
- `suspiciousPorts`: `22, 23, 135, 139, 445, 3389, 5900, 5985, 5986`

## Arquitectura del repo

```text
src/
  App.tsx
  components/
  hooks/
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
    models.rs
  Cargo.toml
  tauri.conf.json
```

Piezas clave:

- `src/App.tsx`: composicion general de la app.
- `src/components/`: vistas y paneles principales.
- `src/hooks/`: sincronizacion, seleccion, filtros y estado compartido.
- `src/lib/monitoring.ts`: helpers de monitorizacion, summary y filtros.
- `src/lib/processGrouping.ts`: agrupacion de conexiones y alertas por proceso o PID.
- `src/lib/tauri.ts`: puente entre frontend y backend.
- `src-tauri/src/monitor.rs`: collector principal.
- `src-tauri/src/classifier.rs`: scoring y razones.
- `src-tauri/src/process_info.rs`: enrichment del proceso.
- `src-tauri/src/destination.rs`: enrichment de destino.
- `src-tauri/src/reputation.rs`: reputacion externa.
- `src-tauri/src/db.rs`: persistencia SQLite.

## Filosofia del proyecto

Nyx Net Sentinel esta enfocado en host visibility con contexto y buen criterio visual. No intenta abarcarlo todo: intenta hacer muy bien una tarea concreta, que es ayudarte a entender que esta pasando en la red del endpoint de una forma clara, util y agradable de usar.

Ese enfoque se traduce en tres principios:

- contexto antes que ruido
- explicabilidad antes que cajas negras
- flujo de analista antes que dashboard generico

## Alcance actual

El producto esta orientado a escritorio Windows y a monitorizacion basada en conexiones y procesos del host. Esa especializacion es deliberada: permite que la herramienta sea mas directa, mas legible y mas util en su terreno.

## Calidad actual

Disponible hoy:

- `npm run build`
- `cargo test`

El proyecto sigue evolucionando y tiene una base muy buena para seguir creciendo en rendimiento, cobertura de pruebas y automatizacion de contratos entre Rust y TypeScript.
