# Nyx Net Sentinel

Nyx Net Sentinel es una aplicación de escritorio para Windows centrada en la monitorización de conexiones de red del host. Su objetivo es ofrecer una visión clara, ordenada y útil de qué procesos están generando tráfico, qué destinos aparecen asociados a cada conexión y qué señales merecen más atención.

Este proyecto nace con una idea muy concreta: convertir información técnica que normalmente aparece dispersa en varias herramientas en una interfaz más cómoda para analizar, priorizar y entender lo que está ocurriendo en el equipo.

Autor: Asier Gonzalez  
GitHub: https://github.com/asier-toraya

## Qué es

Nyx Net Sentinel combina una interfaz de escritorio construida con Tauri y React con un motor en Rust que recopila información de red del sistema, la enriquece con contexto del proceso y del destino, y la clasifica en niveles de riesgo comprensibles.

La aplicación está pensada para:

- visualizar conexiones activas de forma clara;
- identificar procesos y rutas ejecutables asociados;
- destacar tráfico `safe`, `unknown` o `suspicious`;
- reducir ruido mediante agrupaciones por proceso o PID;
- conservar historial, alertas y reglas de confianza persistentes.

## Características principales

- Dashboard con resumen visual por nivel de riesgo.
- Pestañas dedicadas para `Alerts`, `Established connections` y `Live connections`.
- `Activity history` para revisar aperturas, cambios y cierres recientes.
- Agrupación de conexiones repetidas por proceso o PID.
- Panel de detalle con información ampliada del proceso y del destino.
- Reglas de confianza persistentes desde `Trusted rules`.
- Opción para confiar una conexión concreta o un proceso completo.
- Configuración del motor desde `Engine settings`.
- Tema claro y tema oscuro.
- Persistencia local con SQLite.

## Instalación

### Opción recomendada para usuarios

La forma más sencilla de instalar Nyx Net Sentinel es mediante el instalador de Windows generado con Tauri.

Formatos disponibles:

- `NSIS (.exe)`: opción recomendada para la mayoría de usuarios.
- `MSI (.msi)`: opción útil para despliegues más formales o entornos corporativos.

Pasos de instalación:

1. Descarga el instalador de la versión publicada.
2. Ejecuta el archivo `.exe` o `.msi`.
3. Sigue el asistente de instalación.
4. Abre Nyx Net Sentinel desde el menú Inicio o desde el acceso directo creado.

El instalador está preparado para trabajar con WebView2. Si el equipo no lo tiene disponible, el proceso de instalación puede resolverlo automáticamente.

### Instalación desde una build local

Si quieres generar el instalador por tu cuenta:

```bash
npm install
npm run tauri:build:installer
```

Los instaladores se generan en:

```text
src-tauri/target/release/bundle/
```

En compilaciones de depuración, los artefactos se generan en:

```text
src-tauri/target/debug/bundle/
```

## Desarrollo local

### Requisitos

- Windows 10 u 11
- Node.js y npm
- Rust estable
- PowerShell disponible
- Prerrequisitos de Tauri para Windows

### Comandos principales

Instalar dependencias:

```bash
npm install
```

Arrancar la aplicación en desarrollo:

```bash
npm run tauri:dev
```

Arrancar solo el frontend web:

```bash
npm run dev
```

Compilar el frontend:

```bash
npm run build
```

Generar aplicación e instaladores:

```bash
npm run tauri:build
```

Generar instaladores de Windows:

```bash
npm run tauri:build:installer
```

Ejecutar tests del backend:

```bash
cd src-tauri
cargo test
```

## Cómo funciona

El motor de Nyx Net Sentinel sigue un flujo de monitorización continuo:

1. Lee sockets TCP y UDP del sistema.
2. Resuelve el proceso propietario de cada conexión.
3. Enriquece la identidad del proceso con datos como firma, hash, usuario o proceso padre.
4. Enriquece el destino remoto cuando hay contexto disponible.
5. Calcula un score y un nivel de riesgo.
6. Guarda la información relevante en SQLite.
7. Emite actualizaciones a la interfaz en tiempo real.

La interfaz utiliza esa información para presentar:

- conexiones vivas;
- sesiones establecidas;
- alertas abiertas;
- actividad reciente;
- reglas de confianza;
- configuración del motor.

## Interfaz

### Dashboard

Es la vista principal de trabajo. Reúne el resumen por riesgo, las alertas activas, las conexiones establecidas y la tabla de conexiones vivas.

### Alerts

Permite revisar alertas con más espacio y una lectura más cómoda para el análisis.

### Established connections

Muestra únicamente sesiones TCP establecidas en una vista más amplia.

### Live connections

Presenta el inventario completo de conexiones activas del sistema.

### Activity history

Guarda y muestra cambios recientes como:

- `opened`
- `updated`
- `closed`

### Trusted rules

Permite gestionar reglas persistentes para reducir ruido y adaptar el análisis al entorno.

### Engine settings

Reúne la configuración de frecuencia de monitorización, retención, baseline, reputación y puertos vigilados.

## Tecnologías utilizadas

- React 19
- TypeScript
- Vite 7
- Tauri 2
- Rust 2021
- SQLite con `rusqlite`
- `netstat2`
- `sysinfo`

## Estructura del proyecto

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

Archivos clave:

- `src/App.tsx`: composición general de la aplicación.
- `src/components/`: paneles y vistas principales.
- `src/hooks/`: estado compartido, sincronización y selección.
- `src/lib/monitoring.ts`: filtros, summary y helpers de monitorización.
- `src/lib/processGrouping.ts`: agrupación de conexiones y alertas.
- `src/lib/tauri.ts`: comunicación entre frontend y backend.
- `src-tauri/src/monitor.rs`: bucle principal del monitor.
- `src-tauri/src/classifier.rs`: scoring y clasificación.
- `src-tauri/src/process_info.rs`: enriquecimiento del proceso.
- `src-tauri/src/destination.rs`: enriquecimiento del destino.
- `src-tauri/src/reputation.rs`: consultas de reputación externa.
- `src-tauri/src/db.rs`: persistencia SQLite.

## Estado actual del proyecto

Nyx Net Sentinel ya ofrece una base sólida como herramienta de monitorización local y análisis de conexiones. La aplicación funciona como producto de escritorio, cuenta con instalador de Windows y tiene una arquitectura suficientemente clara como para seguir creciendo en nuevas mejoras.

Actualmente dispone de:

- compilación del frontend con `npm run build`;
- generación de instaladores con `npm run tauri:build:installer`;
- tests del backend con `cargo test`.

## Enfoque del proyecto

Este repositorio no busca ser un simple visor de puertos. La intención es construir una herramienta de análisis de red local que resulte práctica, legible y agradable de usar, especialmente para revisar procesos, conexiones y señales de riesgo de una manera más ordenada.

En ese sentido, Nyx Net Sentinel está planteado como un proyecto serio, pero también como una propuesta muy personal de cómo debería sentirse una herramienta de monitorización moderna en escritorio.
