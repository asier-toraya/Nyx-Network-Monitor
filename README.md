# Sentinel Desk

Sentinel Desk es una aplicacion de escritorio Windows-first construida con Tauri, React y Rust para observar conexiones de red activas del host, enriquecerlas con contexto local y externo, asignarles una puntuacion de riesgo legible y ayudar al analista a decidir si una conexion parece esperada, desconocida o sospechosa.

No es un IDS completo ni un sniffer de paquetes. La app trabaja sobre el estado del sistema operativo: sockets TCP/UDP visibles, proceso propietario, firma digital, hash del binario, contexto del usuario, aprendizaje local de patrones, metadatos DNS/ASN y reputacion opcional del destino.

## Tabla de contenidos

- [Resumen funcional](#resumen-funcional)
- [Objetivo del proyecto](#objetivo-del-proyecto)
- [Stack tecnologico](#stack-tecnologico)
- [Requisitos](#requisitos)
- [Puesta en marcha](#puesta-en-marcha)
- [Comandos disponibles](#comandos-disponibles)
- [Uso de la aplicacion](#uso-de-la-aplicacion)
- [Como funciona internamente](#como-funciona-internamente)
- [Politica de riesgo y scoring](#politica-de-riesgo-y-scoring)
- [Persistencia y datos locales](#persistencia-y-datos-locales)
- [Configuracion disponible](#configuracion-disponible)
- [Arquitectura del repositorio](#arquitectura-del-repositorio)
- [Integraciones externas y privacidad](#integraciones-externas-y-privacidad)
- [Calidad y validacion](#calidad-y-validacion)
- [Limitaciones actuales](#limitaciones-actuales)
- [Siguientes mejoras recomendadas](#siguientes-mejoras-recomendadas)

## Resumen funcional

La aplicacion ofrece cuatro capacidades principales:

1. Monitorizar conexiones de red vivas del host y clasificarlas por riesgo.
2. Mantener historial reciente de aperturas, cambios y cierres de sockets.
3. Gestionar reglas de confianza para reducir ruido analitico.
4. Persistir contexto local para que el motor aprenda patrones habituales del equipo.

Desde la interfaz se puede:

- Ver alertas abiertas, sesiones TCP establecidas y la tabla completa de conexiones vivas.
- Filtrar por riesgo, estado, direccion, texto libre y modo de ordenacion.
- Inspeccionar una conexion en detalle.
- Ver ruta del ejecutable, hash, firma, proceso padre, usuario y servicios alojados por `svchost.exe`.
- Consultar la vista cruda del sistema operativo para conexiones TCP establecidas.
- Marcar una conexion como confiable y generar una regla persistente.
- Descartar alertas y revisar su timeline.
- Cambiar parametros del motor de recoleccion, enriquecimiento y aprendizaje.

## Objetivo del proyecto

Sentinel Desk intenta cubrir un punto intermedio entre herramientas muy tecnicas del sistema y productos de seguridad mas pesados:

- Dar visibilidad util sobre sockets y procesos sin obligar a leer `netstat`, `tasklist` o PowerShell manualmente para cada caso.
- Reducir falsos positivos con heuristicas que entienden comportamiento normal de Windows.
- Conservar memoria local del host mediante patrones baseline y reglas del analista.
- Mantener una explicacion legible del por que una conexion recibe una determinada etiqueta de riesgo.

El foco del proyecto es la investigacion local y el triage rapido, no la inspeccion profunda de trafico ni la telemetria distribuida.

## Stack tecnologico

### Frontend

- React 19
- TypeScript
- Vite 7
- `@tauri-apps/api` para comunicar la UI con el backend nativo

### Backend de escritorio

- Tauri 2
- Rust 2021
- SQLite embebido mediante `rusqlite`
- `netstat2` para recolectar sockets del host
- `sysinfo` para asociar procesos y contexto
- `sha2` para calcular hashes SHA-256
- `reqwest` para enriquecimiento HTTP bloqueante y sencillo

### Dependencias del sistema usadas por el backend

La implementacion actual esta pensada claramente para Windows y usa utilidades nativas como:

- `powershell.exe`
- `Get-AuthenticodeSignature`
- `Resolve-DnsName`
- `Get-CimInstance Win32_Service`
- `Get-NetTCPConnection`
- `tasklist`

## Requisitos

### Requisitos funcionales

- Windows 10 o Windows 11
- PowerShell disponible
- Acceso local al estado de red y a la tabla de procesos del sistema

### Requisitos de desarrollo

- Node.js y npm
- Toolchain de Rust estable
- Prerrequisitos oficiales de Tauri para Windows
  Esto incluye, como minimo, el entorno de compilacion MSVC y WebView2.

### Recomendaciones practicas

- Ejecutar la aplicacion con una cuenta que pueda consultar procesos del host.
- Si quieres mas contexto sobre procesos del sistema, puede ayudar abrirla elevada.
- Para usar reputacion externa, necesitas una API key de AbuseIPDB.

## Puesta en marcha

### 1. Instalar dependencias JavaScript

```bash
npm install
```

### 2. Ejecutar la app de escritorio en desarrollo

```bash
npm run tauri:dev
```

Este es el flujo normal de desarrollo. Tauri levantara el frontend Vite y luego abrira la ventana nativa.

### 3. Generar el build del frontend

```bash
npm run build
```

Este comando solo compila la parte web en `dist/`.

### 4. Generar el bundle nativo de escritorio

```bash
npm run tauri:build
```

### 5. Ejecutar tests del backend Rust

```bash
cd src-tauri
cargo test
```

## Comandos disponibles

| Comando | Donde | Para que sirve |
| --- | --- | --- |
| `npm install` | raiz | Instala dependencias del frontend y CLI de Tauri. |
| `npm run tauri:dev` | raiz | Flujo completo de desarrollo de escritorio. |
| `npm run dev` | raiz | Arranca solo Vite. Tauri lo usa como `beforeDevCommand`, pero por si solo no cubre el backend nativo. |
| `npm run build` | raiz | Compila TypeScript y genera el frontend de produccion. |
| `npm run preview` | raiz | Sirve el build web generado por Vite. |
| `npm run tauri:build` | raiz | Empaqueta la app de escritorio. |
| `cargo test` | `src-tauri/` | Ejecuta los tests unitarios del backend. |

### Nota importante sobre `npm run dev`

La UI llama a comandos Tauri (`invoke`) desde el arranque. Eso significa que abrir el frontend solo en navegador no reproduce el comportamiento real de la aplicacion a menos que mockees las APIs nativas. Para desarrollo normal, usa `npm run tauri:dev`.

## Uso de la aplicacion

La interfaz se organiza en cuatro secciones principales.

### 1. Monitor

Es la vista principal y combina tres paneles:

- Alertas abiertas.
- Conexiones TCP establecidas.
- Tabla completa de conexiones vivas.

Desde aqui puedes:

- Filtrar por riesgo: `safe`, `unknown`, `suspicious` o todo.
- Filtrar por estado: activo, pasivo, establecido, escuchando o cerrado.
- Filtrar por direccion: entrante, saliente, listening, closing o closed.
- Ordenar por riesgo, recencia, proceso, endpoint remoto, endpoint local, score o confianza.
- Buscar por PID, proceso, ruta, IP, puerto, ASN, dominio o razones de scoring.

### 2. Activity history

Muestra eventos recientes de tipo:

- `opened`
- `updated`
- `closed`

La vista sirve para reconstruir cambios recientes aunque la conexion ya no este viva.

### 3. Trusted rules

Permite revisar y editar excepciones aprobadas por el analista. Cada regla puede fijar uno o varios de estos campos:

- nombre de proceso
- firma
- ruta ejecutable
- hash SHA-256
- patron remoto
- puerto
- protocolo
- direccion
- notas

Las reglas pueden activarse, desactivarse, editarse o borrarse.

### 4. Engine settings

Desde esta pantalla se ajustan los parametros que gobiernan el comportamiento del motor:

- intervalo de polling
- dias de retencion
- hits de aprendizaje baseline
- cooldown de alertas
- enriquecimiento de destino
- TTL de enriquecimiento
- reputacion externa
- proveedor y API key

### Modal de detalle de conexion

Al seleccionar una fila o alerta se abre una vista de inspeccion con:

- score y confianza
- path del ejecutable
- estado de firma e identidad
- proceso padre y usuario
- hash
- servicios alojados si el proceso es `svchost.exe`
- endpoint local y remoto
- datos de destino: scope, host, ASN, organizacion, dominio, pais
- razones de scoring
- timeline de la alerta

Tambien permite lanzar acciones de host:

- ver proceso con `tasklist`
- obtener ruta del ejecutable con PowerShell
- listar servicios de `svchost.exe`
- obtener detalle de esos servicios
- copiar una sugerencia de regla de firewall
- marcar como confiable
- descartar una alerta

## Como funciona internamente

### 1. Recoleccion de sockets

El backend ejecuta un bucle de monitorizacion en un hilo independiente. En cada ciclo:

1. Refresca el estado de procesos con `sysinfo`.
2. Consulta sockets TCP y UDP con `netstat2`.
3. Construye snapshots normalizados para cada socket.
4. Infiere direccion del trafico en TCP usando puertos y estado.

El intervalo por defecto es de `2` segundos.

### 2. Enriquecimiento de proceso

Para cada socket se intenta resolver:

- PID y nombre del proceso
- ruta del ejecutable
- usuario
- proceso padre
- firma digital
- publisher
- hash SHA-256
- servicios alojados si el proceso es `svchost.exe`

La firma y el hash no bloquean el render principal. El backend usa una cola asincrona simple con cache:

- primer ciclo: el proceso puede aparecer con `metadataPending`
- ciclos siguientes: la informacion se rellena cuando el trabajo termina

### 3. Enriquecimiento de destino

Si hay IP remota:

- se clasifica primero su scope: loopback, private, link-local, unspecified o public
- si es privada o local, se rellena informacion local basica
- si es publica y el enriquecimiento esta activo:
  - intenta reverse DNS con PowerShell
  - consulta `https://ipwho.is/<ip>`
  - cachea el resultado en SQLite con TTL

### 4. Reputacion externa

Si esta activada y existe API key:

- consulta AbuseIPDB
- transforma la respuesta en un veredicto simple: `malicious`, `trusted` o `unknown`
- guarda el resultado en cache local con TTL

### 5. Clasificacion y scoring

Cada conexion pasa por el clasificador heuristico del backend. El score combina muchos factores, entre ellos:

- estado del socket
- listener vs conexion activa
- ruta del ejecutable
- si el proceso esta firmado
- si existe hash estable
- relacion con proceso padre esperado
- contexto de usuario esperado
- servicios confiables en `svchost.exe`
- destino privado o publico
- puertos sensibles
- aprendizaje baseline previo
- reputacion externa
- reglas de confianza del analista

### 6. Persistencia y difusion a la UI

Cuando una conexion cambia de forma relevante:

- se guarda en SQLite
- puede generar o actualizar una alerta
- se anade un evento de actividad
- se emite un evento Tauri `monitor://connection`

La UI escucha ese canal y fusiona incrementalmente:

- conexiones modificadas
- alertas nuevas o actualizadas
- actividad reciente
- IDs de conexiones eliminadas

Ademas, el frontend hace una reconciliacion completa cada 30 segundos para evitar desincronizaciones.

## Politica de riesgo y scoring

El clasificador esta pensado para ser explicable. No trabaja como caja negra; devuelve score, confianza, razones y accion recomendada.

### Casos que reducen ruido de forma explicita

Hay heuristicas dedicadas a no convertir comportamiento normal de Windows en falso positivo. Por ejemplo:

- sockets en `TIME_WAIT`
- listeners legitimos del sistema como SMB en PID 4
- puertos RPC dinamicos esperables
- instancias de `svchost.exe` con servicios confiables
- destinos privados o loopback
- patrones ya aprendidos por baseline

### Factores que aumentan la sospecha

Algunos indicadores que elevan claramente el score:

- binarios desde rutas de usuario como `AppData`, `Temp`, `Downloads` o `Public`
- procesos unsigned en contexto no justificado
- nombres de procesos core de Windows ejecutandose desde rutas sospechosas
- trafico saliente de `script hosts` o LOLBins hacia IPs publicas
- uso inesperado de puertos sensibles
- mala reputacion externa
- ausencia fuerte de atribucion de proceso en conexiones activas

### Umbrales actuales

El motor convierte el score final a una etiqueta:

- `safe`: score `<= 4`
- `unknown`: score `< 38`
- `suspicious`: score `>= 38`

### Reglas de confianza

Las reglas de confianza tienen prioridad alta. Si una conexion encaja en una regla activa, el clasificador devuelve `safe` con una razon explicita de allowlist.

### Baseline local

El baseline se construye a partir de patrones del tipo:

- huella del proceso
- protocolo
- direccion
- puerto de servicio efectivo
- dimension del remoto

El objetivo es ignorar puertos efimeros locales y recordar patrones utiles del host, no sesiones exactas.

## Persistencia y datos locales

La base de datos SQLite se crea en el directorio de datos de la aplicacion de Tauri con el nombre:

```text
sentinel-desk.db
```

En Windows, normalmente acabara bajo una ruta similar a:

```text
%APPDATA%\com.asier.sentineldesk\sentinel-desk.db
```

### Tablas principales

| Tabla | Contenido |
| --- | --- |
| `settings` | Configuracion serializada del motor. |
| `allow_rules` | Reglas confiables persistentes creadas o editadas por el analista. |
| `connection_events` | Ultimo estado conocido por ID de conexion, con proceso, razones y reputacion. |
| `alerts` | Alertas activas, actualizadas o descartadas. |
| `alert_timeline_events` | Historial de eventos asociados a cada alerta. |
| `activity_events` | Aperturas, actualizaciones y cierres recientes. |
| `baseline_patterns` | Patrones observados y numero de hits para aprendizaje local. |
| `destination_cache` | Cache TTL de resolucion de destino y ASN. |
| `reputation_cache` | Cache TTL de reputacion externa. |

### Politica de retencion

El backend hace poda periodica de datos antiguos usando el valor `retentionDays`. Con la configuracion por defecto:

- polling cada 2 segundos
- poda cada 30 ciclos
- limpieza aproximada cada 60 segundos

Se eliminan eventos y alertas fuera de ventana, ademas de entradas expiradas de cache.

## Configuracion disponible

Los valores por defecto actuales son:

| Ajuste | Valor por defecto | Significado |
| --- | --- | --- |
| `pollingIntervalSecs` | `2` | Frecuencia del monitor. |
| `retentionDays` | `30` | Dias de datos a conservar. |
| `baselineLearningThreshold` | `3` | Veces que un patron debe verse antes de considerarse aprendido. |
| `alertCooldownMinutes` | `20` | Ventana para agrupar recurrencias de una alerta. |
| `enableDestinationEnrichment` | `true` | Activa reverse DNS y consulta a `ipwho.is`. |
| `destinationProvider` | `ipwhois + reverse dns` | Texto descriptivo del origen del enriquecimiento. |
| `destinationTtlMinutes` | `1440` | TTL de cache para enriquecimiento de destino. |
| `enableReputation` | `false` | Activa consultas de reputacion externa. |
| `reputationProvider` | `abuseipdb` | Proveedor de reputacion. |
| `reputationApiKey` | `null` | API key opcional de AbuseIPDB. |
| `reputationTtlMinutes` | `1440` | TTL de cache de reputacion. |
| `suspiciousPorts` | `22, 23, 135, 139, 445, 3389, 5900, 5985, 5986` | Puertos sensibles que elevan el score fuera de contexto. |

## Arquitectura del repositorio

```text
.
|-- src/
|   |-- App.tsx
|   |-- components/
|   |-- lib/
|   |-- styles.css
|   `-- types.ts
|-- src-tauri/
|   |-- src/
|   |   |-- lib.rs
|   |   |-- main.rs
|   |   |-- monitor.rs
|   |   |-- classifier.rs
|   |   |-- db.rs
|   |   |-- process_info.rs
|   |   |-- destination.rs
|   |   |-- reputation.rs
|   |   `-- command_runner.rs
|   |-- Cargo.toml
|   `-- tauri.conf.json
|-- package.json
`-- vite.config.ts
```

### Frontend

#### `src/App.tsx`

Es el orquestador principal del estado de la UI:

- arranca el bootstrap inicial
- se suscribe a eventos del monitor
- realiza reconciliacion periodica
- mantiene filtros, seleccion y tabs
- coordina paneles y modal de detalle

#### `src/components/`

Contiene piezas de interfaz orientadas a dominio:

- `AlertList.tsx`
- `EstablishedConnectionsPanel.tsx`
- `ConnectionTable.tsx`
- `ActivityHistoryPanel.tsx`
- `TrustedRulesPanel.tsx`
- `SettingsPanel.tsx`
- `DetailPanel.tsx`
- `CommandOutputModal.tsx`
- `SummaryCard.tsx`

#### `src/lib/tauri.ts`

Wrapper del frontend sobre `invoke` y `listen` de Tauri. Centraliza todos los comandos nativos consumidos por React.

#### `src/lib/connectionPresentation.ts`

Agrupa helpers de presentacion para convertir datos tecnicos en etiquetas, resumenes y textos legibles en la UI.

#### `src/types.ts`

Define los contratos TypeScript del frontend. Reflejan la estructura que expone el backend Rust por Tauri.

### Backend Rust

#### `src-tauri/src/lib.rs`

Punto de entrada real del backend Tauri:

- inicializa la base de datos
- carga settings, baselines, reglas y alertas activas
- arranca el monitor
- registra los comandos invocables desde la UI

#### `src-tauri/src/monitor.rs`

Es el corazon operativo de la aplicacion:

- recolecta sockets
- enriquece procesos y destinos
- llama al clasificador
- actualiza baseline
- inserta eventos y alertas
- emite actualizaciones a la UI

#### `src-tauri/src/classifier.rs`

Contiene la heuristica de scoring y las razones explicables que ve el usuario.

#### `src-tauri/src/db.rs`

Encapsula toda la persistencia SQLite:

- inicializacion de schema
- migraciones ligeras por columnas faltantes
- CRUD de reglas y settings
- actividad, alertas y timelines
- caches TTL
- poda de datos

#### `src-tauri/src/process_info.rs`

Resuelve identidad del proceso y metadatos asociados:

- path
- parent
- user
- firma
- publisher
- hash
- servicios de `svchost.exe`

#### `src-tauri/src/destination.rs`

Resuelve contexto del destino remoto y cachea resultados.

#### `src-tauri/src/reputation.rs`

Gestiona reputacion externa opcional mediante AbuseIPDB.

#### `src-tauri/src/command_runner.rs`

Ejecuta acciones de inspeccion bajo demanda desde la UI usando comandos del host.

## Integraciones externas y privacidad

La aplicacion puede funcionar enteramente en local si no necesitas enriquecimiento de internet.

### Trafico saliente potencial

Solo se hacen llamadas externas en estos casos:

- `ipwho.is` para ASN, organizacion, dominio y pais de IPs publicas
- AbuseIPDB para reputacion, si esta habilitado y hay API key

### Comportamiento local

Siempre puede consultar localmente:

- tabla de sockets
- tabla de procesos
- firma de ejecutables
- reverse DNS via PowerShell
- servicios alojados por `svchost.exe`

### Recomendacion operativa

Si trabajas en un entorno sensible o aislado:

- desactiva `Enable DNS and ASN enrichment`
- deja desactivada la reputacion externa

De ese modo la app seguira clasificando usando solo contexto local, baseline y reglas confiables.

## Calidad y validacion

### Validaciones existentes en el repo

Actualmente hay tests unitarios del backend para:

- scoring del clasificador
- listeners legitimos de Windows
- reglas de allowlist
- generacion de keys estables
- persistencia SQLite
- actividad y alertas

### Lo que si existe

- build del frontend con TypeScript y Vite
- tests Rust en `src-tauri`

### Lo que no existe ahora mismo

- script de lint en `package.json`
- suite de tests del frontend
- tests end-to-end de la interfaz

## Limitaciones actuales

Estas son las mas relevantes para mantenimiento y evolucion:

1. El proyecto esta muy orientado a Windows.
   Gran parte del backend depende de PowerShell y de utilidades propias del sistema.

2. `npm run dev` no representa el producto completo.
   La app real necesita Tauri para exponer comandos nativos a la UI.

3. El enriquecimiento HTTP es bloqueante.
   `reqwest::blocking` simplifica la implementacion, pero no es el enfoque mas escalable si el motor creciera mucho.

4. No hay captura de paquetes.
   La app razona sobre sockets y contexto del proceso, no sobre payload ni contenido de red.

5. El score es heuristico y local.
   Es muy util para triage, pero no pretende sustituir un motor de deteccion avanzado ni una telemetria centralizada.

6. Los contratos de tipos se mantienen en dos lugares.
   Hay modelos en Rust y tipos espejo en TypeScript sin generacion automatica.

7. Faltan quality gates en frontend.
   No hay lint ni tests React que protejan contra regresiones de interfaz.

## Siguientes mejoras recomendadas

Si se quiere llevar el proyecto a una siguiente fase, este seria un orden razonable:

1. Anadir `lint` y tests del frontend.
2. Introducir mocks del bridge Tauri para facilitar desarrollo browser-only y testing.
3. Extraer configuracion a un modulo compartido y documentar versionado de schema.
4. Unificar contratos Rust/TypeScript o automatizar su generacion.
5. Mover enriquecimiento de red a un modelo asincrono o a colas dedicadas.
6. Anadir exportacion de casos, filtros guardados y snapshots de investigacion.
7. Incorporar observabilidad interna del motor: tiempos por ciclo, cache hit rate y errores de enriquecimiento.

## Estado del proyecto

En el momento de redactar este README, el repositorio expone una base funcional bastante completa para:

- recoleccion local de conexiones
- scoring explicable
- reglas de confianza
- persistencia local
- timeline de alertas
- enriquecimiento de procesos y destinos

Es una base solida para seguir iterando en producto, calidad o integraciones sin tener que rehacer la arquitectura principal.
