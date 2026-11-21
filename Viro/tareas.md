# Backlog de Tareas — Centro de Ciberseguridad

Este archivo registra las funcionalidades, mejoras y tareas de configuración pendientes o completadas para el proyecto ubicado en `Proyecto/`.  
**Regla de trabajo:** Las tareas aquí listadas permanecen en estado **`Pendiente`** hasta que el usuario indique explícitamente cuáles ejecutar.

---

## Resumen de Estado

| ID | Título | Prioridad | Estado |
| :---: | :--- | :---: | :---: |
| **T-01** | Enviar `.ZIP` desde `Consultas` directo a `Operar` leyendo `manifest.json` y `datos.enc` | Alta | `[x] Completada` |
| **T-02** | Quitar la clave sugerida por defecto en la app | Media | `[x] Completada` |
| **T-03** | Crear `Viro/manual.md` exclusivo de comandos (ejecución y publicación) | Media | `[x] Completada` |
| **T-04** | Configurar `Proyecto/` para VS Code (`C# Dev Kit`, `launch.json`, `tasks.json`) y guía de botón Run/F5 | Media | `[x] Completada` |
| **T-05** | Rediseñar acciones de `Consultas` con íconos (Editar, Descargar, Enviar blanco, Eliminar, Limpiar todos, Guardar todos) | Media | `[x] Completada` |
| **T-06** | Cambiar identidad del nodo a `NODO-04` y agregar vista alterna tipo tarjetas/tickets en `Consultas` | Media | `[x] Completada` |
| **T-07** | Agregar tarjeta discreta de `Equipo 4` en `Operar` y generar versión pública compilada | Media | `[x] Completada` |

---

## Detalle de Tareas

### `[x]` T-01: Cargar paquete `.ZIP` desde `Consultas` directo a `Operar`
* **Objetivo:** Evitar descargar manualmente el `.zip` y copiar/pegar su contenido en `Operar` para descifrarlo.
* **Alcance acordado:**
  1. **Backend (`Program.cs` / `CertificateAndZipService.cs`):**
     - Agregar endpoint `GET /api/consultas/{id}/unpack` que obtenga el `ZipBytes` desde SQLite (`SavedPackages`), descomprima en memoria `manifest.json` y `datos.enc`, valide integridad y devuelva `{ algorithmCode, algorithmName, payloadMode, originalFileName, dataText, dataBase64 }`.
  2. **Frontend (`wwwroot/index.html`, `wwwroot/app.js`):**
     - Agregar el botón **`Operar`** en cada fila de `Consultas` (tanto `Local` como `Recibido`).
     - Al hacer clic:
       - Cambiar automáticamente a la pestaña `Operar`.
       - Activar el modo **`Descifrar`**.
       - Seleccionar el algoritmo indicado en `manifest.json` (`algorithmCode`).
       - Cambiar al modo de entrada correspondiente (`Texto` o `Archivo`) según `payloadMode` y precargar `datos.enc` listo para que el usuario ingrese su clave y pulse `Descifrar`.
* **Criterio de aceptación:** Al recibir/aceptar un `.zip` en `Solicitudes` o generar uno en `Operar`, al ir a `Consultas` y pulsar **`Operar`**, la pantalla queda lista con el algoritmo y datos precargados para descifrar con un clic tras ingresar la clave.

---

### `[x]` T-02: Quitar la clave sugerida por defecto en la app
* **Objetivo:** Que la aplicación no sugiera ni rellene automáticamente ninguna contraseña/clave predeterminada.
* **Alcance acordado:**
  1. **Frontend (`wwwroot/app.js`):**
     - Eliminar la carga automática de `algo.defaultKey` en `#keyInput` (`updateDefaultKey()`) al iniciar o cambiar de algoritmo; el campo `#keyInput` debe quedar vacío por defecto.
     - Eliminar el fallback silencioso `|| algo.defaultKey` en `runOperation()`.
     - Conservar el botón **`Clave`** (`#genKeyBtn`) para generar una clave aleatoria únicamente cuando el usuario lo presione manualmente.
  2. **Backend (`CryptoEngineService.cs`):**
     - Eliminar el fallback silencioso a `algo.DefaultKey` cuando `req.Key` llegue vacío, exigiendo que el usuario ingrese una clave (excepto en algoritmos que no requieren clave secreta como `HASHSHA` al calcular el hash).
* **Criterio de aceptación:** Al cambiar entre los 21 algoritmos en `Operar`, el campo `Clave / Parámetro` permanece vacío y si se intenta cifrar/descifrar sin clave (en algoritmos con clave) se muestra un mensaje claro pidiendo la clave.

---

### `[x]` T-03: Crear `Viro/manual.md` exclusivo de comandos de ejecución y publicación
* **Objetivo:** Disponer de un manual ultra conciso que contenga **únicamente** los comandos necesarios para ejecutar la aplicación en desarrollo y para generar la versión pública autocontenida (`.exe` / `.zip`) cuando se necesite.
* **Alcance acordado:**
  - Crear `Viro/manual.md` únicamente con:
    1. Comando para ejecutar la aplicación localmente (`dotnet run`).
    2. Comando para publicar la versión autocontenida `win-x64` (`dotnet publish`).
    3. Comando para empaquetar la carpeta publicada en `.zip` (`7z`) lista para llevar a otra PC.
* **Criterio de aceptación:** `Viro/manual.md` existe y contiene solo comandos claros y listos para copiar y pegar en PowerShell.

---

### `[x]` T-04: Configurar VS Code en `Proyecto/` y guía para ejecutar con el botón Run/F5
* **Objetivo:** Dejar `Proyecto/` listo para abrirse en Visual Studio Code y ejecutarse directamente con el botón **Run / F5**.
* **Contexto detectado:** Actualmente `Proyecto/.vscode/` no existe y VS Code no tiene instalada la extensión `ms-dotnettools.csdevkit`.
* **Alcance acordado:**
  1. Instalar en VS Code la extensión oficial **`ms-dotnettools.csdevkit`** (`code --install-extension ms-dotnettools.csdevkit`).
  2. Crear `Proyecto/.vscode/tasks.json` (tarea `build` con `dotnet build`) y `Proyecto/.vscode/launch.json` (perfil `.NET Core Launch (web)` apuntando a `src/CentroCiberseguridad.Web` en `http://localhost:5000`).
  3. Entregar al usuario los pasos exactos para abrir `Proyecto/` en VS Code y ejecutar el proyecto desde el botón **Run / F5**.
* **Criterio de aceptación:** Al abrir `Proyecto/` en VS Code y presionar **F5** (o el botón **Run**), la aplicación compila, levanta en el puerto `5000` y abre en el navegador sin errores.

---

### `[x]` T-05: Botones por ícono y acciones masivas en `Consultas`
* **Objetivo:** Reemplazar los botones textuales de cada fila por íconos minimalistas y sumar acciones individuales y masivas en `Consultas`.
* **Alcance implementado:**
  1. **Por fila (`wwwroot/index.html`, `wwwroot/styles.css`, `wwwroot/app.js`):**
     - `Operar` → ícono de editar (lápiz).
     - `.ZIP` → ícono de descarga.
     - `Enviar` → ícono de avión de papel resaltado en sólido/blanco (`.icon-action-solid`).
     - Eliminar individual → ícono de papelera (`.icon-action-danger`) conectado a `DELETE /api/consultas/{id}`.
  2. **Acciones globales (`Program.cs`, `SqliteDatabaseService.cs`):**
     - **`Guardar todos`**: `GET /api/consultas/export-all` empaqueta todos los `.zip` guardados en un único archivo `Consultas_Export_YYYYMMDD_HHMMSS.zip`.
     - **`Limpiar todos`**: `DELETE /api/consultas` vacía la tabla `SavedPackages` en SQLite.

---

### `[x]` T-06: Identidad `NODO-04` y vista tipo tarjetas/tickets en `Consultas`
* **Objetivo:** Identificar este nodo como `NODO-04` en certificado X.509, manifiestos, `.zip` y UI, y sumar un modo de visualización en tarjetas/tickets sin quitar la tabla.
* **Alcance implementado:**
  1. **Identidad `NODO-04`:** Actualizado en `DomainModels.cs`, `CertificateAndZipService.cs` (`CN=NODO-04`, `NODO04_<ALGO>_...zip`), `SqliteDatabaseService.cs`, `Program.cs` (`/api/status` y `X-Source-Node`) y `wwwroot/index.html`.
  2. **Vista `Tarjetas` en `Consultas`:** Selector segmentado `Tabla | Tarjetas` persistente en `localStorage` con tarjetas tipo ticket (`.tickets-grid` / `.ticket-card`) que conservan los mismos 4 botones por ícono.

---

### `[x]` T-07: Tarjeta discreta de `Equipo 4` en `Operar` y publicación `win-x64`
* **Objetivo:** Mostrar discretamente los créditos del **Equipo 4** al final de `Operar` y regenerar el paquete público autocontenido.
* **Alcance implementado:**
  1. Tarjeta `.team-card` centrada al pie de `#view-operar` (`Equipo 4` + los 4 integrantes).
  2. Compilación `dotnet test -c Release`, `dotnet publish -c Release -r win-x64 --self-contained true` en `Proyecto/publicado` y empaquetado en `Proyecto/CentroCiberseguridad_win-x64.zip`.
