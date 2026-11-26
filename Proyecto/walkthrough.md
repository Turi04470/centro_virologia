# Walkthrough — Creación y Evolución del Proyecto (`NODO-04`)

Este documento resume paso a paso cómo se diseñó, construyó, probó y evolucionó la aplicación **Centro de Ciberseguridad (`NODO-04`)** en `.NET 10` + `SQLite`.

---

## 1. Análisis de Requerimientos y Diseño Inicial
1. **Levantamiento base:** Se analizaron las guías y materiales teóricos del curso en `Viro/`, identificando **20 algoritmos/métodos** (implementados como **21 motores funcionales** en código) y los requisitos de entrega: cifrado/descifrado de texto, archivos e imágenes, certificados digitales X.509 y comunicación entre células de trabajo.
2. **Estándar de intercambio `.ZIP` (`Viro/propuesta.md`):** Se definió el protocolo común por IP (`GET /api/status`, `POST /api/requests/receive`) y el paquete `.zip` obligatorio con 3 archivos en raíz (`datos.enc`, `certificado.pem`, `manifest.json`) bajo la nomenclatura:
   ```text
   <NODO_ORIGEN>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8>.zip
   ```
   usando códigos cortos oficiales en MAYÚSCULAS (`AESGCM` .. `LORENZSZ40`).

---

## 2. Prototipo Visual y UX (`prototipo/`)
Antes de programar el backend, se validó un prototipo HTML/CSS/JS minimalista inspirado en `cifraronline.com`:
* **Tema dual sin mezcla amarillo + azul:**
  * **Modo Oscuro:** fondo `#0E0E0E`, tarjetas `#161616` y acento dorado `#C5992E`.
  * **Modo Claro:** fondo `#F8F8F8`, tarjetas `#FFFFFF` y acento azul `#003882`.
* **Flujo unificado:** Se eliminó la pestaña separada de *Certificados* (al integrarse cada certificado dentro del `.zip`) y se pospuso la red *Ping-Pong* para una actualización futura, consolidando 5 vistas: `Operar`, `Inspector`, `Consultas`, `Solicitudes` y `Ajustes`.

---

## 3. Arquitectura Implementada en `.NET 10` (`Proyecto/`)

### Backend (`src/CentroCiberseguridad.Web/`)
* **Modelos (`Models/DomainModels.cs`):** `AlgorithmConfig`, `OperateRequest`, `OperateResponse`, `SignedManifest`, `DigitalCertificateRecord`, `SavedPackageRecord`, `IncomingRequestRecord`, `UnpackedPackageResponse`.
* **Persistencia SQLite (`Services/Data/SqliteDatabaseService.cs`):** Base local `ciberseguridad.db` (embebida vía `Microsoft.Data.Sqlite 11.0.0`, sin instalación externa) con 5 tablas: `AlgorithmConfigs`, `DigitalCertificates`, `SavedPackages`, `IncomingRequests` y `CryptoOperationsLog`.
* **Motores Criptográficos (`Services/Crypto/CryptoEngineService.cs`):** Implementación en C# de los **21 motores** (`AESGCM`, `DES`, `TRIPLEDES`, `CHACHA20`, `RSA`, `ECC`, `DIFFIEHELLMAN`, `CAESAR`, `VIGENERE`, `XORASM`, `LSBSTEGO`, `EUCLIDESAFFINE`, `MILLERRABIN`, `FISHERYATES`, `HASHSHA`, `HMACSHA256`, `DIGITALSIG`, `QUANTUMPQC`, `DFTSPECTRAL`, `LAGRANGESHAMIR`, `LORENZSZ40`) con validación estricta de permisos (`IsVisible`, `CanEncrypt`, `CanDecrypt`).
* **Certificados X.509 y Empaquetado `.ZIP` (`Services/Transfer/CertificateAndZipService.cs`):** Emisión automática de certificado autofirmado `RSA-2048` (`CN=NODO-04`), firma `RSA-PSS-SHA256` de `manifest.json` y validación de integridad/firma al recibir paquetes externos.
* **API REST (`Program.cs`):** Escucha en `http://0.0.0.0:5000` exponiendo endpoints para operar, configurar permisos, consultar/enviar/descargar/eliminar paquetes `.zip` y recibir/aceptar/rechazar solicitudes entrantes.

### Frontend (`wwwroot/`)
* **`Operar`:** Tarjeta única con transición *in-place* (Entrada → Salida), modos `Texto`, `Archivo` y `LSB` en `<canvas>`, y tarjeta discreta de **Equipo 4** al pie.
* **`Inspector`:** Visualización de estado en `Matriz`, `Hex` o `Binario` y pasos internos de la operación.
* **`Consultas`:** Historial de paquetes `Local` y `Recibido` con vista alternable **`Tabla | Tarjetas`**, panel lateral desplegable para enviar `.zip` por `IP:Puerto`, acciones por ícono (`Operar`, `Descargar .ZIP`, `Enviar` resaltado en blanco, `Eliminar`) y botones globales `Guardar todos` y `Limpiar todos`.
* **`Solicitudes`:** Bandeja de recepción por IP con `Aceptar` (inserta automáticamente en `Consultas`) y `Rechazar`.
* **`Ajustes`:** Buscador, botón `Ocultar Todos` y 3 interruptores por algoritmo (`Visible`, `Cifrar`, `Descifrar`).

---

## 4. Cambios Evolutivos Aplicados (`T-01` a `T-07`)

| ID | Cambio aplicado |
| :---: | :--- |
| **T-01** | Desempaquetado directo desde `Consultas` hacia `Operar` (`GET /api/consultas/{id}/unpack`), leyendo `manifest.json` y `datos.enc` (soportando salidas textuales, binarias Base64 y archivos). |
| **T-02** | Eliminación de la clave sugerida por defecto en frontend y backend (campo vacío al iniciar/cambiar algoritmo, exigiendo clave manual salvo `HASHSHA` al calcular hash). |
| **T-03** | Creación de `Viro/manual.md` exclusivo con comandos de ejecución y publicación. |
| **T-04** | Configuración de VS Code (`.vscode/tasks.json`, `.vscode/launch.json` e instalación de `ms-dotnettools.csdevkit`) para ejecutar con **F5 / Run**. |
| **T-05** | Rediseño de acciones en `Consultas` con íconos minimalistas (`Editar`, `Descargar`, `Enviar` sólido en blanco, `Eliminar`), más `Guardar todos` (`export-all`) y `Limpiar todos`. |
| **T-06** | Cambio de identidad completa a **`NODO-04`** (`CN=NODO-04`, `NODO04_...zip`, `/api/status`) y vista alterna tipo **`Tarjetas`** en `Consultas`. |
| **T-07** | Tarjeta discreta de **Equipo 4** en `Operar` y generación de compilado público autocontenido (`publicado/` y `CentroCiberseguridad_win-x64.zip`). |

---

## 5. Verificación y Empaquetado
* **Pruebas automatizadas (`tests/CentroCiberseguridad.Tests/CryptoAndZipTests.cs`):** `dotnet test -c Release` ejecutado con **29/29 pruebas aprobadas** (`0` errores, `0` advertencias), cubriendo ida y vuelta de los 21 algoritmos, modo archivo binario, permisos de `Ajustes`, validación `.zip` + detección de alteración de 1 byte, desempaquetado `Consultas → Operar` y eliminación individual/masiva.
* **Publicación `win-x64`:** Generada en `Proyecto/publicado/CentroCiberseguridad.Web.exe` y comprimida en `Proyecto/CentroCiberseguridad_win-x64.zip` para ejecutarse en otra PC Windows sin instalar `.NET` ni `SQLite`.
* **Documentación de arranque:** [README.md](file:///C:/Users/Administrator/Documents/GitHub/Centro%20de%20virlogia/Proyecto/README.md) actualizado con requisitos de Windows (`.NET 10 SDK` + `SQLite` embebido) y comandos de ejecución, pruebas y publicación.
