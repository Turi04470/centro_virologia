# Registro de Versiones — Centro de Ciberseguridad (`EQ04`)

Control de versiones de la aplicación ubicada en `Proyecto/`.

---

## Tabla de Versiones

| Versión | Fecha | Estado | Resumen |
| :---: | :---: | :---: | :--- |
| **`v2.0`** | 2026-11-25 | Actual (Estable) | Adopción completa del **Estándar de Comunicación v2.0**: `EQ04` en puerto `5004`, descubrimiento UDP `5099` + escaneo HTTP `/24` + TOFU, sobre `CC-ENV-1`, proveedor remoto `/api/crypto/forward` & `inverse` (`DIFFIEHELLMAN` con `keyId` + `CAESAR`), delegación automática con respaldo local, validación de 14 pasos + `application/problem+json`, pestaña `Nodos` y vectores `vectores/EQ04/`. |
| **`v1.0`** | 2026-11-25 | Histórica | Lanzamiento inicial: 21 motores locales, `.ZIP` v1.0, `Consultas` (Tabla/Tarjetas + panel lateral), `Solicitudes` por IP, `Ajustes` granulares y compilado `win-x64`. |

---

## Versión `2.0` (2026-11-25)

### Cambios Principales respecto a `v1.0` (sin compatibilidad hacia atrás en protocolo `.zip`)
1. **Identidad y Red v2.0:**
   * Identificador oficial **`EQ04`** (`teamNumber = 4`), servidor HTTP en **`0.0.0.0:5004`**, descubrimiento UDP en puerto **`5099`** (anuncio `CC-BEACON` cada 30 s, `offline` al cerrar y expiración a 90 s).
   * Certificado X.509 v3 RSA-2048 autofirmado con sujeto `CN=EQ04, OU=Equipo 04, O=Centro de Ciberseguridad, C=MX` (`sha256WithRSAEncryption`) y huella SHA-256 en hex MAYÚSCULAS.
2. **Primitivas y Seguridad v2.0 (`CertificateAndZipService.cs`):**
   * **Sobre híbrido `CC-ENV-1`** (`RSA-OAEP-SHA256` + `AES-256-GCM` con AAD = `requestId` o `packetId`) para secretos y resultados.
   * **Cadena de firma extendida (11 campos)** y **hash canónico `publicParametersSha256`** con `RSA-PSS-SHA256`.
   * **Validación de 14 pasos** (sección 13.1): anti ZIP-bomb (≤ 200 MB y razón ≤ 100:1), estructura exacta de 3 entradas, `version = "2.0"`, diccionario de 21 algoritmos, ventana temporal ±10 min, protección anti-repetición (`409 E-DUPLICATE`) y verificación TOFU (`403 E-CERT-UNTRUSTED`).
   * **Errores estandarizados RFC 9457** (`application/problem+json`) con el catálogo oficial del Anexo B.
   * **Reempaquetado de reenvío (9.6):** conserva `datos.enc`, `publicParameters`, `keyRef` y `producerNode` actualizando `packetId`, `timestampUtc` y firma de `EQ04`.
3. **Roles de Proveedor y Solicitante:**
   * `EQ04` anuncia y provee **`DIFFIEHELLMAN` (7, con `keyId` persistente `EQ04-KEY-<uuid>`)** y **`CAESAR` (8)** en `GET /api/status`, `GET /api/algorithms`, `GET /api/keys/{keyId}`, `POST /api/crypto/forward`, `POST /api/crypto/inverse`, `GET /api/jobs/{jobId}` y `GET /api/jobs/{jobId}/result`.
   * En `Operar`, con **`Modo avanzado`** desactivado (por defecto en `Ajustes`), solo se muestran `DIFFIEHELLMAN`, `CAESAR` y los algoritmos de nodos `online` con huella fijada (TOFU) en `Nodos` (delegando automáticamente por red); al activar **`Modo avanzado`**, se habilitan los 21 motores localmente para respaldo o pruebas.
4. **Nueva Pestaña `Nodos` y Actualizaciones de UI:**
   * Directorio LAN en SQLite (`DirectoryNodes`) con anuncio UDP automático, botón **`Buscar nodos`** (escaneo HTTP `/24` puertos `5001`–`5020`), alta manual (`IP` + `Puerto`), confirmación TOFU y alerta visual si la huella cambia.
   * Panel lateral `Enviar .ZIP` en `Consultas` conectado al directorio de nodos; filtros de origen v2.0 (`Generado`, `Recibido`, `Resultado`).
   * `Solicitudes` muestra `sourceNode`, `operationName` y estado de confianza (`Firma OK` / `Remitente no confirmado` / `Inválida`).
5. **Vectores de Interoperabilidad:**
   * Carpeta `Proyecto/vectores/EQ04/` generada conforme a la sección 16.1 del estándar.

---

## Versión `1.0` (2026-11-25)
* Versión base con 21 motores criptográficos locales, base SQLite embebida, 5 vistas (`Operar`, `Inspector`, `Consultas` Tabla/Tarjetas, `Solicitudes`, `Ajustes`), tarjeta discreta `Equipo 4`, `29/29` pruebas unitarias y publicación `win-x64`.
