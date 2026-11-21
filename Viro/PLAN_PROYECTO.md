# Plan Maestro del Proyecto: Centro de Ciberseguridad Multi-Algoritmo

**Ubicación de documentación y planificación:** `C:\Users\Administrator\Documents\GitHub\Centro de virlogia\Viro\`  
**Ubicación del código fuente (por desarrollar):** `C:\Users\Administrator\Documents\GitHub\Centro de virlogia\Proyecto\`  
**Fecha de elaboración:** 16 de noviembre de 2026  

---

## 1. Resumen Ejecutivo y Decisiones de Diseño (Levantamiento de Requerimientos)

Este documento define la arquitectura, especificaciones funcionales, catálogo criptográfico, protocolos de red y plan de implementación por fases para el proyecto **Centro de Ciberseguridad**, desarrollado como nodo interoperable dentro de la red de células de trabajo del grupo.

### 1.1 Principios y Decisiones Acordadas
* **Enfoque General (Universal y Agnóstico de Dominio):** A diferencia de un sistema limitado a una temática específica (como expedientes clínicos o biblioteca), la aplicación será una **plataforma universal de procesamiento criptográfico** capaz de cifrar, descifrar, firmar, ocultar y verificar **texto plano**, **archivos binarios/documentos arbitrarios** e **imágenes (PNG/BMP)**.
* **Stack Tecnológico:** **.NET 10 (`10.0.102`) — C# / ASP.NET Core Web App + API REST**, ejecutable en navegador local y accesible vía red local (LAN) desde los equipos de otras células de trabajo.
* **Base de Datos Local:** **SQLite** (`ciberseguridad.db`) mediante `Microsoft.Data.Sqlite` / Entity Framework Core. Portátil, autocontenida, sin dependencias de servidores externos y de cero configuración.
* **Gestión de Certificados Digitales Integrada:** Emisión automática local en formato estándar **X.509 v3 (`.pem`)** y **Manifiesto JSON Firmado (`manifest.json`)** empaquetados directamente dentro de cada archivo `.zip` (se elimina la pestaña independiente de Certificados al integrarse en el ciclo de envío/recepción).
* **Protocolo Estandarizado de Intercambio `.ZIP` por IP (`propuesta.md`):** Cada equipo implementará obligatoriamente **Modo de Envío** (`POST /api/requests/receive` por `IP:Puerto`) y **Modo de Recepción** (bandeja de `Solicitudes` con validación automática y acciones `Aceptar` / `Rechazar`). La dinámica "Ping-Pong" queda reservada para una actualización futura.

### 1.2 Requerimiento Especial: Panel de Configuraciones Granular de Algoritmos
Dado que los integrantes del equipo o la red de células pueden requerir restringir algoritmos específicos por módulo, rol o demostración, el sistema contará con un **Panel de Configuraciones** persistente en SQLite que gobierna cada algoritmo/método de forma independiente mediante **tres interruptores por algoritmo**:

| Interruptor (`AlgorithmConfigs`) | Valores | Comportamiento en UI y Backend (API) |
| :--- | :---: | :--- |
| **`IsVisible`** *(Mostrar / Ocultar)* | `true` / `false` | Si es `false`, el algoritmo **desaparece por completo** de los selectores, menús desplegables, tarjetas y catálogos de la interfaz principal (solo sigue administrable dentro del Panel de Configuraciones). Además, sus endpoints directos rechazan la ejecución si está oculto/deshabilitado según política. |
| **`CanEncrypt`** *(Habilitar / Deshabilitar Encriptación)* | `true` / `false` | Controla si el algoritmo puede ejecutar operaciones de **cifrado, ocultamiento (LSB), generación de firma/HMAC, encapsulación o fragmentación**. Si es `false`, la opción de cifrar con ese algoritmo queda deshabilitada en UI y bloqueada con HTTP `403 Forbidden` en el backend. |
| **`CanDecrypt`** *(Habilitar / Deshabilitar Desencriptación)* | `true` / `false` | Controla si el algoritmo puede ejecutar operaciones de **descifrado, extracción (LSB), verificación de integridad/firma o reconstrucción**. Si es `false`, la opción de descifrar queda deshabilitada en UI y bloqueada con HTTP `403 Forbidden` en el backend. |

#### Acción Rápida en Configuraciones
* **`Ocultar Todos`:** Apaga `IsVisible`, `CanEncrypt` y `CanDecrypt` en los 21 algoritmos para dejar la vista `Operar` limpia y habilitar manualmente solo los algoritmos deseados mediante sus 3 interruptores individuales.

---

## 2. Catálogo Completo de Algoritmos y Métodos a Implementar

Con base en los **20 algoritmos y métodos** identificados en el material de apoyo (desglosados en **21 motores funcionales** al separar explícitamente Hash, HMAC y Firmas, e integrando Esteganografía, Simulador Cuántico/PQC, DFT, Lagrange y Lorenz), cada módulo implementará procesamiento tanto para **Texto** como para **Archivos/Imágenes**, acompañado de un **Inspector Matemático / Paso a Paso** con fines didácticos.

| # | Algoritmo / Método | Categoría | Operación en Texto (`Encriptar` / `Descifrar`) | Operación en Archivos e Imágenes (`Encriptar` / `Descifrar`) | Parámetros / Llaves e Inspector Paso a Paso |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | **AES (128 / 192 / 256)** *(Modos GCM y CBC)* | Simétrico por Bloques | Cifrado/descifrado UTF-8 con resultado en Base64/Hex. En GCM incluye etiqueta de autenticación (*Tag*). | Cifrado binario completo de cualquier archivo o imagen preservando extensión y metadatos en cabecera/manifiesto. | Clave de 128/192/256 bits + Nonce/IV aleatorio. **Inspector:** Matriz de estado `4×4`, expansión de subclaves de ronda (*Key Schedule*) y traza de `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`. |
| **2** | **DES (56 bits)** | Simétrico Legado | Cifrado/descifrado de texto por bloques de 64 bits con padding PKCS#7 (aviso educativo de obsolescencia). | Procesamiento por bloques de 64 bits de archivos binarios con almacenamiento seguro de IV en modo CBC. | Clave de 64 bits (56 bits efectivos) + IV. **Inspector:** Permutación inicial/final, red de Feistel de 16 rondas y cajas S. |
| **3** | **Triple DES (3DES / TDEA y perfil "Triple-DES-96")** | Simétrico Legado | Esquema EDE (*Encrypt-Decrypt-Encrypt*) con 2 o 3 llaves y perfil parametrizado de clave truncada/etiquetada ("Triple-DES-96"). | Cifrado/descifrado binario por bloques de 64 bits bajo esquema EDE para archivos completos. | Llaves `K1, K2, K3` (112/168 bits y perfil 96). **Inspector:** Traza de las 3 pasadas E-D-E y aviso de retiro NIST (2024). |
| **4** | **ChaCha20 y ChaCha20-Poly1305** | Simétrico de Flujo (AEAD) | Cifrado autenticado en tiempo real de texto UTF-8 con etiqueta Poly1305 anti-alteración. | Cifrado de flujo de alto rendimiento para archivos grandes sin tablas de búsqueda (*look-up tables*). | Clave de 256 bits, Nonce de 96 bits y contador. **Inspector:** Matriz inicial `4×4` (constantes `"expand 32-byte k"`, clave, contador, nonce) y operaciones ARX (*Add-Rotate-XOR*). |
| **5** | **RSA (RSA-OAEP / RSA-PSS + Modo Didáctico)** | Asimétrico | **Modo Real (OAEP):** Cifra texto corto o envuelve clave de sesión AES. **Modo Didáctico:** Aritmética directa $c = m^e \bmod n$ con primos pequeños o medianos. | **Cifrado Híbrido:** Cifra el archivo con clave efímera AES-256-GCM y protege dicha clave con la llave pública RSA-OAEP del destinatario. | Par de llaves $(n, e)$ pública y $(d, p, q)$ privada (2048/4096 bits o modo didáctico). **Inspector:** Cálculo de $n=p\cdot q$, $\varphi(n)$, $e\cdot d \equiv 1 \pmod{\varphi(n)}$ y exponenciación modular. |
| **6** | **ECC (ECDH + ECIES Híbrido + ECDSA)** | Asimétrico (Curva Elíptica) | Establece secreto compartido ECDH (`NIST P-256 / secp256r1`), deriva clave simétrica vía HKDF y cifra/descifra el texto con AES-GCM. | Esquema híbrido ECIES para cifrar y descifrar cualquier archivo o imagen usando la clave pública ECC del receptor. | Par de llaves ECC (`a` privada, `A = aG` pública). **Inspector:** Coordenadas del punto público $(X, Y)$, derivación HKDF y comparación con tamaño de llave RSA equivalente. |
| **7** | **Diffie-Hellman Clásico ($g^a \bmod p$)** | Acuerdo de Claves + Cifrado Derivado | Simula intercambio entre Alice y Bob ($A = g^a \bmod p$, $B = g^b \bmod p$), calcula $K$ compartido y cifra/descifra el texto con clave derivada. | Usa el secreto compartido $K$ derivado a 256 bits para cifrar y descifrar archivos completos. | Primo público $p$, generador $g$, secretos privados $a, b$. **Inspector:** Tabla completa de valores públicos/privados y comprobación $B^a \bmod p = A^b \bmod p$. |
| **8** | **Cifrado César** | Clásico | Desplazamiento monoalfabético configurable (`mod 26` respetando mayúsculas/minúsculas o alfabeto UTF-8 extendido). | Desplazamiento modular byte a byte `C = (B + k) mod 256` y reverso `B = (C - k) mod 256` para archivos binarios. | Desplazamiento entero $k$. **Inspector:** Tabla carácter por carácter (`C(2) -> (2+3) mod 26 = 5 -> F`) o byte por byte en hexadecimal. |
| **9** | **Cifrado Vigenère** | Clásico Polialfabético | Sustitución por palabra clave repetida sobre el alfabeto (`mod 26` o tabla extendida). | Suma/resta modular del flujo de bytes de la clave repetida sobre los bytes del archivo (`mod 256`). | Palabra/cadena clave. **Inspector:** Alineación letra/byte de texto claro con clave y cálculo modular paso a paso. |
| **10** | **Cifrado XOR en Ensamblador (Nivel Registro)** | Bajo Nivel / IoT | Simulación de registro de 8/16/32 bits (`WREG`) ejecutando `XOR` y operaciones opcionales de rotación/desplazamiento (`ROL`, `ROR`, `SHL`, `SHR`) invertibles. | Procesamiento de flujo binario aplicando máscara XOR con llave multi-byte y rotación reversible de bits por byte/palabra. | Llave binaria/hexadecimal + patrón de rotación (`ROL/ROR`). **Inspector:** Traza en binario, hexadecimal y pseudocódigo ensamblador (`MOV`, `XORWF`, `ROL`, `ROR`). |
| **11** | **Esteganografía LSB (Least Significant Bit)** | Ocultamiento de Información | **Encriptar/Ocultar:** Inserta el texto (opcionalmente comprimido o pre-cifrado) en los bits menos significativos de una imagen PNG/BMP. **Descifrar/Extraer:** Recupera el mensaje oculto. | **Encriptar/Ocultar:** Incrusta un archivo arbitrario (PDF, TXT, ZIP, etc.) con su cabecera de nombre y tamaño dentro de los píxeles RGB/RGBA de una imagen portadora PNG/BMP sin pérdidas. | Imagen portadora (PNG/BMP) + canal RGB/LSB (1-2 bits). **Inspector:** Comparativa de píxel original vs. modificado en decimal/binario (`0110100[0]` → `0110100[1]`) y capacidad disponible en bytes. |
| **12** | **Algoritmo de Euclides y Euclides Extendido (Cifrado Afín)** | Teoría de Números | **Encriptar:** Cifrado afín modular $C = (a \cdot M + b) \bmod m$. **Descifrar:** Calcula $a^{-1} \bmod m$ con Euclides Extendido y aplica $M = a^{-1}(C - b) \bmod m$. | Cifrado/descifrado afín sobre $\mathbb{Z}_{256}$ byte a byte exigiendo $\text{MCD}(a, 256) = 1$. | Coeficientes $(a, b)$ coprimos con el módulo $m$. **Inspector:** Tabla completa de divisiones sucesivas, residuos, cálculo de $\text{MCD}$ e inverso multiplicativo por sustitución hacia atrás. |
| **13** | **Miller–Rabin + Cifrado con Primos Verificados** | Primalidad y Criptografía Modular | Evalúa primalidad de enteros grandes/medianos ingresados o generados y emplea dos primos verificados $(p, q)$ para cifrar/descifrar mensajes mediante exponenciación modular. | Utiliza la pareja de primos verificados por Miller–Rabin para generar llaves de cifrado/envoltura sobre el archivo. | Candidato $n$, número de rondas $k$, bases testigo $a$. **Inspector:** Descomposición $n - 1 = d \cdot 2^s$, cálculo de $a^d \bmod n$ y cuadrados sucesivos por ronda. |
| **14** | **Generación de Permutaciones (Fisher–Yates)** | Transposición / Combinatoria | **Encriptar:** Genera una permutación determinista vía Fisher–Yates usando una semilla/clave criptográfica y reordena los caracteres del texto. **Descifrar:** Aplica la permutación inversa exacta. | Reordena bloques o bytes del archivo mediante índices generados por Fisher–Yates con PRNG determinista desde la clave y restaura el orden original al descifrar. | Semilla/clave de barajado + tamaño de bloque. **Inspector:** Traza de intercambios $(i, j)$ paso a paso y vector de permutación directa e inversa. |
| **15** | **Funciones Hash (SHA-256, SHA-384, SHA-512, SHA-3)** | Integridad (Unidireccional) | **Encriptar/Calcular:** Genera el resumen hexadecimal/Base64 del texto. **Descifrar/Verificar:** Recalcula el hash del texto y lo compara en tiempo constante contra una huella esperada (*checksum*). | Calcula la huella digital del archivo completo y valida que un archivo recibido coincida bit a bit con un digest proporcionado. | Algoritmo (`SHA-256`, `SHA-512`, `SHA3-256`), digest de comparación. **Inspector:** Longitud fija en bits, efecto avalancha al cambiar 1 carácter y resultado de verificación. |
| **16** | **HMAC (HMAC-SHA256 / HMAC-SHA512)** | Autenticación de Mensajes | **Encriptar/Sellar:** Genera etiqueta HMAC con clave secreta compartida. **Descifrar/Verificar:** Valida etiqueta HMAC sobre el texto recibido en tiempo constante. | Sella archivos o payloads con etiqueta HMAC-SHA256/512 y verifica autenticidad e integridad al recibirlos. | Clave secreta compartida + variante hash. **Inspector:** Construcción `H((K ⊕ opad) || H((K ⊕ ipad) || m))` y estado de validación. |
| **17** | **Firmas Digitales (RSA-PSS y ECDSA P-256)** | Autenticidad y No Repudio | **Encriptar/Firmar:** Emite firma digital sobre el hash del texto usando llave privada. **Descifrar/Verificar:** Valida la firma con la llave pública o certificado X.509. | Firma archivos binarios generando archivo `.sig` o manifiesto JSON firmado, y verifica que el archivo no fue alterado. | Par de llaves (RSA/ECDSA) y esquema de padding (`PSS`/`P-256`). **Inspector:** Digest del documento, firma en Base64/Hex y resultado booleano de verificación criptográfica. |
| **18** | **Criptografía Cuántica (QKD BB84) y Poscuántica (PQC: ML-KEM / ML-DSA / Retículos LWE)** | Cuántica / Poscuántica | **QKD BB84:** Simula envío de fotones en bases rectilínea/diagonal (con opción de activar a "Eve" para detectar intercepción por tasa QBER), negocia clave y cifra/descifra texto. **PQC:** Encapsulación en retículos (LWE/ML-KEM) para establecer secreto y cifrar texto. | Usa el secreto compartido establecido por BB84 o por el módulo poscuántico (ML-KEM / LWE) para cifrar y descifrar archivos con cifrado autenticado derivado, además de firmar con esquema resistente cuántico. | Bases BB84, probabilidad de espía Eve, parámetros de retículo $(n, q, \sigma)$ o perfil FIPS 203/204. **Inspector:** Tabla de fotones/bases coincidentes, QBER (%) y matrices de retículo. |
| **19** | **Transformada Discreta de Fourier (DFT / IDFT Espectral)** | Procesamiento Matemático Reversible | Convierte códigos de caracteres en señal discreta $x[n]$, aplica DFT hacia el espectro complejo $X[k]$, aplica máscara/permutación espectral por clave; para descifrar invierte la máscara y reconstruye vía IDFT con redondeo exacto. | Procesa bloques de bytes del archivo mediante DFT + transformación de fase/permutación con clave y reconstruye los bytes exactos mediante IDFT. | Clave/semilla de fase y permutación espectral. **Inspector:** Magnitudes $|X[k]|$, fases en el dominio de frecuencia y demostración educativa de reversibilidad vs. seguridad criptográfica real. |
| **20** | **Teorema de Lagrange (Shamir Secret Sharing en $\text{GF}(256)$ + Subgrupos)** | Álgebra de Grupos / Umbral $(K, N)$ | **Encriptar/Fragmentar:** Codifica cada byte del texto como término constante de un polinomio de grado $K-1$ en $\text{GF}(256)$ generando $N$ participaciones. **Descifrar/Reconstruir:** Aplica interpolación polinomial de Lagrange con $\ge K$ participaciones. | Divide un archivo completo (o su clave de cifrado) en $N$ archivos/fragmentos `.share` de umbral $(K, N)$ y lo reconstruye exactamente al reunir al menos $K$ piezas. | Total de partes $N$, umbral mínimo $K$ ($K \le N$). **Inspector:** Polinomio generado en $\text{GF}(256)$, tabla de subgrupos (Teorema de Lagrange en grupos $\mathbb{Z}_m$) y pasos de interpolación $f(0)$. |
| **21** | **Máquina / Cifrado Lorenz (SZ40/42)** | Cifrado de Flujo Electromecánico | Simula las 12 ruedas binarias ($\chi_1..\chi_5$, $\psi_1..\psi_5$ y ruedas motor $\mu_{37}, \mu_{61}$) con código de 5 bits (Baudot ITA2 o flujo binario UTF-8) haciendo XOR reversible. | Aplica el flujo pseudoaleatorio generado por las ruedas Lorenz sincronizadas byte a byte sobre archivos binarios (operación autoinversa). | Configuración inicial de pines y posiciones de inicio de las 12 ruedas (clave de sesión). **Inspector:** Estado bit a bit de ruedas $\chi$, $\psi$, bit de avance $\mu$ y operación XOR por carácter/byte. |

> **Nota sobre Operaciones de Unidireccionalidad o Especiales:** Para algoritmos que por definición matemática no son de cifrado tradicional (como **Hash**, **HMAC**, **Firmas Digitales**, **Esteganografía**, **QKD** o **Shamir/Lagrange**), la interfaz adaptará las etiquetas de acción de forma clara conservando la semántica dual exigida por el usuario (`CanEncrypt` = Cifrar / Sellar / Firmar / Ocultar / Fragmentar; `CanDecrypt` = Descifrar / Verificar / Extraer / Reconstruir).

---

## 3. Estándar de Empaquetado `.ZIP` y Certificados Digitales (según `propuesta.md`)

Cada nodo generará y administrará su identidad local usando `System.Security.Cryptography.X509Certificates` de .NET 10, integrando el certificado directamente en cada paquete `.zip` exportado o enviado por IP (sin requerir una pantalla separada de Certificados).

### 3.1 Nomenclatura y Códigos Cortos Oficiales en MAYÚSCULAS
Todo paquete `.zip` debe seguir el formato:
```text
<NODO_ORIGEN>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8>.zip
```
Donde `<ALGORITMO>` utiliza exactamente los **21 códigos cortos oficiales en MAYÚSCULAS** definidos en `propuesta.md` (`AESGCM`, `DES`, `TRIPLEDES`, `CHACHA20`, `RSA`, `ECC`, `DIFFIEHELLMAN`, `CAESAR`, `VIGENERE`, `XORASM`, `LSBSTEGO`, `EUCLIDESAFFINE`, `MILLERRABIN`, `FISHERYATES`, `HASHSHA`, `HMACSHA256`, `DIGITALSIG`, `QUANTUMPQC`, `DFTSPECTRAL`, `LAGRANGESHAMIR`, `LORENZSZ40`).

### 3.2 Estructura Interna del `.ZIP` (3 archivos obligatorios en raíz)
1. **`datos.enc`** — Contenido cifrado o estego-imagen en binario/texto.
2. **`certificado.pem`** — Certificado público X.509 v3 del nodo emisor.
3. **`manifest.json`** — Metadatos técnicos (`version`, `packetId`, `sourceNode`, `sourceIp`, `timestampUtc`, `algorithm`, `algorithmCode`, `payloadMode`, `originalFileName`, `encryptedSha256`, `publicParameters`, `certificateThumbprintSha256`, `signatureAlgorithm`, `manifestSignatureBase64`).

---

## 4. Protocolo de Envío y Recepción por IP (y Alcance Futuro Ping-Pong)

Siguiendo la especificación de `propuesta.md`, **todos los nodos implementarán obligatoriamente ambos modos**:

### 4.1 Modo de Recepción (Endpoints REST en `0.0.0.0:5000`)
1. **`GET /api/status`** — Devuelve `nodeId`, `protocolVersion` (`"1.0"`), `status` (`"online"`) y `acceptingPackages` (`true`).
2. **`POST /api/requests/receive`** (`multipart/form-data`, campo `package`, límite `50 MB`):
   - Valida que el `.zip` contenga exactamente `datos.enc`, `certificado.pem` y `manifest.json` (`400 Bad Request` si falta alguno).
   - Recalcula `SHA-256` de `datos.enc` y verifica la firma digital con `certificado.pem` (`422 Unprocessable Entity` si falla).
   - Guarda la solicitud en la tabla `IncomingRequests` con estado **`Pendiente`** y responde **`202 Accepted`**.

### 4.2 Modo de Envío, Aceptación y Consultas
* **Envío desde `Consultas`:** Cada cifrado realizado localmente en `Operar` se guarda en `Consultas` (SQLite). Al pulsar **`Enviar`**, un **panel lateral desplegable** solicita la `IP:Puerto` destino y transmite el `.zip` por HTTP `POST /api/requests/receive`.
* **Bandeja `Solicitudes`:** Al pulsar **`Aceptar`**, el paquete `.zip` y sus metadatos se insertan automáticamente en la base de datos de **`Consultas`** con origen **`Recibido`**. Al pulsar **`Rechazar`**, se descarta de `Consultas`.
* **Actualización Futura ("Pelota de Ping-Pong"):** La retransmisión automática encadenada entre múltiples nodos queda pospuesta para una actualización posterior cuando el grupo acuerde las reglas de salto.

---

## 5. Arquitectura del Proyecto en `Proyecto/` y Esquema de Base de Datos

### 5.1 Estructura de Directorios (`.NET 10`)
Cuando se autorice el inicio de la programación, la solución se construirá en `C:\Users\Administrator\Documents\GitHub\Centro de virlogia\Proyecto\`:

```text
Proyecto/
├── CentroCiberseguridad.sln
├── src/
│   └── CentroCiberseguridad.Web/
│       ├── CentroCiberseguridad.Web.csproj
│       ├── Program.cs                        # Arranque Kestrel (LAN), SQLite, Swagger/OpenAPI y DI
│       ├── Data/
│       │   ├── AppDbContext.cs               # Esquema SQLite y siembra inicial de los 21 motores
│       │   └── DatabaseInitializer.cs        # Migración automática y creación de CA/Nodo inicial
│       ├── Models/
│       │   ├── AlgorithmConfig.cs            # Id, Code, Name, Category, IsVisible, CanEncrypt, CanDecrypt
│       │   ├── CryptoRequest.cs              # Entrada de texto/archivo, algoritmo, llaves y parámetros
│       │   ├── CryptoResult.cs               # Salida cifrada/descifrada, métricas y pasos didácticos
│       │   │   ├── DigitalCertificateRecord.cs   # Identidad X.509 del nodo local
│       │   │   ├── SignedManifest.cs             # Esquema de manifest.json (propuesta.md)
│       │   │   ├── SavedPackageRecord.cs         # Registro en Consultas (Local / Recibido)
│       │   │   └── IncomingRequestRecord.cs      # Solicitudes entrantes (Pendiente / Aceptada / Rechazada)
│       │   ├── Services/
│       │   │   ├── Crypto/
│       │   │   │   ├── ICryptoAlgorithmEngine.cs # Contrato común (EncryptText, DecryptText, EncryptBytes, DecryptBytes, InspectSteps)
│       │   │   │   ├── CryptoEngineRegistry.cs   # Despachador que valida IsVisible / CanEncrypt / CanDecrypt en SQLite
│       │   │   │   ├── SymmetricEngines.cs       # AES, DES, 3DES/Triple-DES-96, ChaCha20-Poly1305
│       │   │   │   ├── AsymmetricEngines.cs      # RSA (OAEP/Didáctico), ECC (ECDH/ECIES), Diffie-Hellman
│       │   │   │   ├── ClassicAndAsmEngines.cs   # César, Vigenère, XOR Ensamblador (WREG/ROL/ROR), Lorenz
│       │   │   │   ├── MathAndAlgebraEngines.cs  # Euclides/Afín, Miller-Rabin, Fisher-Yates, DFT/IDFT, Lagrange Shamir GF(256)
│       │   │   │   ├── IntegrityEngines.cs       # Hash (SHA-2/SHA-3), HMAC, Firmas Digitales (RSA-PSS/ECDSA)
│       │   │   │   ├── SteganographyEngine.cs    # Esteganografía LSB en imágenes PNG/BMP (SixLabors.ImageSharp)
│       │   │   │   └── QuantumAndPqcEngines.cs   # Simulador QKD BB84 + PQC (Retículos LWE / ML-KEM / ML-DSA)
│       │   │   ├── Certificates/
│       │   │   │   └── CertificateAuthorityService.cs # Emisión X.509 v3 (.pem) y firma/validación de manifest.json
│       │   │   └── Transfer/
│       │       │   └── ZipTransferService.cs     # Empaquetado/validación .zip (3 archivos) y envío/recepción HTTP por IP
│       │   ├── Controllers/                      # Endpoints REST (Crypto, Config, Consultas, Requests)
│       │   └── wwwroot/                          # SPA Web minimalista (Oscuro dorado / Claro azul, estilo cifraronline)
│       │       ├── index.html
│       │       ├── css/styles.css
│       │       └── js/
│       │           ├── app.js
│       │           ├── operateView.js            # Tarjeta única con transición in-place (Texto / Archivo / LSB)
│       │           ├── inspectorView.js          # Inspector paso a paso y matrices/fotones
│       │           ├── consultasView.js          # Base de datos local + panel lateral desplegable Enviar .ZIP
│       │           ├── solicitudesView.js        # Bandeja de recepción (Aceptar / Rechazar)
│       │           └── settingsView.js           # Panel granular IsVisible / CanEncrypt / CanDecrypt + Ocultar Todos
└── tests/
    └── CentroCiberseguridad.Tests/          # Pruebas unitarias e integración de los 21 motores, ZIP y permisos
```

### 5.2 Tablas Principales en SQLite (`ciberseguridad.db`)
1. **`AlgorithmConfigs`**:
   - `Id` (PK), `Code` (unique, código corto oficial en MAYÚSCULAS ej. `AESGCM`), `DisplayName`, `Category`, `SupportsText`, `SupportsFile`, `IsVisible`, `CanEncrypt`, `CanDecrypt`, `UpdatedAtUtc`.
2. **`DigitalCertificates`**:
   - `Id` (PK), `SubjectName`, `ThumbprintSha256`, `SerialNumber`, `IsLocalNode`, `CertificatePem`, `PrivateKeyPfxBase64`, `NotBeforeUtc`, `NotAfterUtc`.
3. **`SavedPackages` (`Consultas`)**:
   - `Id` (PK), `ZipFileName` (`<NODO>_<ALGO>_<FECHA>_<SHA8>.zip`), `Origin` (`Local` / `Recibido`), `SourceIp`, `AlgorithmCode`, `AlgorithmName`, `EncryptedSha256`, `ZipBlobPathOrBytes`, `CreatedAtUtc`.
4. **`IncomingRequests` (`Solicitudes`)**:
   - `Id` (PK), `PacketId`, `SourceIp`, `ZipFileName`, `AlgorithmCode`, `SignatureValid`, `Status` (`Pendiente` / `Aceptada` / `Rechazada`), `ZipBlobPathOrBytes`, `ReceivedAtUtc`.
5. **`CryptoOperationsLog`**:
   - `Id` (PK), `AlgorithmCode`, `OperationType` (`Encrypt`/`Decrypt`), `InputKind` (`Text`/`File`/`LSB`), `InputSha256`, `OutputSha256`, `DurationMs`, `CreatedAtUtc`.

---

## 6. Diseño de Interfaz Web (Minimalista, Dual Theme y Estilo `cifraronline.com`)

Basada directamente en el prototipo validado en `prototipo/`:
* **Paleta sin mezcla amarillo + azul:**
  * **Modo Oscuro (defecto):** Fondo `#0E0E0E`, tarjeta `#161616`, chips `#242424`, botones sólidos `#FFFFFF`/`#111111` y acento dorado `#C5992E` / `#F0D9A0` (sin azul).
  * **Modo Claro:** Fondo `#F8F8F8`, tarjeta `#FFFFFF`, chips `#EFEFEF`, botones sólidos `#1A1A1A`/`#FFFFFF` y acento azul `#003882` / `#60A5FA` (sin amarillo/dorado).
* **5 Vistas en Barra Superior:**
  1. **`Operar`:** Tarjeta única centrada con transición *in-place* (Entrada → Salida), píldoras `Cifrar` / `Descifrar` y `Texto` / `Archivo` / `LSB`, selector de algoritmo filtrado por `IsVisible = true`, `Opciones` (`+ Certificado`, `Limpiar`) y guardado automático en `Consultas`.
  2. **`Inspector`:** Visualización en `Matriz`, `Hex` o `Binario` y pasos internos de la operación.
  3. **`Consultas`:** Tabla de cifrados `Local` y `Recibido` con buscador, descarga `.ZIP` y botón **`Enviar`** que abre un **panel lateral desplegable** para ingresar `IP:Puerto`.
  4. **`Solicitudes`:** Bandeja de recepción por IP con contador de pendientes y acciones **`Aceptar`** (inserta automáticamente en `Consultas`) y **`Rechazar`**.
  5. **`Ajustes`:** Buscador, botón `Ocultar Todos` y los 3 interruptores (`Visible`, `Cifrar`, `Descifrar`) para los 21 motores.

---

## 7. Plan de Ejecución por Etapas (Roadmap)

| Fase | Alcance y Entregables | Criterio de Terminación |
| :--- | :--- | :--- |
| **Fase 1: Base del Proyecto y SQLite** | Crear solución `.NET 10` en `Proyecto/`, configurar Kestrel en LAN (`0.0.0.0:5000`), inicializar `ciberseguridad.db` (5 tablas) y `CryptoEngineRegistry`. | Proyecto compila sin errores y expone `GET/PUT /api/config/algorithms` persistiendo `IsVisible`, `CanEncrypt` y `CanDecrypt` en SQLite. |
| **Fase 2: Motores Criptográficos (21 Módulos)** | Implementar `ICryptoAlgorithmEngine` y los 7 grupos de motores con códigos cortos oficiales (`AESGCM`..`LORENZSZ40`), soporte de texto/archivos/LSB e inspector. | Pruebas unitarias pasando al 100% en ida y vuelta para todos los motores. |
| **Fase 3: Empaquetado `.ZIP` y Certificados X.509** | Implementar emisión X.509 v3 (`.pem`), `manifest.json` firmado y empaquetador/validador `.zip` de 3 archivos con nomenclatura oficial. | Se genera `<NODO>_<ALGO>_<FECHA>_<SHA8>.zip` válido en Windows/7-Zip y se valida su firma + `SHA-256` (fallando ante alteración de 1 byte). |
| **Fase 4: Protocolo HTTP por IP (`Consultas` ↔ `Solicitudes`)** | Implementar `GET /api/status`, `POST /api/requests/receive` (`202`/`400`/`413`/`422`), cliente HTTP de envío y flujo `Aceptar` → `Consultas` / `Rechazar`. | Envío real de `.zip` por IP entre dos instancias/equipos y aprobación automática hacia `Consultas`. |
| **Fase 5: Interfaz Web Minimalista (`wwwroot/`)** | Migrar el prototipo validado (`index.html`, `styles.css`, JS modular) conectándolo a la API REST real de `.NET 10`. | Navegación fluida en modo oscuro/claro para las 5 vistas (`Operar`, `Inspector`, `Consultas` + panel lateral, `Solicitudes`, `Ajustes`). |
| **Fase 6: Pruebas Integrales y Apoyo al Informe** | Ejecutar `dotnet test`, validar intercambio `.zip` en LAN y generar evidencias/diagramas para el informe final IPN–UPIICSA. | Suite `dotnet test` 100% en verde y documentación lista en `Viro/`. |

---

## 8. Matriz de Trazabilidad hacia el Material de Apoyo e Informe Final

* **Guía del Proyecto:** Cumple con módulo de cifrado/descifrado multi-algoritmo (texto, archivos e imágenes), gestión de certificados digitales verificables por otros nodos, comunicación ping-pong entre células y uso homogéneo de `.NET / C#` + base de datos SQLite.
* **Material Teórico y Manual Didáctico (`Criptografia_Seguridad_Informatica (1).md`, `algoritmos_encriptacion.md`, `guia_algoritmos_criptografia.md`):** Cubre el 100% de los algoritmos y métodos documentados, incluyendo sus pasos matemáticos en el inspector interactivo.
* **Lineamientos del Informe (`lineamientos informe proyecto.md`):** La estructura modular de `Proyecto/` y este plan permiten extraer directamente los diagramas de bloques/procesos, fragmentos de código, resultados y evidencias requeridos para el reporte final de IPN–UPIICSA.
