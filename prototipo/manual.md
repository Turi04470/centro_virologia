# Manual de Uso — Prototipo Minimalista (`NODO-01`)

Este manual documenta todas las pantallas, botones, interruptores y parámetros de prueba del prototipo HTML ubicado en `prototipo/index.html`.  
La interfaz fue diseñada bajo un criterio estrictamente **minimalista** (sin párrafos extensos ni etiquetas recargadas en pantalla), concentrando aquí las instrucciones de operación.

---

## 1. Apertura, Tema y Paleta de Colores

1. **Cómo abrir el prototipo:** Haz doble clic en `prototipo/index.html` o ábrelo desde cualquier navegador web moderno (Edge, Chrome, Firefox). Funciona 100% en local sin servidores externos.
2. **Modo Oscuro / Modo Claro:** En la esquina superior derecha se encuentra el botón **Sol / Luna**. Alterna de forma instantánea entre el modo oscuro (predeterminado) y el modo claro, guardando tu preferencia en el navegador (`localStorage`).
3. **Paleta de Colores:**
   * **Modo Oscuro — Acento Dorado (`#C5992E` / `#F0D9A0`):** Marco sutil de la tarjeta principal, orbe de algoritmo e interruptores activos (sin azul).
   * **Modo Claro — Acento Azul (`#003882` / `#60A5FA`):** Marco sutil de la tarjeta principal, orbe de algoritmo e interruptores activos (sin amarillo/dorado).
   * **Neutros de Alto Contraste (`#0E0E0E` / `#161616` / `#FFFFFF` en oscuro y `#F8F8F8` / `#FFFFFF` / `#1A1A1A` en claro):** Botones tipo píldora sólidos en contraste blanco/carbón y tarjetas limpias estilo *cifraronline.com*.

---

## 2. Guía de las 5 Vistas de la Barra Superior

### 2.1 `Operar` (Cifrado, Descifrado y Esteganografía)
Es la pantalla principal centrada en una tarjeta única con transición *in-place* (el área de entrada se transforma en el panel de salida al ejecutar):

* **Selector de acción (`Cifrar` | `Descifrar`):** Define la operación del botón principal de la barra inferior. El botón principal **se deshabilita automáticamente** si la acción seleccionada está bloqueada en `Ajustes`.
* **Selector de entrada (`Texto` | `Archivo` | `LSB`):**
  * `Texto`: Área de texto sin bordes para cadenas UTF-8.
  * `Archivo`: Zona de carga/arrastre para cifrar o descifrar cualquier archivo binario.
  * `LSB`: Carga una imagen portadora (`PNG`/`BMP`), muestra su capacidad en bytes (`cap`) y habilita el campo `Dato oculto`.
* **Barra inferior de la tarjeta:**
  * **Píldora de algoritmo:** Solo lista los algoritmos con **`Visible`** activo en `Ajustes`.
  * **`Opciones`:** Despliega el panel compacto con `+ Certificado` (adjunta manifiesto JSON firmado + SHA-256) y `Limpiar`.
  * **Píldora `Clave / Parámetro` + `Clave`:** Ingresa o genera una llave aleatoria para el algoritmo activo.
  * **Botón principal (`Cifrar` / `Descifrar`):** Ejecuta la operación y muestra la salida en el mismo espacio con las acciones `Editar`, `Copiar`, `Descargar` (descarga `paquete.zip` con `datos.enc`, `certificado.pem` y `manifest.json` cuando `+ Certificado` está activo) y `Reiniciar`. Cada cifrado realizado se guarda automáticamente en `Consultas`.

---

### 2.2 `Inspector` (Visualización Matemática Paso a Paso)
Muestra el estado interno de la última operación ejecutada en `Operar`:

* **Selector (`Matriz` | `Hex` | `Binario`):** Cambia el formato de la cuadrícula de estado (`4×4`) entre valores hexadecimales compactos, notación `0xHH` o representación binaria de 8 bits.
* **Panel `Pasos`:** Lista numerada de las transformaciones realizadas (ej. módulo de Euclides, rondas, píxel modificado antes/después en LSB, polinomio en `GF(256)`, exponentes RSA/Diffie-Hellman o ruedas de Lorenz).

---

### 2.3 `Consultas` (Base de Datos Local y Panel Lateral de Envío)
Muestra todos los cifrados realizados localmente en `Operar` y los paquetes aceptados desde `Solicitudes`:

* **Filtros:** Buscador por archivo/algoritmo y píldoras de origen (`Todos` | `Local` | `Recibido`).
* **Acciones por registro:**
  * `.ZIP`: Descarga el paquete estandarizado con `datos.enc`, `certificado.pem` y `manifest.json`.
  * `Enviar`: Abre un **panel lateral desplegable** donde ingresas la `IP:Puerto` del nodo destino y confirmas el envío del `.zip`.

---

### 2.4 `Solicitudes` (Bandeja de Recepción `.ZIP` por IP)
Bandeja de recepción exclusiva para aprobar o rechazar paquetes `.zip` enviados por otros nodos:

* **Simular llegada:** Agrega una solicitud entrante de prueba desde otra IP para validar el flujo.
* **Acciones por solicitud:** Cada solicitud pendiente muestra `Origen IP`, archivo `.zip`, algoritmo, verificación X.509 y los botones **`Aceptar`** (incorpora el paquete automáticamente a `Consultas`) o **`Rechazar`** (descarta la solicitud).

---

### 2.5 `Ajustes` (Control Granular de los 21 Algoritmos)
Esta vista controla en tiempo real qué algoritmos están disponibles y qué acciones permiten. Todos los cambios se guardan automáticamente en `localStorage`.

* **Buscador (`Buscar...`):** Filtra al instante la tabla por nombre o categoría.
* **Acción rápida (`Ocultar Todos`):** Oculta por completo los 21 algoritmos de la vista `Operar`.
* **Los 3 interruptores por fila:**
  1. **`Visible`**: Si se apaga, el algoritmo **desaparece** del selector de `Operar`.
  2. **`Cifrar`**: Si se apaga, bloquea la acción `Cifrar` cuando ese algoritmo está seleccionado.
  3. **`Descifrar`**: Si se apaga, bloquea la acción `Descifrar` cuando ese algoritmo está seleccionado.

*(Nota: El módulo de red "Ping-Pong" entre nodos queda reservado para una actualización futura del sistema.)*

---

## 3. Referencia Rápida de Pruebas para los 21 Algoritmos

| # | Algoritmo | Clave / Parámetro sugerido | Notas de prueba rápida (`Cifrar` → `Descifrar`) |
| :---: | :--- | :--- | :--- |
| 1 | **AES-256-GCM** | `clave-aes-256-segura` | Cifra texto o archivo con etiqueta de autenticación; copiar salida y pulsar `Descifrar`. |
| 2 | **DES (56-bit)** | `claveDES` | Cifrado y descifrado simétrico reversible de texto o archivo. |
| 3 | **Triple DES / 3DES-96** | `clave-3des-96-ede` | Cifrado y descifrado simétrico reversible. |
| 4 | **ChaCha20-Poly1305** | `chacha20-llave-32bytes` | Flujo ARX reversible con verificación de etiqueta. |
| 5 | **RSA (OAEP / Modular)** | `p=257,q=263,e=3` | Usa aritmética modular `BigInt`; se recomienda `p*q > 255` y `MCD(e, φ(n)) = 1`. |
| 6 | **ECC (ECDH / ECIES)** | `ecc-p256-secp256r1` | Ida y vuelta simétrica derivada de curva elíptica. |
| 7 | **Diffie-Hellman** | `p=467,g=2,a=15,b=27` | Calcula `A`, `B` y secreto compartido `K` visible en `Inspector`. |
| 8 | **Cifrado César** | `3` | Desplaza letras (`mod 26`) en texto y bytes (`mod 256`) en archivos. |
| 9 | **Cifrado Vigenère** | `SOL` | Sustitución polialfabética con palabra clave. |
| 10 | **XOR Ensamblador** | `0x5A,ROL=1` | Aplica `XOR` por byte seguido de rotación `ROL` (o `ROR` al descifrar). |
| 11 | **Esteganografía LSB** | `1-bit-RGB` | Selecciona `Imagen LSB`, carga una imagen PNG/BMP, escribe en `Dato oculto` y pulsa `Cifrar`; descarga `estego.png`, vuelve a cargarla y pulsa `Descifrar`. |
| 12 | **Euclides Extendido (Afín)** | `a=5,b=11` | `a` debe ser impar (coprimo con `256`); el sistema calcula `a^-1 mod 256` al descifrar. |
| 13 | **Miller–Rabin** | `n=1009,rondas=5` | Evalúa primalidad de `n` y muestra el veredicto en `Inspector`. |
| 14 | **Permutación Fisher–Yates** | `semilla-2026` | Reordena los bytes con permutación determinista e invierte exactamente al descifrar. |
| 15 | **Hash SHA-256** | `sha256` *(o hash esperado)* | `Cifrar` calcula el digest; para verificar con `Descifrar`, pega el hash esperado en `Clave`. |
| 16 | **HMAC-SHA256** | `secreto-hmac` | `Cifrar` genera `tag|base64`; `Descifrar` valida la etiqueta con la misma clave. |
| 17 | **Firma Digital** | `NODO-01-PRIV` | `Cifrar` emite envoltorio JSON firmado; `Descifrar` verifica integridad y firma. |
| 18 | **Cuántica BB84 + PQC** | `bb84-eve=0` | Cifrado y descifrado con clave derivada del protocolo cuántico/poscuántico. |
| 19 | **Transformada DFT / IDFT** | `fase-42` | En textos cortos (`<= 120` chars) transforma al espectro de frecuencias y reconstruye por IDFT. |
| 20 | **Lagrange (Shamir GF256)** | `N=5,K=3` | `Cifrar` genera 5 líneas (`1:...` a `5:...`); conserva al menos 3 líneas y pulsa `Descifrar` para reconstruir el mensaje original. |
| 21 | **Máquina Lorenz (SZ40)** | `chi=13,psi=29` | Cifrado de flujo autoinverso de 12 ruedas. |
