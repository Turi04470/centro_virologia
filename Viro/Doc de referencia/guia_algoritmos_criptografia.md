Manual didáctico · edición octubre de 2026

# Guía de algoritmos de cifrado y conceptos criptográficos

Una introducción extensa y práctica con analogías Feynman, procedimientos paso a paso, ejemplos pequeños y orientación sobre usos actuales. Pensada para estudiar y experimentar en entornos propios, no como sustituto de estándares ni auditorías de seguridad.

Imprimir / Guardar como PDF

**Alcance y honestidad técnica.** No es posible documentar literalmente todos los algoritmos existentes en un solo archivo: existen familias, variantes, protocolos y diseños académicos nuevos. Esta guía cubre los métodos solicitados y una selección representativa de los más importantes. Los ejemplos manuales son pedagógicos y usan claves diminutas; **no son seguros para proteger información real**. En sistemas reales se usan bibliotecas revisadas y protocolos completos.

## Contenido

1. [Conceptos básicos](#bases)
2. [Mapa rápido: qué es cada cosa](#clasificacion)
3. [César y Vigenère](#cesar)
4. [AES y claves de ronda](#aes)
5. [DES, Triple DES y “Triple-DES-96”](#des)
6. [ChaCha20-Poly1305](#chacha)
7. [RSA](#rsa)
8. [Criptografía de curva elíptica](#ecc)
9. [Algoritmo de Euclides y Euclides extendido](#euclides)
10. [Miller–Rabin](#miller)
11. [Generación de permutaciones](#permutaciones)
12. [Funciones hash y HMAC](#hash)
13. [Firmas digitales](#firmas)
14. [Esteganografía](#estego)
15. [Criptografía cuántica y poscuántica](#cuantica)
16. [Transformada discreta de Fourier](#dft)
17. [Teorema de Lagrange](#lagrange)
18. [“Teorema de Lorenz” / cifrado Lorenz](#lorenz)
19. [Algoritmos en ensamblador](#asm)
20. [Cómo elegir hoy](#practica)
21. [Fuentes técnicas](#fuentes)

## 1. Conceptos básicos (Feynman)

**Analogía:** cifrar es guardar un mensaje dentro de una caja cerrada. El algoritmo describe la cerradura y la llave es el secreto que permite abrirla.

* **Texto claro:** el mensaje antes del cifrado.
* **Cifrado:** transformación que usa una clave para producir texto cifrado.
* **Descifrado:** proceso inverso autorizado.
* **Cifrado simétrico:** emisor y receptor comparten una clave secreta; suele ser rápido para grandes volúmenes.
* **Criptografía asimétrica:** usa un par de claves relacionadas, normalmente pública y privada; sirve para acordar claves o firmar, y algunos esquemas también cifran.
* **Hash:** huella de longitud fija; no se “descifra”.
* **Firma digital:** ayuda a verificar origen e integridad, pero no oculta el contenido.
* **Nonce/IV:** valor que ciertos modos requieren para que cifrar mensajes iguales no produzca siempre el mismo resultado. Debe respetarse la regla específica del algoritmo.
* **Autenticación:** detecta modificaciones y, según el protocolo, ayuda a confirmar quién envió el dato.

Un algoritmo aislado no constituye necesariamente un sistema seguro: importan el modo, el formato, la generación y protección de claves, la aleatoriedad, la implementación y la gestión de errores.

## 2. Mapa rápido: categorías correctas

| Elemento | Qué es realmente | Uso típico |
| --- | --- | --- |
| AES, DES, 3DES, ChaCha20 | Cifradores simétricos | Proteger datos con una clave secreta |
| RSA-OAEP | Esquema asimétrico de cifrado | Cifrar claves pequeñas o secretos de sesión, no archivos grandes |
| ECDH, ML-KEM | Acuerdo/encapsulación de claves | Establecer un secreto compartido |
| ECDSA, EdDSA, RSA-PSS, ML-DSA, SLH-DSA | Firmas digitales | Autenticidad e integridad |
| César, Vigenère | Cifrados clásicos de sustitución | Aprendizaje histórico; inseguros hoy |
| Euclides, Miller–Rabin, permutaciones | Herramientas matemáticas/computacionales | Calcular inversos, probar primalidad, mezclar elementos |
| Esteganografía | Ocultación de la existencia del mensaje | Insertar datos en imágenes, audio u otros medios |
| DFT, teorema de Lagrange | Herramientas matemáticas generales | Señales o razonamiento algebraico; no son cifradores por sí solos |
| Criptografía cuántica/poscuántica | Áreas y familias distintas | Distribuir claves con fenómenos cuánticos / resistir ataques cuánticos |

## 3. Cifrado César

**Qué es:** cada letra se desplaza un número fijo de posiciones del alfabeto. **Analogía Feynman:** todos los caracteres avanzan la misma cantidad de casillas en una rueda.

**Sirve/cuándo:** ejercicios didácticos y rompecabezas. No debe usarse para datos reales: solo hay unas pocas claves posibles y se rompe por fuerza bruta o análisis de frecuencias.

### Paso a paso

1. Asigna números a las letras: A=0, B=1, …, Z=25.
2. Elige un desplazamiento k; para este ejemplo, k=3.
3. Para cada letra calcula `C=(P+k) mod 26`.
4. Para descifrar calcula `P=(C-k) mod 26`.

**Ejemplo resuelto:** “HOLA” con k=3 se convierte en “KROD”: H→K, O→R, L→O, A→D. Al restar 3 se recupera HOLA. El ejemplo omite espacios y tildes.

**Aplicaciones reales actuales:** enseñanza, juegos y acertijos; no es un control de seguridad.

## 4. Cifrado Vigenère

**Qué es:** un cifrado clásico que aplica desplazamientos distintos según una palabra clave. **Analogía:** en lugar de mover todas las letras tres casillas, cada posición tiene su propio número de casillas.

**Sirve/cuándo:** estudio histórico de criptografía. Una clave repetida y corta deja patrones y puede atacarse; no protege comunicaciones modernas.

### Paso a paso

1. Convierte letras a números A=0…Z=25.
2. Repite la clave hasta cubrir el mensaje.
3. Suma el valor de la letra del mensaje y el de la clave, módulo 26.
4. Para descifrar resta el valor de la clave, módulo 26.

**Ejemplo:** texto “ATAQUE”, clave “SOLSOL”. A(0)+S(18)=S(18); T(19)+O(14)=H(7) tras módulo 26; A+L=L; Q+S=I; U+O=I; E+L=P. Resultado: “SHLIIP”. Para descifrar se resta la clave y se recupera “ATAQUE”.

**Uso actual:** educativo, análisis histórico y retos de criptogramas; no usar para contraseñas, archivos ni redes.

## 5. AES (Advanced Encryption Standard) y claves de ronda

**Qué es:** cifrador simétrico por bloques de 128 bits con claves de 128, 192 o 256 bits. **Analogía:** un bloque de datos pasa por varias estaciones de transformación; en cada ronda se combina con una subclave derivada de la clave principal.

**Para qué/cuándo:** cifrado de datos, discos, bases de datos, conexiones y protocolos; se utiliza mediante modos seguros como AES-GCM o AES-CCM, no improvisando un modo propio. AES-GCM aporta cifrado y autenticación.

### Proceso conceptual de AES

1. Representar los 16 bytes del bloque como una matriz 4×4 (estado).
2. Expandir la clave principal para producir claves de ronda (key schedule).
3. Aplicar una ronda inicial: AddRoundKey, que combina el estado con la subclave mediante XOR.
4. En cada ronda normal: SubBytes (sustitución no lineal), ShiftRows (desplazamiento de filas), MixColumns (mezcla de columnas) y AddRoundKey.
5. En la última ronda se omite MixColumns.
6. El descifrado aplica transformaciones inversas y las subclaves en el orden correspondiente.

**Claves de ronda:** no son contraseñas independientes. Son subclaves calculadas desde la clave original. AES-128 tiene 10 rondas, AES-192 tiene 12 y AES-256 tiene 14.

**Ejemplo realista:** una aplicación cifra un archivo con AES-GCM usando una clave aleatoria de 256 bits y un nonce único. Guarda el nonce y la etiqueta de autenticación junto al texto cifrado; el secreto es la clave, no el nonce. Si alguien modifica el archivo, la verificación de autenticación debe fallar. No se incluye una salida hexadecimal manual porque depende de la clave, nonce, datos y etiqueta exactos.

**Precaución:** nunca reutilices un nonce con la misma clave en AES-GCM. Para sistemas reales, usa una biblioteca consolidada y una API de alto nivel.

## 6. DES, Triple DES y “Triple-DES-96”

### DES

**Qué es:** cifrador de bloques de 64 bits con clave efectiva de 56 bits. **Analogía:** 16 rondas de dividir, mezclar y volver a combinar los datos con subclaves. **Estado:** obsoleto; NIST retiró el estándar porque ya no ofrece seguridad suficiente.

1. Aplicar la permutación inicial al bloque de 64 bits.
2. Separar en mitades izquierda y derecha de 32 bits.
3. Repetir 16 rondas: expandir la mitad derecha, combinar con una subclave, sustituir mediante cajas S y permutar; luego combinar con la mitad izquierda.
4. Intercambiar mitades y aplicar la permutación final.
5. Para descifrar, repetir con las subclaves en orden inverso.

**Ejemplo:** DES puede estudiarse con vectores de prueba publicados y herramientas educativas, pero no se recomienda inventar una clave “de ejemplo” como si fuese segura. Una clave de 56 bits puede probarse exhaustivamente con recursos modernos especializados.

### Triple DES (3DES/TDEA)

Aplica DES tres veces, normalmente en secuencia cifrar–descifrar–cifrar (EDE), usando dos o tres claves. Fue una transición histórica cuando DES dejó de ser suficiente. NIST retiró su especificación desde el 1 de enero de 2024 para aplicar protección criptográfica nueva; su uso se limita a procesar datos heredados en los contextos permitidos.

1. Dividir los datos en bloques de 64 bits.
2. Aplicar DES con K1.
3. Aplicar DES inverso con K2.
4. Aplicar DES con K3 (o K1 en la variante de dos claves).
5. Para descifrar, invertir la secuencia y las operaciones.

**Ejemplo:** un sistema bancario heredado podría necesitar descifrar registros antiguos protegidos con TDEA. La migración recomendada es descifrar dentro del entorno controlado y volver a cifrar con un esquema moderno validado; no crear nuevos datos protegidos con 3DES.

### ¿Qué significa Triple-DES-96?

“Triple-DES-96” no es una denominación estándar inequívoca en los estándares NIST consultados. Puede ser una etiqueta de una implementación, un formato de clave o una referencia a una variante específica. No debe asumirse que significa “96 bits de seguridad”. Para describirlo correctamente se necesita la fuente, el producto o la especificación exacta. En cualquier caso, las variantes basadas en DES/3DES no son una elección apropiada para nueva protección.

## 7. ChaCha20-Poly1305

**Qué es:** construcción moderna de cifrado autenticado: ChaCha20 genera un flujo de bytes para cifrar y Poly1305 verifica integridad/autenticidad. **Analogía:** una máquina mezcla la clave con un contador y un nonce para producir una máscara; un sello criptográfico detecta alteraciones.

**Uso:** protocolos de red y software, especialmente donde las instrucciones AES especializadas no están disponibles. Debe usarse como construcción completa, por ejemplo a través de una API estándar.

1. Generar una clave secreta de 256 bits y un nonce conforme al protocolo.
2. Combinar clave, nonce y contador en el estado de ChaCha20.
3. Ejecutar sus rondas de suma modular, XOR y rotaciones para generar bloques de flujo.
4. Hacer XOR del flujo con el texto claro para producir el texto cifrado.
5. Calcular una etiqueta Poly1305 sobre el contenido autenticado según la especificación.
6. Al descifrar, verificar la etiqueta antes de aceptar los datos como auténticos.

**Ejemplo:** una conexión segura cifra “transferencia=100” con ChaCha20-Poly1305. El receptor necesita la clave, el nonce, el texto cifrado y la etiqueta; si un atacante cambia “100” por “900”, la autenticación falla.

**Precaución:** no reutilizar el nonce con la misma clave. Preferir APIs de alto nivel.

## 8. RSA

**Qué es:** familia de criptografía de clave pública basada en operaciones modulares y la dificultad práctica de factorizar ciertos enteros grandes. **Analogía:** cualquiera puede cerrar una caja con el candado público, pero solo quien tiene la clave privada puede abrirla.

**Uso:** esquemas como RSA-OAEP para cifrar pequeños secretos y RSA-PSS para firmas. En sistemas modernos suele cifrarse una clave de sesión con un mecanismo asimétrico y usar un cifrador simétrico para los datos grandes.

### Generación de claves simplificada

1. Elegir dos primos grandes distintos p y q.
2. Calcular n=p×q y φ(n)=(p−1)(q−1).
3. Elegir e coprimo con φ(n), comúnmente 65537.
4. Calcular d, el inverso multiplicativo de e módulo φ(n), es decir e×d≡1 mod φ(n).
5. La clave pública es (n,e); la privada incluye d y material secreto asociado.
6. Para el esquema matemático básico, cifrar c=m^e mod n y descifrar m=c^d mod n. En uso real hay que aplicar un esquema de codificación seguro como OAEP; el RSA “crudo” no es seguro.

**Ejemplo didáctico diminuto:** p=5, q=11; n=55 y φ=40. Elige e=3 y d=27, pues 3×27=81≡1 (mod 40). Si m=7, c=7³ mod 55=13; al calcular 13²⁷ mod 55 se recupera 7. Estos números son diminutos y se rompen de inmediato: solo ilustran la aritmética, no una configuración real.

**Aplicaciones actuales:** certificados, firmas y compatibilidad con sistemas existentes. RSA requiere tamaños de clave y padding apropiados; no usar el ejemplo simple en producción.

## 9. Criptografía de curva elíptica (ECC)

**Qué es:** familia de técnicas basadas en puntos de curvas sobre campos finitos. No es un único algoritmo. Incluye ECDH (acuerdo de claves), ECDSA y EdDSA (firmas). **Analogía:** es fácil avanzar muchas veces en una ruta matemática, pero difícil deducir cuántos pasos se dieron al ver solo el punto final.

**Uso:** intercambio de claves y firmas en TLS, dispositivos y sistemas móviles; depende del protocolo y de curvas aprobadas. ECC no significa automáticamente “cifrar un archivo”.

1. Escoger una curva, parámetros y un punto base G válidos.
2. La persona A elige un secreto a y publica A=aG.
3. La persona B elige un secreto b y publica B=bG.
4. A calcula aB=abG; B calcula bA=baG. Obtienen el mismo punto/secreto compartido.
5. Derivar de ese secreto una clave simétrica con una función de derivación de claves.
6. Usar esa clave con un cifrador autenticado para los datos.

**Ejemplo:** un cliente y un servidor acuerdan una clave de sesión mediante ECDH efímero durante una conexión TLS y luego cifran el tráfico con un cifrador simétrico. El punto público no revela directamente el secreto privado si se usan parámetros y una implementación segura.

**Importante:** el acuerdo de claves debe autenticarse para evitar ataques de intermediario. La criptografía de curva elíptica clásica no es resistente a un computador cuántico criptográficamente relevante.

## 10. Algoritmo de Euclides y Euclides extendido

**Qué es:** procedimiento para hallar el máximo común divisor (MCD); la versión extendida también encuentra x,y tales que ax+by=MCD(a,b). No cifra datos, pero el inverso modular que ayuda a calcular es esencial en RSA.

**Analogía:** para saber qué tamaño de pieza divide exactamente dos longitudes, se repite la división usando el residuo.

1. Divide a entre b y conserva el residuo r.
2. Reemplaza (a,b) por (b,r).
3. Repite hasta que el residuo sea cero; el último divisor distinto de cero es el MCD.
4. En la versión extendida, retrocede sustituyendo residuos para expresar el MCD como combinación de a y b.
5. Si MCD(a,m)=1, el coeficiente de a da su inverso módulo m (reducido módulo m).

**Ejemplo:** MCD(30,18): 30=1×18+12; 18=1×12+6; 12=2×6+0. Por tanto MCD=6. Para el inverso de 3 módulo 40, 3×27=81=2×40+1, así que el inverso es 27. Esto permite calcular d en el ejemplo RSA.

**Aplicación real:** cálculo de inversos modulares en generación de claves y aritmética de números enteros.

## 11. Prueba de primalidad Miller–Rabin

**Qué es:** prueba probabilística rápida para comprobar si un entero es probablemente primo. No cifra ni genera claves por sí sola, pero ayuda a seleccionar primos para RSA. **Analogía:** una serie de pruebas busca testigos que demuestren que un número es compuesto.

1. Para n impar mayor que 2, escribe n−1 como d×2ˢ, con d impar.
2. Elige una base a entre 2 y n−2.
3. Calcula x=a^d mod n.
4. Si x=1 o n−1, esta ronda pasa.
5. Si no, eleva x al cuadrado repetidamente hasta s−1 veces; si aparece n−1, la ronda pasa.
6. Si no aparece, n es compuesto. Si pasa varias bases, es “probablemente primo”; la confianza depende de bases y protocolo.

**Ejemplo:** n=13; n−1=12=3×2². Con base a=2, 2³ mod 13=8. Como 8 no es 1 ni 12, se eleva al cuadrado: 8² mod 13=12, por lo que la ronda pasa. Varias rondas reducen mucho la probabilidad de aceptar un compuesto, pero la generación real debe seguir una biblioteca y un estándar.

**Uso:** generación de primos en criptografía de clave pública. No confiar en una sola ronda arbitraria para un sistema crítico.

## 12. Generación de permutaciones

**Qué es:** producir reordenamientos de elementos. No es, por sí misma, criptografía segura. Algunas cifras antiguas usan permutaciones para reordenar bits; un generador de permutaciones aleatorias también aparece en pruebas y simulaciones.

**Analogía:** barajar cartas: los elementos no cambian, solo sus posiciones.

1. Crear una lista de elementos.
2. Para una permutación uniforme, recorrer desde el último elemento hacia el segundo.
3. En la posición i, elegir j uniformemente entre 0 e i.
4. Intercambiar los elementos i y j.
5. Si se necesita reproducibilidad, registrar la semilla; si la permutación tiene función de seguridad, usar un generador criptográficamente seguro y un diseño adecuado.

**Ejemplo:** lista [A,B,C,D]. Si las elecciones son j=1 para i=3, j=0 para i=2 y j=1 para i=1, el resultado depende de los intercambios concretos. El algoritmo de Fisher–Yates produce permutaciones uniformes cuando las elecciones son uniformes e independientes.

**Aplicaciones:** barajado, pruebas, protocolos especializados y algunas transformaciones internas. Una permutación secreta aislada no sustituye a un cifrador moderno.

## 13. Funciones hash y HMAC

### Hash criptográfico (SHA-256, SHA-3)

Una función hash convierte datos de cualquier longitud en una huella de tamaño fijo. No es cifrado reversible. Se usa para verificar integridad, construir firmas y otros protocolos. Para contraseñas deben usarse funciones específicas de derivación lentas como Argon2id, scrypt o PBKDF2, con sal y parámetros adecuados; no basta con SHA-256 simple.

1. Tomar el mensaje.
2. Procesarlo según la construcción hash en bloques o permutaciones internas.
3. Obtener una huella de tamaño fijo.
4. Recalcular el hash del archivo recibido y comparar las huellas si se dispone de un valor confiable.

**Ejemplo:** un sitio publica el SHA-256 de un instalador. Tras descargarlo, el usuario calcula su hash local y lo compara. Si coincide, es evidencia de integridad frente a ese valor publicado, pero solo autentica el origen si el valor publicado también es confiable.

### HMAC

HMAC combina una función hash con una clave secreta para autenticar mensajes. **Pasos:** elegir clave compartida; calcular la construcción HMAC definida sobre mensaje y clave; enviar mensaje y etiqueta; el receptor recalcula y compara de forma segura. **Ejemplo:** dos servicios usan HMAC-SHA-256 para detectar si una solicitud fue alterada y comprobar que quien la generó conoce la clave. HMAC no cifra el contenido.

## 14. Firmas digitales

**Qué son:** mecanismo criptográfico para verificar integridad y vincular un mensaje a una clave privada. No ocultan el mensaje. Familias actuales incluyen RSA-PSS, ECDSA y EdDSA; NIST también estandarizó firmas poscuánticas ML-DSA y SLH-DSA.

1. El firmante genera o dispone de un par de claves válido.
2. Calcula una firma sobre el mensaje o su hash usando el algoritmo y formato especificados.
3. Envía el mensaje, la firma y la información pública/certificado pertinente.
4. El receptor verifica la firma con la clave pública y valida por separado la identidad/certificado y el contexto.

**Ejemplo:** una actualización de software se firma con la clave privada del fabricante. El dispositivo verifica la firma con una clave pública de confianza antes de instalarla. La firma ayuda a detectar una actualización modificada; no cifra el archivo.

## 15. Esteganografía

**Qué es:** ocultar que existe un mensaje dentro de otro medio, como imagen, audio o texto. No es necesariamente cifrado: si alguien descubre el mensaje oculto, podría leerlo.

**Analogía:** escribir una nota invisible dentro de una carta; el cifrado sería además escribir la nota en un código que solo el destinatario entiende.

1. Elegir un medio portador y un método de inserción.
2. Preparar el mensaje; si requiere confidencialidad, cifrarlo primero.
3. Insertar los datos en posiciones o características permitidas por el método.
4. Compartir el medio sin alterar las características que permiten recuperar el mensaje.
5. El receptor aplica el procedimiento inverso y, si hay cifrado, descifra el contenido.

**Ejemplo didáctico:** en una imagen sin compresión, un programa puede codificar bits en el bit menos significativo de ciertos píxeles. Cambios de formato, redimensionado o compresión con pérdida pueden destruir el mensaje y los patrones pueden detectarse por análisis estadístico.

**Usos reales:** marcas de agua, autenticación de contenido y estudios forenses; también puede abusarse para ocultar datos. No es una garantía de confidencialidad ni de anonimato.

## 16. Criptografía cuántica y poscuántica

### Criptografía cuántica

Usa propiedades de sistemas cuánticos; el ejemplo más conocido es la distribución cuántica de claves (QKD). No es un “cifrado cuántico universal”: ayuda a establecer claves bajo supuestos físicos y requiere autenticación clásica, equipos especializados y un canal cuántico.

1. Dos participantes transmiten estados cuánticos según un protocolo, por ejemplo con bases elegidas al azar.
2. Comparan públicamente una parte de sus elecciones de base, no todos los valores secretos.
3. Estiman errores para detectar posible intervención o ruido excesivo.
4. Aplican reconciliación de información y amplificación de privacidad para derivar una clave compartida.
5. Usan la clave con un cifrador clásico autenticado.

**Ejemplo:** una infraestructura especializada usa QKD para generar una clave compartida y luego AES-GCM cifra el tráfico. QKD no sustituye por sí sola a la autenticación, al cifrado del tráfico ni a la seguridad de los dispositivos.

### Criptografía poscuántica (PQC)

Son algoritmos clásicos diseñados para resistir ataques de computadores cuánticos. No requieren hardware cuántico. En agosto de 2024 NIST publicó FIPS 203 (ML-KEM, establecimiento de claves), FIPS 204 (ML-DSA, firmas) y FIPS 205 (SLH-DSA, firmas basadas en hash).

1. Identificar dónde se usan actualmente RSA, Diffie–Hellman o ECC.
2. Seleccionar un estándar poscuántico adecuado para el propósito (KEM para establecer secreto; firma para autenticidad).
3. Integrarlo en un protocolo compatible y mantener autenticación, gestión de claves y actualización.
4. Probar interoperabilidad, rendimiento y recuperación antes de migrar.

**Ejemplo:** un sistema nuevo puede establecer una clave de sesión mediante ML-KEM y cifrar los datos con un cifrador simétrico autenticado. ML-KEM no cifra directamente un vídeo completo: establece un secreto del que se deriva la clave de cifrado.

## 17. Transformada discreta de Fourier (DFT)

**Qué es:** herramienta matemática para expresar una secuencia como combinación de frecuencias. No es un algoritmo de cifrado. Puede aparecer en procesamiento de señales, compresión, análisis y algunos esquemas especializados, pero no proporciona confidencialidad por sí sola.

**Analogía:** separar el sonido de una canción en las notas/frecuencias que lo componen.

1. Tomar N muestras de una señal x[n].
2. Para cada frecuencia k, calcular la suma ponderada por factores complejos exponenciales.
3. El resultado X[k] describe la contribución de esa frecuencia.
4. La transformada inversa permite reconstruir la secuencia con las condiciones matemáticas apropiadas.

**Ejemplo:** analizar muestras de audio para detectar un tono de 440 Hz. Eso es análisis de señal, no cifrado. Si una aplicación transforma una imagen mediante Fourier, la transformación sigue siendo reversible y no debe tratarse como protección criptográfica.

## 18. Teorema de Lagrange

El nombre puede referirse a varios resultados. En teoría de grupos, el teorema de Lagrange dice que el orden de un subgrupo finito divide el orden del grupo. No es un cifrador, pero el álgebra de grupos es parte del contexto matemático de varios sistemas criptográficos.

**Analogía:** si un grupo finito se puede dividir en copias iguales de un subgrupo, el número de elementos de cada copia debe encajar exactamente en el total.

1. Identificar el grupo finito G y su número de elementos |G|.
2. Identificar un subgrupo H y contar sus elementos |H|.
3. Las clases laterales de H particionan G en conjuntos del mismo tamaño.
4. Por tanto, |H| divide a |G|.

**Ejemplo:** en el grupo de enteros módulo 6 bajo la suma, el subgrupo {0,2,4} tiene 3 elementos y el grupo total tiene 6; 3 divide 6. Esto ilustra una propiedad algebraica, no cifra un mensaje.

**Si se refería al teorema de interpolación de Lagrange:** ese resultado construye un polinomio que pasa por puntos dados y se utiliza, por ejemplo, en el esquema de compartición de secretos de Shamir. En Shamir, cada participante recibe un punto y se necesitan suficientes puntos para reconstruir el secreto mediante interpolación. Ejemplo: un secreto se codifica como el término constante de un polinomio y se recupera al reunir el umbral requerido de participaciones.

## 19. “Teorema de Lorenz” y cifrado Lorenz

**Aclaración:** “teorema de Lorenz” no identifica un algoritmo de cifrado estándar ampliamente reconocido. Puede ser una confusión con la máquina de cifrado Lorenz, usada históricamente en comunicaciones alemanas durante la Segunda Guerra Mundial, o con conceptos matemáticos ajenos a la criptografía.

**Máquina Lorenz:** sistema electromecánico de flujo que combinaba el texto con una secuencia pseudoaleatoria producida por ruedas. A diferencia de César o Vigenère, no se manejaba como una simple sustitución de letras fija.

1. Representar caracteres mediante un código telegráfico de cinco bits.
2. Las ruedas generan patrones de bits que cambian con cada carácter.
3. Combinar el texto con el flujo de clave, históricamente mediante XOR/suma módulo 2.
4. El receptor, con una configuración idéntica y sincronizada, genera el mismo flujo y lo combina otra vez para recuperar el texto.
5. La seguridad depende de la configuración, sincronización y secreto del flujo; reutilizar o predecir patrones puede permitir criptoanálisis.

**Ejemplo conceptual:** si un bit del texto es 1 y el bit de clave es 1, XOR produce 0; al aplicar XOR otra vez con el mismo bit de clave se recupera 1. Esto ilustra el principio de flujo, no reproduce una configuración histórica completa de Lorenz.

**Aplicaciones actuales:** historia de la criptografía y análisis de cifrados. No se usa la máquina histórica para proteger comunicaciones modernas. Si “teorema de Lorenz” alude a otro resultado, hace falta el nombre de la fuente o la fórmula para identificarlo sin inventar contenido.

## 20. ¿Existen algoritmos de cifrado para lenguaje ensamblador?

**Respuesta corta:** no existe una categoría criptográfica separada llamada “cifrado para ensamblador”. Los algoritmos se definen matemáticamente y pueden implementarse en C, Rust, Java, Python, ensamblador u otro lenguaje. El ensamblador permite controlar instrucciones y registros con precisión, pero también aumenta el riesgo de errores y de filtraciones por canales laterales.

**Aplicaciones reales:** bibliotecas criptográficas optimizadas pueden usar ensamblador para aprovechar instrucciones de CPU como AES-NI o extensiones vectoriales. La selección depende de la arquitectura (x86-64, ARM, etc.), las capacidades disponibles y la biblioteca.

### Proceso de implementación (visión segura)

1. Elegir un estándar bien definido (por ejemplo AES-GCM), no inventar una cifra.
2. Seleccionar una biblioteca mantenida que ya incluya optimizaciones para la arquitectura.
3. Usar su API de alto nivel para generar claves, nonces y etiquetas de manera correcta.
4. Compilar y verificar que la biblioteca usa una ruta optimizada compatible; no asumirlo sin medición o documentación.
5. Probar vectores oficiales, manejo de errores y casos límite; evaluar canales laterales si el riesgo lo requiere.

**Ejemplo real:** un programa de almacenamiento cifra archivos mediante la API de una biblioteca criptográfica. La biblioteca puede ejecutar AES con instrucciones especializadas del procesador o una implementación alternativa. El programa consumidor no necesita escribir manualmente las rondas AES en ensamblador.

**Nota:** el código ensamblador de un cifrador completo sería extenso y dependiente de CPU; para uso real, copiar código criptográfico sin revisión es peligroso.

## 21. Qué elegir en proyectos actuales

| Necesidad | Orientación general | Evitar |
| --- | --- | --- |
| Cifrar archivos o datos en reposo | Cifrador autenticado de una biblioteca confiable; AES-GCM o XChaCha20-Poly1305 donde esté soportado | Diseñar un modo propio, ECB, claves incrustadas |
| Proteger comunicaciones | Protocolos mantenidos como TLS configurado correctamente | Implementar criptografía a mano |
| Intercambiar una clave | Esquemas de acuerdo/KEM adecuados al protocolo; plan de migración poscuántica cuando corresponda | Usar RSA crudo o confundir firma con cifrado |
| Firmar software/documentos | Firma digital estándar y gestión confiable de certificados/claves | Tratar un hash simple como firma |
| Almacenar contraseñas | Argon2id u otra función de derivación apropiada con sal y parámetros robustos | Guardar contraseñas en claro o usar cifrado reversible como sustituto del hashing de contraseñas |
| Aprender conceptos | César, Vigenère, DES en entorno de laboratorio, ejemplos matemáticos pequeños | Usarlos para datos reales |

**Regla de oro:** no inventes tu propio algoritmo ni copies ejemplos educativos para proteger información sensible. Usa implementaciones mantenidas, claves aleatorias, nonces únicos según el esquema, autenticación y un protocolo revisado.

## 22. Fuentes técnicas y lecturas recomendadas

* [NIST FIPS 197 — Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final): definición oficial de AES y tamaños de clave.
* [NIST — retiro de DES](https://csrc.nist.gov/News/2005/Withdrawal-of-FIPS-46-3-FIPS-74-and-FIPS-81): explicación de por qué DES ya no ofrece seguridad suficiente.
* [NIST — retiro de TDEA/Triple DES](https://www.nist.gov/news-events/news/2023/06/nist-withdraw-special-publication-800-67-revision-2): cronología y límites para protección nueva.
* [RFC 8017 — PKCS #1: RSA Cryptography Specifications](https://www.rfc-editor.org/rfc/rfc8017.html): RSA, OAEP, firmas y codificación.
* [NIST — Elliptic Curve Cryptography](https://csrc.nist.gov/Projects/Elliptic-Curve-Cryptography): ECC, firmas y acuerdo de claves.
* [NIST — estándares poscuánticos FIPS 203, 204 y 205](https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved): ML-KEM, ML-DSA y SLH-DSA.
* [NIST — proyecto de criptografía poscuántica](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography): estándares y orientación de migración.

Esta guía es educativa y no constituye una certificación de seguridad, recomendación legal ni especificación de implementación. Las recomendaciones y estándares pueden evolucionar; revisa siempre la versión vigente de las fuentes oficiales.

Guía didáctica de criptografía · Español · Hecha para lectura local en navegador