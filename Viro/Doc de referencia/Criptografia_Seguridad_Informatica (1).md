2.1.2 Criptografía en el Ambiente de Internet
(Ciberseguridad)

Canales de Comunicación Seguros
• Seguridad en Tránsito: Protección exhaustiva de flujos de datos
que viajan a través de redes inseguras e interconectadas
globalmente.

Protocolos y Mitigación
• Protocolos HTTPS / TLS: Mecanismo estándar que cifra la
comunicación web entre el navegador y el servidor,
garantizando privacidad y autenticidad bidireccional.

• Cifrado Extremo a Extremo: Garantiza que solo los puntos
finales legítimos puedan leer la información enviada.

• Redes Privadas Virtuales (VPN): Canales cifrados tunelizados
que aíslan el tráfico de datos corporativos o privados dentro de
infraestructuras públicas abiertas.

• Protección contra Interceptación: Mitigación directa y efectiva
de ataques pasivos como el sniffing de paquetes en redes Wi-Fi
públicas o enlaces troncales de proveedores de servicios.

2.1.3 Elementos y Personas Involucradas en
Criptografía

Componentes Técnicos
• Texto Claro (Plaintext): El mensaje original legible que
contiene la información sin alterar.

• Texto Cifrado (Ciphertext): El resultado incomprensible tras
aplicar la transformación matemática criptográfica.

• Algoritmo: La función matemática pública (ej. AES, RSA)
encargada de estructurar el cifrado.

• Llave (Key): El secreto criptográfico que personaliza y vuelve
única la transformación matemática.

Actores del Escenario
• Alice y Bob: Nombres arquetípicos universales utilizados para
representar a los participantes legítimos que buscan
comunicarse con seguridad.

• Eve: Representa al escucha pasivo (Eavesdropper), un atacante
que intercepta el canal sin alterar el mensaje.

• Mallory: Representa al atacante activo malicioso capaz de
modificar, inyectar o eliminar los mensajes en tránsito.

2.2 Las Matemáticas Discretas en la Criptografía

Fundamentos del Cómputo Criptográfico
• Naturaleza Discreta del Cómputo: Las computadoras digitales
operan estrictamente con estados finitos y binarios, requiriendo
estructuras discretas en lugar de funciones continuas.

• Evitar Errores de Redondeo: Los sistemas basados en
funciones continuas sufren de imprecisión por el punto flotante;
las matemáticas discretas garantizan un cifrado y descifrado
100% exacto simétrico.

Estructuras Matemáticas Especializadas
• Funciones Unidireccionales: Estructuras matemáticas fáciles de
calcular en un sentido (directo), pero computacionalmente
infactibles de revertir (sentido inverso) sin un secreto o
trapdoor.

• Estructuras Algebraicas Fundamentales: Uso intensivo de
conjuntos finitos, grupos permutacionales, anillos y campos
algebraicos para mapear y transformar datos de forma unívoca.

2.2.1 Teoría de la Información

Entropía y Secreto Perfecto
• Concepto de Entropía de Shannon: Medida científica de la
incertidumbre o aleatoriedad de una fuente de datos. Una alta
entropía previene ataques estadísticos basados en patrones.

Aplicaciones Prácticas
• One-Time Pad (Libreta de un solo uso): El único sistema con
secreto perfecto matemáticamente verificado, requiriendo una
llave aleatoria que sea tan larga como el propio mensaje.

• Secreto Perfecto: Concepto teórico donde el texto cifrado no
revela información alguna sobre el texto claro original, sin
importar la capacidad de cómputo del atacante.

• Redundancia del Lenguaje: Los lenguajes naturales poseen
patrones repetitivos; la criptografía moderna busca destruirlos
por completo para simular ruido blanco puramente aleatorio.

2.2.2 Teoría de Números

Pilares Matemáticos
• Números Primos: Bloques de construcción criptográficos
esenciales debido a la dificultad extrema de factorizar el
producto de dos primos de gran tamaño.

• Aritmética Modular: Operaciones matemáticas realizadas
sobre conjuntos finitos cíclicos (comúnmente llamada
aritmética del reloj). Es la base operativa de casi toda la
criptografía asimétrica.

Problemas y Teoremas
• Problema del Logaritmo Discreto: Problema matemático de
alta complejidad que sustenta directamente esquemas
avanzados como Diffie-Hellman y Criptografía de Curvas
Elípticas.

• Teoremas Fundamentales: El Pequeño Teorema de Fermat y el
Teorema de Euler son utilizados directamente en el diseño para
validar la reversibilidad en el algoritmo RSA.

2.2.3 Teoría de la Complexity de los Algoritmos

Clases de Complejidad
• Clases de Complejidad (P vs. NP): P incluye problemas
resolubles rápidamente en tiempo polinomial; NP contiene
problemas cuya solución es rápida de verificar pero
exponencialmente lenta de hallar de forma determinista.

• Problemas Hard (Difíciles): La factorización de enteros y los
logaritmos discretos se consideran intratables para
computadoras clásicas en escalas de tiempo humanas al escalar
el tamaño.

Criterios de Diseño
• Seguridad Basada en Costo Computacional: La seguridad
criptográfica no es absoluta, sino relativa al tiempo, energía y
dinero requeridos por un atacante para romper el esquema.

• Impacto del Crecimiento Exponencial: Diseñar algoritmos
robustos donde la seguridad interna aumente de forma
exponencial al incrementar el tamaño de la llave en tan solo
unos pocos bits.

2.3 Programación de Algoritmos: Tipos

Taxonomía Criptográfica
• Criptografía Simétrica: Utiliza exactamente la misma llave
secreta tanto para cifrar como para descifrar. Destaca por su
alta velocidad y optimización para grandes volúmenes de datos
(ej. AES, DES).

• Criptografía Asimétrica: Emplea un par de llaves
matemáticamente vinculadas: una pública (distribuible) y una
privada (secreta). Resuelve el problema crítico de la distribución
segura de llaves (ej. RSA, ECC).

Funciones Hash y Gestión
• Funciones Hash (Una Sola Vía): Algoritmos que generan una
huella digital determinista de tamaño fijo, no invertible, a partir
de cualquier volumen de datos de entrada (ej. SHA-256).

• Gestión e Intercambio de Llaves: Los sistemas modernos
combinan ambos mundos: se usa criptografía asimétrica para
compartir una llave simétrica efímera que cifrará los datos de la
sesión de forma veloz.

2.3 INTERMEDIO Encriptamiento en Lenguaje
Ensamblador

Restricciones de Hardware en IoT
• Entornos de Microcontroladores: Los chips embebidos (ej.
PIC, AVR, ARM Cortex-M) poseen memoria RAM,
almacenamiento y capacidad de procesamiento críticamente
limitadas.

Eficiencia a Nivel de Registro
• Manipulación Directa: Programar en ensamblador permite
manipular directamente registros de 8, 16 o 32 bits, eliminando
el overhead de compiladores de alto nivel y optimizando ciclos
de reloj.

• Criptografía Ligera (Lightweight): Implementación óptima y
matemática de algoritmos ultra compactos como Simon, Speck
o variantes compactas y reducidas de AES optimizadas para
hardware embebido.

• Operaciones de Bajo Nivel: Uso nativo de instrucciones
ultrarrápidas de un solo ciclo de CPU como XOR (Exclusive
OR), rotaciones de bits (ROR, ROL) y desplazamientos lógicos
(SHL, SHR).

2.3.1 Criptografía Clásica: Algoritmo Cifrado César

Técnica Detallada:
Sustitución Monoalfabética: Desplaza cada carácter una distancia fija 'K' a
lo largo del alfabeto. Manipula caracteres individuales manualmente o
mecánicamente.

Paso a Paso del Algoritmo:
1. Definir el alfabeto estándar de 26 letras y asignar un índice numérico a
cada una (A=0, B=1, ..., Z=25).

2. Tomar la letra del texto claro (M) y obtener su posición numérica.

3. Sumar la llave de desplazamiento (K) a dicha posición.

4. Aplicar módulo 26 sobre el resultado para asegurar el comportamiento
cíclico: C = (M + K) mod 26.

5. Convertir el número resultante de vuelta a la letra correspondiente del
alfabeto cifrado.

Ejemplo de Aplicación Práctica:

EJERCICIO PRÁCTICO RESOLVIdO:

Mensaje: 'CRIPTOGRAFIA'
Llave de desplazamiento: K = 3

Operación letra por letra:
• C (2)   -> (2+3) mod 26 = 5   -> F
• R (17)  -> (17+3) mod 26 = 20 -> U
• I (8)   -> (8+3) mod 26 = 11  -> L
• P (15)  -> (15+3) mod 26 = 18 -> S
• T (19)  -> (19+3) mod 26 = 22 -> W
• O (14)  -> (14+3) mod 26 = 17 -> R
• G (6)   -> (6+3) mod 26 = 9   -> J
• R (17)  -> (17+3) mod 26 = 20 -> U
• A (0)   -> (0+3) mod 26 = 3   -> D
• F (5)   -> (5+3) mod 26 = 8   -> I
• I (8)   -> (8+3) mod 26 = 11  -> L
• A (0)   -> (0+3) mod 26 = 3   -> D

Texto Cifrado Final: 'FULswrjudild'

2.3.2 Esteganografía: Técnica LSB (Least Significant
Bit)

Técnica Detallada:
Ocultamiento en Contenedores: Modifica el bit menos significativo de los
bytes que componen una imagen o audio para esconder información sin
alterar notablemente la apariencia externa.

Paso a Paso del Algoritmo:
1. Convertir el mensaje secreto que se desea ocultar en una cadena de
bits binarios puros.

2. Seleccionar el archivo portador (ej. imagen en escala de grises de 8 bits
por píxel).

3. Leer secuencialmente los bytes del archivo portador.

4. Reemplazar el bit de menor peso (LSB, posición 0) de cada byte del
portador por un bit del mensaje secreto.

5. Guardar el archivo modificado resultante (Estego-objeto) manteniendo
su formato de apariencia intacta.

Ejemplo de Aplicación Práctica:

EJERCICIO PRÁCTICO RESOLVIdO:

Píxel original (8 bits de gris):
Valor decimal: 104
Binario original: 01101000

Bit secreto a ocultar: '1'

Paso de Reemplazo LSB:
• Tomamos:  0 1 1 0 1 0 0 [0] <- Cambiar por
1
• Resultado:0 1 1 0 1 0 0 [1]

Píxel modificado final:
Binario: 01101001
Valor decimal resultante: 105

Efecto Visual:
El cambio en la intensidad del color es de
apenas 1/255, siendo totalmente invisible
para el ojo humano.

2.3 Ensamblador: Algoritmo Cifrado XOR

Técnica Detallada:
Lógica Simétrica Inversa: Utiliza la propiedad booleana de la compuerta
XOR a nivel de registros binarios donde A XOR B XOR B = A. Se
procesa a la velocidad nativa del procesador en un solo ciclo.

Paso a Paso del Algoritmo:
1. Cargar el dato original o texto claro en un registro de trabajo del
microcontrolador (ej. WREG).

2. Cargar el valor de la llave secreta binaria en un registro
complementario o literal en memoria.

3. Ejecutar la instrucción nativa XOR bit a bit entre ambos registros (ej.
XORWF WREG, F).

4. El resultado almacenado constituye el dato cifrado listo para
transmitirse o almacenarse de forma segura.

5. Para descifrar, volver a aplicar exactamente la misma instrucción XOR
con la misma llave secreta.

Ejemplo de Aplicación Práctica:

EJERCICIO PRÁCTICO RESOLVIdO:

Registro de datos (WREG) = 0x5A
Binario: 01011010

Registro de Llave Secreta = 0x3F
Binario: 00111111

Operación lógica bit a bit (XOR):

01011010 (Dato 0x5A)

XOR

00111111 (Llave 0x3F)
--------
01100101 (Resultado Cifrado)

Valor Hexadecimal Cifrado: 0x65

Demostración de Descifrado Reversible:

01100101 (Cifrado 0x65)

XOR

00111111 (Llave 0x3F)
--------
01011010 (Dato original 0x5A)

2.3.3 Curva Elíptica: Intercambio Diffie-Hellman

Técnica Detallada:
Grupos Cíclicos en Campos Finitos: Establece un secreto compartido
sobre un canal inseguro evadiendo la reversión del logaritmo discreto. En
ECC se usan puntos de curva en vez de enteros ordinarios.

Paso a Paso del Algoritmo:
1. Acordar públicamente un número primo 'p' y una base matemática o
generador 'g'.

2. Alice elige un número secreto privado 'a' y calcula su valor público: A =
(g^a) mod p. Envía A a Bob.

3. Bob elige un número secreto privado 'b' y calcula su valor público: B =
(g^b) mod p. Envía B a Alice.

4. Alice calcula la llave compartida usando el dato de Bob: K = (B^a) mod
p.

5. Bob calcula la llave compartida usando el dato de Alice: K = (A^b) mod
p. Ambos valores coinciden exactamente.

Ejemplo de Aplicación Práctica:

EJERCICIO PRÁCTICO RESOLVIdO:

Parámetros públicos: p = 23, g = 5

1. Alice elige secreto privado: a = 6

Calcula valor público A:
A = (5^6) mod 23 = 15625 mod 23 = 8
Alice transmite A = 8 a Bob.

2. Bob elige secreto privado: b = 15

Calcula valor público B:
B = (5^15) mod 23 = 19
Bob transmite B = 19 a Alice.

3. Cálculo de llave compartida (K):

• Alice: K = (19^6) mod 23 = 2
• Bob:   K = (8^15) mod 23 = 2

Ambos obtienen la misma llave simétrica K =
2 de forma segura sin revelar sus secretos
privados.

2.3.4 Criptografía Cuántica y Post-Cuántica

La Amenaza Cuántica
• Algoritmo de Shor: Algoritmo cuántico capaz de romper por
completo RSA y ECC en tiempo polinomial al factorizar primos
masivos y resolver logaritmos discretos rápidamente.

Criptografía Post-Cuántica (PQC)
• Definición PQC: Algoritmos matemáticos clásicos nuevos
basados en estructuras como retículos algebraicos o códigos
que son intrínsecamente resistentes a ataques cuánticos.

• Distribución de Claves Cuánticas (QKD): Uso de leyes físicas
y mecánicas de la física cuántica (fotones) para intercambiar
llaves secretas con detección intrínseca de intrusos en tiempo
real.

• Transición Global Obligatoria: Estándares impulsados
actualmente por agencias internacionales (NIST) para migrar de
forma masiva la infraestructura digital mundial hacia algoritmos
PQC.

2.4 Campos de Aplicación de la Criptografía

Protección de Entornos
• Autenticación de Sistemas: Mecanismos criptográficos
avanzados para verificar la identidad digital de usuarios,
servidores o dispositivos antes de otorgar accesos
corporativos.

• Almacenamiento Seguro (Data at Rest): Cifrado completo de
discos duros, bases de datos y archivos locales para evitar fugas
de información masivas ante pérdidas físicas de hardware.

Transacciones y Redes
• Comercio Electrónico y Banca: Pasarelas de pago cifradas y
transacciones financieras protegidas de extremo a extremo
contra fraudes, clonaciones e interceptación.

• Sistemas Distribuidos (Blockchain): Uso intensivo de hashes y
firmas criptográficas para enlazar bloques de datos inmutables y
firmar transacciones descentralizadas.

