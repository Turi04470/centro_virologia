=================================
=================

PROYECTO: CENTRO DE
CIBERSEGURIDAD Enfoque Principal:
Virología y Criptografía

1.  OBJETIVO GENERAL DEL PROYECTO
●  Construir un Centro de Ciberseguridad distribuido en equipos o "células de trabajo".
●  Cada equipo funcionará de manera independiente pero colaborativa, actuando tanto

como nodo inicial como nodo final dentro de la red del sistema.

●  El propósito central es procesar, cifrar, transmitir, descifrar y volver a cifrar información de
manera segura, emulando sistemas reales de transferencia de datos gubernamentales o
corporativos.

1.  ORGANIZACIÓN Y ESTRUCTURA DE LOS EQUIPOS
●  El grupo se divide en células de trabajo (aprox. 8 equipos en total).
●  Cada equipo es responsable de desarrollar su propio módulo de seguridad.
●  Todos los equipos deben tener la capacidad de comunicarse entre sí dentro de la red del

centro (como nodos interconectados).

1.  REQUISITOS TÉCNICOS POR MÓDULO (CADA CÉLULA)
●  Desarrollo del Módulo de Cifrado y Descifrado:

○  Cada módulo debe implementar al menos dos algoritmos de cifrado principales,
más los requerimientos adicionales solicitados previamente por el profesor.

○  Capacidad de procesar entradas (como imágenes o archivos con texto/información

específica) y generar salidas cifradas.

●  Gestión de Certificados Digitales:

○  Como resultado final, cada módulo/célula debe generar un archivo acompañado de

un certificado digital que avale y compruebe la autenticidad e integridad de la
información procesada.

○  El certificado debe poder ser verificado y leído por cualquier otro nodo de la red.

1.  COMUNICACIÓN E INTERCONECTIVIDAD ENTRE NODOS
●  Los equipos deben establecer protocolos de comunicación estables entre sus módulos.
●  Flujo de trabajo estándar: Un nodo envía información cifrada a otro, el receptor la recibe,
la descifra, aplica un algoritmo o modificación propia, la vuelve a cifrar (o la procesa
según el flujo) y la retransmite si es necesario (dinámica de "pelota de ping-pong").

●  Validación del flujo: Se evaluará que la información llegue correctamente, se procese bajo

los estándares requeridos y cumpla con las necesidades de seguridad solicitadas.

1.  TECNOLOGÍA Y ARQUITECTURA
●  Elección de Tecnología: Los equipos deben acordar la tecnología base a utilizar de forma
homogénea si se requiere compatibilidad estricta (por ejemplo, trabajar todos bajo el
ecosistema de Java o bien todos bajo .NET, ya que tecnologías radicalmente distintas

como Java y .NET presentan incompatibilidades de protocolos de comunicación directa).

●  Arquitectura y Componentes a Definir:

○  Diseño de interfaces (entorno web o móvil según decida el equipo).
○  Definición de bases de datos.
○  Protocolos de comunicación y control de errores.

1.  ENTREGABLES Y CALIFICACIÓN
●  Cada célula será evaluada con base en el funcionamiento correcto de su módulo, la
implementación adecuada de los algoritmos criptográficos, la emisión del certificado
digital y la correcta comunicación entre nodos.

●  Se recomienda avanzar por etapas: establecer la base de datos, definir la arquitectura, la

paleta de colores/interfaz y la lógica de cifrado antes de integrar el reporte final del
proyecto.

