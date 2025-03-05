# PAI-2 BYODSEC - Bring Your Own Device Seguro usando Road Warrior VPN SSL para una Universidad Pública

## Introducción
En este Proyecto de Aseguramiento de la Información, implementaremos técnicas para garantizar la integridad, confidencialidad y autenticidad en la transmisión de datos a través de redes públicas como Internet.

Una Universidad Pública nos ha solicitado la implementación de una política de seguridad **Bring Your Own Device (BYOD) seguro** para sus empleados. Esto permitirá que utilicen sus propios dispositivos para acceder a recursos como correos electrónicos, bases de datos y archivos en servidores corporativos mediante una **VPN SSL**. En un contexto empresarial, estos usuarios se denominan **Road Warriors**, es decir, trabajadores remotos que requieren acceso seguro a la infraestructura de la organización.

Para lograr esto, utilizaremos canales de comunicación seguros mediante **Virtual Private Networks (VPNs)**, específicamente con el protocolo **SSL/TLS**, garantizando así autenticidad, confidencialidad e integridad en la comunicación.

Además, la Universidad debe cumplir con la normativa vigente en España, incluyendo:
- **Reglamento General de Protección de Datos (RGPD)** de la Unión Europea.
- **Ley Orgánica 3/2018 (LOPDGDD)** sobre Protección de Datos Personales y garantía de los derechos digitales.
- **Real Decreto 3/2010** sobre el Esquema Nacional de Seguridad (ENS), que exige protección en la administración electrónica.

## Política de Seguridad
La política de seguridad de la Universidad establece que:
> "Las transmisiones de información entre cliente y servidor deben ser **confidenciales, íntegras y autenticadas**."

## Objetivos
1. Implementar de manera eficiente canales de comunicación segura con **SSL/TLS** para la transmisión de credenciales y mensajes.
2. Asegurar que el sistema pueda manejar **hasta 300 usuarios concurrentes** sin degradación del rendimiento.
3. Utilizar herramientas de análisis de tráfico para verificar la **confidencialidad e integridad** de los datos.
4. Configurar **Cipher Suites robustos** en **TLS 1.3**, evitando vulnerabilidades.
5. Comparar el rendimiento con y sin **VPN SSL** para evaluar posibles pérdidas de rendimiento.

## Arquitectura
### Requisitos Funcionales
1. **Registro de usuarios**:
   - Permitir el registro con **nombre de usuario** y **contraseña**.
   - Validar si el usuario ya está registrado.
   - No permitir modificaciones de datos una vez registrado.
2. **Inicio de sesión**:
   - Autenticación mediante usuario y contraseña.
   - Validación contra la base de datos del servidor.
3. **Cierre de sesión**:
   - Permitir a los usuarios cerrar sesión de manera segura.
4. **Gestión de usuarios preexistentes**:
   - Cargar una lista inicial de usuarios pre-registrados.
5. **Mensajería segura**:
   - Envío de mensajes autenticados y cifrados mediante **SSL/TLS**.
   - Persistencia de datos: almacenar usuarios y mensajes enviados.
   - Registrar el número de mensajes enviados por usuario y fecha.
6. **Interfaz de comunicación**:
   - Proveer una interfaz con **sockets seguros (SSL/TLS)** para autenticación y mensajería.

### Requisitos de Información
- Almacenar información de usuarios:
  - **Nombre de usuario único**.
  - **Contraseña cifrada**.
- Mantener una base de datos con:
  - Usuarios pre-registrados.
  - Historial de mensajes (usuario, texto, fecha).
- Informar al usuario en situaciones clave como:
  - Registro exitoso o fallido.
  - Inicio de sesión exitoso o fallido.
  - Mensajes enviados y recibidos correctamente.

### Requisitos de Seguridad
1. **Credenciales de usuario**:
   - Almacenamiento seguro de contraseñas.
   - Protección contra ataques de fuerza bruta en login.
2. **Mensajes**:
   - Garantizar **confidencialidad, integridad y autenticidad** en la transmisión.
3. **Base de datos**:
   - Protección contra alteraciones y accesos no autorizados.

## Conclusión
Este proyecto asegurará la transmisión de datos mediante **VPN SSL** para los empleados de la Universidad Pública, cumpliendo con los requisitos de seguridad y normativas legales. La implementación de **TLS 1.3** garantizará la máxima seguridad en la autenticación, confidencialidad e integridad de la información transmitida.
