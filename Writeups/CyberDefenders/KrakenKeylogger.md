# 🔍 KrakenKeylogger Lab WriteUp – Endpoint Forensics (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: Un empleado de una gran compañía recibe “ayuda” de un tercero para completar una tarea con deadline de dos días. Al día siguiente, el tercero le envía una notificación indicando que terminó el trabajo y le manda un archivo de prueba, pero acto seguido le exige 160 USD para entregarle el resultado final. El comportamiento extorsivo dispara la intervención del equipo de DFIR.  
**Objetivo**: Analizar el endpoint del empleado para identificar el canal de comunicación con el atacante, el vector de infección, los mecanismos de persistencia y el canal de exfiltración de datos.  
**Herramientas**: DB Browser for SQLite, LECmd, Timeline Explorer, SRUM tools.  
**Tácticas**: Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Command and Control | Exfiltration.

---

## 📋 Preguntas del Laboratorio & Respuestas

| Q1 | What is the the web messaging app the employee used to talk to the attacker? | 
-

Teniendo en cuenta la pregunta y apoyándonos en el comportamiento de notificaciones de Windows, navegamos a:  
`C:\Users\OMEN\AppData\Local\Microsoft\Windows\Notifications\`  
para localizar el archivo **`wpndatabase.db`**.

Este archivo es una **base de datos SQLite** donde Windows almacena todas las notificaciones **toast** y **push** generadas por el sistema y por aplicaciones de terceros, incluyendo aplicaciones web que corren en el navegador y solicitan permiso para enviar notificaciones de escritorio. Desde el punto de vista forense, es clave porque puede revelar qué aplicaciones y sitios web estaban activos en el momento del incidente, aunque no haya clientes nativos instalados.

Exportamos `wpndatabase.db` y lo abrimos con **DB Browser for SQLite**. En la tabla `Notification` identificamos un registro cuyo payload referencia explícitamente **`web.telegram.org`**, lo que indica que el empleado estaba utilizando **Telegram Web** como cliente de mensajería en el navegador. 

<img width="1919" height="765" alt="1" src="https://github.com/user-attachments/assets/b86b6d76-9ce8-4ba3-b624-e6c09a599aca" />



**R:** `Telegram`

-----

| Q2 | What is the password for the protected ZIP file sent by the attacker to the employee? | 
-

Continuando el análisis de `wpndatabase.db`, profundizamos en el contenido del campo **payload** del registro asociado a `web.telegram.org`. Las notificaciones toast están almacenadas internamente como XML, incluyendo tanto el remitente como el **texto completo del mensaje** que generó la notificación.

Al expandir el payload en DB Browser for SQLite, encontramos el mensaje enviado por el atacante al empleado, donde se especifican tanto el nombre del archivo como la contraseña del ZIP:

`our project templet test.zip, pass:@1122d`

Esta línea deja explícito que el ZIP protegido enviado por el atacante utiliza la contraseña `@1122d`. 


<img width="1919" height="705" alt="2" src="https://github.com/user-attachments/assets/374460b3-cc00-4370-92b8-f57314f73f7f" />


**R:** `@1122d`  

-----

| Q3 | What domain did the attacker use to download the second stage of the malware? |  
-

El análisis se dividió en dos fases: **parsing del .lnk** y **análisis de comportamiento en filescan.io**.

**Fase 1 – LECmd sobre `templet.lnk`**  
Exportamos el archivo `templet.lnk` de la imagen forense y lo procesamos con **LECmd**:

```bash
LECmd.exe -f "templet.lnk"
```

LEcmd expone todos los campos estructurales del archivo: target path, timestamps, volume serial number y, lo más relevante para este caso, el campo Command Line Arguments. Al inspeccionarlo, confirmamos que el archivo no apuntaba a ningún documento legítimo, sino a powershell.exe con un argumento ofuscado — una red flag inmediata que nos indicó que este .lnk era el vector de ejecución inicial del atacante.

<img width="1919" height="941" alt="3" src="https://github.com/user-attachments/assets/d90bd828-61c8-496a-898b-51b3258a38ca" />


---


**Fase 2 – filescan.io**  
Subimos `templet.lnk` a **filescan.io**, que emula la ejecución y extrae automáticamente IOCs (URLs, dominios, DNS, etc.). En la sección **Network Behavior / Domains** se observa que el LNK descarga un HTA de segunda etapa desde:

`https://masherofmasters.cyou/shins/se1.hta`

El archivo `se1.hta` es un HTML Application descargado y ejecutado por `mshta.exe` — un binario legítimo de Windows frecuentemente abusado en ataques Living off the Land (LotL) para evadir controles de seguridad basados en reputación de procesos.  




<img width="1919" height="952" alt="3 1" src="https://github.com/user-attachments/assets/58432dd5-3392-4c56-86c2-a0f29f878073" />


**R:** `masherofmasters.cyou`

-----

| Q4 | What is the name of the command that the attacker injected using one of the installed LOLAPPS on the machine to achieve persistence? |  
-

Para esta pregunta seguimos tres pasos: identificación de **LOLAPP** instalada, confirmación en el proyecto **LOLAPPS**, y análisis de configuración.

**1) Qué es una LOLAPP**  
Las **LOLAPPs** (*Living off the Land Applications*) son aplicaciones legítimas de usuario (no binarios del sistema) cuya funcionalidad puede ser abusada para ejecución o persistencia sin instalar malware adicional. El proyecto `lolapps-project.github.io` las cataloga de forma análoga a **LOLBAS** (para binarios Windows).

**2) Identificación de Greenshot como LOLAPP**  
El primer paso fue revisar las aplicaciones instaladas a través de Autopsy, en la sección Data Artifacts → Installed Programs. Allí identificamos **Greenshot 1.2.10.6**. Consultando el catálogo de LOLAPPs, confirmamos que **Greenshot** está documentada como vector de persistencia mediante su **External Command Plugin**.

**3) Análisis de `Greenshot.ini`**  
Navegamos a:  
`C:\Users\OMEN\AppData\Roaming\Greenshot\Greenshot.ini`

El contenido relevante es:

```ini
[ExternalCommand]
Commands=MS Paint,jlhgfjhdfIghjhuhuh

Commandline.MS Paint=C:\Windows\System32\mspaint.exe
Commandline.jlhgfjhdfIghjhuhuh=C:\Windows\system32\cmd.exe

Argument.MS Paint={0}
Argument.jlhgfjhdfIghjhuhuh=C:\Users\OMEN\AppData\Local\Temp\templet.lnk
```

El comando **`MS Paint`** funciona como señuelo legítimo, mientras que el comando **`jlhgfjhdfIghjhuhuh`** ejecuta `cmd.exe` apuntando a `templet.lnk`, re-lanzando toda la cadena maliciosa **cada vez que el usuario toma una captura de pantalla**.  


<img width="1918" height="966" alt="4 1" src="https://github.com/user-attachments/assets/2626371b-fffe-46c0-a29c-a2b65c9d08fc" />

------

<img width="1784" height="681" alt="4" src="https://github.com/user-attachments/assets/87c6afc5-03a3-4a5f-afb4-cb9c7f1be313" />

**R:** `jlhgfjhdfIghjhuhuh`

-----

| Q5 | What is the complete path of the malicious file that the attacker used to achieve persistence? | 
-

En la misma configuración de `Greenshot.ini` (sección `[ExternalCommand]`) podemos ver el parámetro que define el argumento asociado al comando malicioso:

```ini
Argument.jlhgfjhdfIghjhuhuh=C:\Users\OMEN\AppData\Local\Temp\templet.lnk
```

Esto nos revela la ruta completa del archivo utilizado para mantener la persistencia. El atacante eligió `%LocalAppData%\Temp` porque es una ubicación de escritura permitida para usuarios no privilegiados, repleta de archivos temporales legítimos y normalmente poco monitoreada, lo que reduce drásticamente la probabilidad de detección.  



**R:** `C:\Users\OMEN\AppData\Local\Temp\templet.lnk`

-----

| Q6 | What is the name of the application the attacker utilized for data exfiltration? |  
-

Para esta pregunta nos centramos en el artefacto **`SRUDB.dat`** ubicado en:  
`C:\Windows\System32\sru\SRUDB.dat`

Este archivo corresponde al **System Resource Usage Monitor (SRUM)**, un componente nativo de Windows que registra de forma continua el uso de recursos (CPU, red, energía, etc.) por aplicación, con resolución temporal fina, independientemente de los logs de eventos.

**Parsing con SrumECmd**  
Usamos **SrumECmd** para parsear `SRUDB.dat` y lo exportamos en formato `csv` para inyectarlo en nuestro amigo **Timeline Explorer**:

```bash
SrumECmd.exe -f "SRUDB.dat" --csv .
```

El comando genera, entre otros, el archivo:

`20260418044534_SrumECmd_NetworkUsages_Output.csv`

Al abrir este CSV y filtrar por **`AnyDesk.exe`**, observamos una sesión con ~**2.8 GB de datos enviados**, claramente desproporcionado para un uso de soporte remoto legítimo. Esto, correlacionado con el resto de la evidencia, apunta a **exfiltración de datos masiva** a través de AnyDesk.  

<img width="1697" height="729" alt="5" src="https://github.com/user-attachments/assets/2726d701-d2c6-48e4-8d7d-ae9d29ed42dc" />

<img width="1919" height="938" alt="5 1" src="https://github.com/user-attachments/assets/8e3a1d54-2f96-40ab-892b-9b31c71b228a" />


**R:** `AnyDesk`

-----

| Q7 | What is the IP address of the attacker? | 
-

Para identificar la IP del atacante utilizamos los logs propios de AnyDesk, en particular el archivo:

`C:\Users\OMEN\AppData\Roaming\AnyDesk\ad.trace`

**¿Qué es `ad.trace`?**  
Es el log principal de AnyDesk, en texto plano, donde se registran todos los eventos de la aplicación: conexiones entrantes y salientes, IDs remotos, transferencias de archivos y, lo más importante, las **direcciones IP externas** de los peer remotos. No depende de la configuración del usuario y persiste incluso después de cerrar la aplicación.

Importamos `ad.trace` en **Timeline Explorer** y filtramos por la palabra clave **`External address`** (o `anynet.relay_conn`), que corresponde a las entradas donde AnyDesk anota la IP pública del cliente remoto conectado.

El filtro devuelve las entradas de sesión correspondientes al atacante, revelando la IP pública utilizada durante la sesión de exfiltración (~2.8 GB) detectada previamente en SRUM.  


<img width="1919" height="350" alt="6" src="https://github.com/user-attachments/assets/16bdef9d-85ff-4e8e-a16b-cbd65291dd15" />


**R:** `77.232.122.31`

-----

## 🛡️ Proceso de CTI (Cyber Threat Intelligence)

### 1. **Vector de Comunicación Inicial**

wpndatabase.db → Notificación web.telegram.org

→ Canal inicial: Telegram Web (chat con el atacante)

ZIP protegido: our project templet test.zip (pass: @1122d)



### 2. **Vector de Ejecución y Segunda Etapa**

Archivo: templet.lnk

LECmd → Target: powershell.exe con argumentos ofuscados

filescan.io → Descarga se1.hta desde masherofmasters.cyou

Ejecutor: mshta.exe (LOLBin)



### 3. **Persistencia via LOLAPP (Greenshot)**

Greenshot.ini → ExternalCommand

Comando malicioso: jlhgfjhdfIghjhuhuh

Ruta persistencia: C:\Users\OMEN\AppData\Local\Temp\templet.lnk

Trigger: Toma de captura de pantalla → ejecuta cadena de infección



### 4. **Canal de Exfiltración**

SRUDB.dat → SrumECmd → NetworkUsages

Proceso: AnyDesk.exe → ~2.8 GB enviados

ad.trace → External address → 77.232.122.31

Conclusión: AnyDesk usado como canal de exfiltración C2

---

## 🎯 MITRE ATT&CK Mapping

| Táctica | Técnica | ID | Descripción Observada |
|---------|---------|----|-----------------------|
| Initial Access | Phishing / User Execution (Compressed File) | T1204.002 | Usuario abre ZIP y ejecuta LNK malicioso (`templet.lnk`) |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | LNK lanza PowerShell con payload ofuscado |
| Execution | Command and Scripting Interpreter: mshta.exe | T1218.005 | `se1.hta` ejecutado vía `mshta.exe` (LOLBin) |
| Persistence | Event-Triggered Execution (User Activity) | T1546 | Greenshot ejecuta `templet.lnk` al tomar capturas |
| Defense Evasion | Obfuscated Files or Information | T1027 | PowerShell ofuscado (Reverse + Base64) |
| Command and Control | Remote Access Tools | T1219 | AnyDesk utilizado como RAT/exfil canal |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | ~2.8 GB enviados vía AnyDesk hacia 77.232.122.31 |

---

## 🔬 Herramientas Utilizadas

🔍 Artefactos de Usuario

├── DB Browser for SQLite → wpndatabase.db (notificaciones Telegram Web)

├── LECmd → Parsing avanzado de templet.lnk

└── Greenshot.ini → Persistencia via ExternalCommand

🌐 Network & Usage

├── SrumECmd → SRUDB.dat (NetworkUsages por proceso)

└── Timeline Explorer → Análisis de ad.trace (AnyDesk, external IP)

🔎 Threat Intel

└── filescan.io → Emulación y extracción automática de IOCs del LNK

---

## 📊 Lecciones Aprendidas

1. **Notificaciones de Windows como Intel**: `wpndatabase.db` es una fuente poco explotada que puede evidenciar el uso de aplicaciones web maliciosas (como Telegram Web) incluso sin clientes locales instalados.
2. **LOLAPPs en Persistencia**: Software “inofensivo” como Greenshot puede ser abusado como mecanismo de persistencia altamente sigiloso. Es crítico incluir LOLAPPs en las matrices de detección.
3. **SRUM + AnyDesk = Evidencia Fuerte**: Correlacionar `SRUDB.dat` (volumen de datos) con `ad.trace` (IP remota) proporciona una narrativa sólida y probatoria de exfiltración de datos mediante herramientas de acceso remoto.

---

> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: KrakenKeylogger (Endpoint Forensics Category)*
