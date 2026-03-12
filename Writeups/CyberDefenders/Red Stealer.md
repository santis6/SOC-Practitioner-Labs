# 🔍 Oski Lab WriteUp – CTI & Malware Analysis (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: Un contador recibió un email **"Urgent New Order"** con adjunto PPT que contenía información falsa de pedido. El SIEM alertó sobre descarga de archivo malicioso vinculado al PPT.  
**Objetivo**: Analizar el comportamiento del malware, identificar IOCs y mapear TTPs MITRE ATT&CK.

En el contenido del laboratorio nos entregan un hash del archivo malicioso para posteriormente realizar los análisis y pruebas pertinentes en las plataformas de CTI (VirusTotal, Hybrid Analisis, Any.Run, etc)



*HASH*: ****

---

## 📋 Preguntas del Laboratorio & Respuestas


| Q1 | Determining the creation time of the malware can provide insights into its origin. What was the time of malware creation?
-

En la plataforma de VirusTotal después de haber introducido el hash, podemos irnos al apartado de "Details" y en "History" podemos encontrar dicha fecha de creación.

<img width="1360" height="692" alt="image" src="https://github.com/user-attachments/assets/0072dd05-08a7-4cbf-ad8a-6ff5af4637bf" />



**R:** `2022-09-28 17:40 UTC` 

-----

| Q2 | Identifying the command and control (C2) server that the malware communicates with can help trace back to the attacker. Which C2 server does the malware in the PPT file communicate with?
-

Podemos corroborar en VirusTotal que en "Relations" hay un C2 Server vinculado a este malware, o también en el texto del reporte de Any.Run, en "Malware Configuration" vemos el C2 Server correspondiente.

<img width="1360" height="694" alt="image" src="https://github.com/user-attachments/assets/d10675a0-6ea6-4d7a-bfbf-4772e96061f3" />


**R:**`http://171.22.28.221/5c06c05b7b34e8e6.php` 

-----

| Q3 | Identifying the initial actions of the malware post-infection can provide insights into its primary objectives. What is the first library that the malware requests post-infection?


Después de ver el apartado de "Behaviour" en VirusTotal, encontramos que la primer librería que solicita el malware es la siguiente: 

<img width="1360" height="692" alt="image" src="https://github.com/user-attachments/assets/eee18e24-e49c-417e-9597-327a61aef554" />



**R:**`sqlite3.dll` 

-----

| Q4 | By examining the provided Any.run report, what RC4 key is used by the malware to decrypt its base64-encoded string? 
-

Como podemos ver en la parte de "Malware Configuration" del reporte de Any.Run podemos encontrar tanto el C2 Server como una RC4 key para decodificar base64.

![image-5](https://github.com/user-attachments/assets/65378f20-2880-46b6-afe5-dced8c931ae0)



**R:**`5329514621441247975720749009`

-----

| Q5 | By examining the MITRE ATT&CK techniques displayed in the Any.run sandbox report, identify the main MITRE technique (not sub-techniques) the malware uses to steal the user’s password.
-
En Any.Run podemos ver un mapeo de las TTPs de MITRE ATT&CK, en la parte de robo de credenciales encontramos dos posibles opciones:

1- T1552 `Unsecured Credentials`

2- T1555 `Credentials from Password Stores`

Podemos intentar con las dos opciones y ver cual es la correcta, o podemos irnos a alguna de las POST Request del malware. Como vimos anteriormente este malware codifica en Base64 así que copiamos la POST Request y nos dirigimos a CyberChef. Decodificando el Base64 encontramos que hace el envío de los artefactos, dándonos a entender que se trata de un "Credential from Password Stores".

<img width="1359" height="677" alt="image" src="https://github.com/user-attachments/assets/f5f4a410-97b3-413e-addc-96c3f6827b78" />

<img width="1360" height="692" alt="image" src="https://github.com/user-attachments/assets/c5d98813-68b2-4317-b313-9092c7183025" />




**R:**`T1555`

-----

| Q6 | By examining the child processes displayed in the Any.run sandbox report, which directory does the malware target for the deletion of all DLL files?
-

Como bien podemos observar el malware crea un proceso `cmd.exe` con varios parámetros.. Espera 5 segundos antes de eliminarse a sí mismo y también todo el contenido de la carpeta `C:\ProgramData` apuntando a las librerías `*.dll`.


<img width="1360" height="694" alt="image" src="https://github.com/user-attachments/assets/7b8547fe-ee31-4a8b-8ddb-bbcb1979f930" />




**R:**`C:\ProgramData` 

-----

| Q7 | Understanding the malware's behavior post-data exfiltration can give insights into its evasion techniques. By analyzing the child processes, after successfully exfiltrating the user's data, how many seconds does it take for the malware to self-delete?
-

Acá la respuesta es 5 segundos teniendo en cuenta la observación de la respuesta anterior. :)


**R:**`5 segundos`

-----



## 🛡️ Proceso de CTI (Cyber Threat Intelligence)

### 1. **Verificación Inicial de Hash**


SHA256: a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb


- **VirusTotal**: 60+ detecciones (Google Chrome Helper, etc.)
 
- **ANY.RUN**: Reporte interactivo disponible
  
- **Hybrid Analysis**: Confirmación stealer capabilities



### 2. **Análisis Dinámico (ANY.RUN Sandbox)**

#### **Proceso Principal Observado**:

VPN.exe.bin → .dll malicious → Network Activity → Data Exfil → Self-Delete



### 3. **Análisis de Comportamiento**

🔍 TTPs Identificados:

├── T1555.001 - Keychain (Chrome/Edge passwords)

├── T1071.001 - Web Protocols (HTTP C2)

├── T1560.001 - Archive via Utility (DLL cleanup)

├── T1489 - Service Stop (evasion)

└── T1070.004 - File Deletion (self-delete)


### 4. **Comportamiento Específico del Stealer**

1. Enumera perfiles de navegadores (Chrome/Edge)
  
2. Extrae credenciales via sqlite3.dll → Chrome Login Data
   
3. Empaqueta datos del sistema (hostname, user, IP)
 
4. Codifica payload en base64 → HTTP POST al C2
   
5. Recibe comando de "éxito" → inicia cleanup
  
6. Borra DLLs en ProgramData → Self-delete


---



## 🔬 Herramientas Utilizadas

Análisis Dinámico

├── ANY.RUN (sandbox principal)

├── VirusTotal (hash reputation)

└── Hybrid Analysis (comportamiento)

🛠️ Análisis Manual

├── CyberChef (RC4 decoding)

└── MITRE ATT&CK Navigator


---

## 📊 Lecciones Aprendidas

1. **T1555 Hunting**: Monitorear *.dll fuera de browsers legítimos
2. **C2 Patterns**: IPs China (171.x.x.x) + PHP endpoints = alta sospecha
3. **Evasion**: Self-delete timers requieren memory forensics inmediata

---


> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: Oski (Threat Intel Category)*
