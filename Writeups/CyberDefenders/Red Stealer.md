# 🔍 Red Stealer Lab WriteUp – CTI & Malware Analysis (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: Un ejecutable sospechoso (`wextract.exe`) fue descubierto en la PC de un colega del SOC, con comunicación C2 detectada.  

**Objetivo**: Analizar hash en plataformas CTI para extraer IOCs, identificar infraestructura C2, técnicas MITRE ATT&CK y mecanismos de escalación de privilegios. 

**Herramientas**: VirusTotal, MalwareBazaar, ThreatFox, ANY.RUN, Whois.

**Tácticas**: Execution | Persistence | Privilege Escalation | Defense Evasion | Discovery | Collection | Impact |

En el contenido del laboratorio nos entregan un hash del archivo malicioso para posteriormente realizar los análisis y pruebas pertinentes en las plataformas de CTI (VirusTotal, Hybrid Analisis, Any.Run, etc)

<img width="1359" height="677" alt="image" src="https://github.com/user-attachments/assets/f03076b9-f485-46c3-a671-afe6b527f7d0" />


*HASH*: **248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B**

---

## 📋 Preguntas del Laboratorio & Respuestas


| Q1 | Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?
-

Siguiendo la consigna de la pregunta nos dirigimos a VirusTotal, al introducir el Hash buscamos como lo categoriza dicho motor, viendo así que el mismo lo categoriza como un "Trojan".

<img width="1359" height="681" alt="Captura de pantalla 2026-03-12 025226" src="https://github.com/user-attachments/assets/88adefa6-f34b-4cdb-bd4d-469523a42c94" />

**R:** `Trojan` 

-----

| Q2 | Clearly identifying the name of the malware file improves communication among the SOC team. What is the file name associated with this malware?
-

Si nos vamos al apartado de "Details" podemos bajar hasta donde están los nombres de archivo vinculados a este Hash.

<img width="1358" height="677" alt="Captura de pantalla 2026-03-12 025521" src="https://github.com/user-attachments/assets/134de7f4-ae18-4f50-ad89-8b808a0e2296" />

**R:**`wextract` 

-----

| Q3 | Knowing the exact timestamp of when the malware was first observed can help prioritize response actions. Newly detected malware may require urgent containment and eradication compared to older, well-documented threats. What is the UTC timestamp of the malware's first submission to VirusTotal?
-

Acá en "Details" vemos que la primera vez que fue analizado por VirusTotal fue la siguiente:

<img width="1359" height="679" alt="Captura de pantalla 2026-03-12 025809" src="https://github.com/user-attachments/assets/48799136-931a-4cea-943a-c133c2877e02" />


**R:**`2023-10-06 04:41` 

-----

| Q4 | Understanding the techniques used by malware helps in strategic security planning. What is the MITRE ATT&CK technique ID for the malware's data collection from the system before exfiltration?
-

Si nos vamos a "Behaviour" en VT, podemos corroborar en "Data Collection" el comportamiento principal de recolección de información se trata de la siguiente TTP:

<img width="1136" height="159" alt="Captura de pantalla 2026-03-12 033534" src="https://github.com/user-attachments/assets/b9a04ae2-90cb-42ca-b9e1-a8c677dbb2ef" />


**R:**`T1005`

-----

| Q5 | Following execution, which social media-related domain names did the malware resolve via DNS queries?
-

Siguiendo el comportamiento desde VT, podemos ver en "Activity Summary" que en "DNS Resolutions" podemos encontrar el dominio "Facebook.com".
Esto es una clara señal de intentar ofuscar el comportamiento maligno de este malware simulando comportamiento "benigno" de red.

<img width="1359" height="682" alt="Captura de pantalla 2026-03-12 033929" src="https://github.com/user-attachments/assets/c292cdb6-5f25-4c2a-8650-2f21eb93e889" />


**R:**`Facebook.com`

-----

| Q6 | YARA rules are designed to identify specific malware patterns and behaviors. Using MalwareBazaar, what's the name of the YARA rule created by "Varp0s" that detects the identified malware?
-

Para buscar la YARA rule de nuestro bro "Varp0s" nos dirigiremos hacia MalwareBazaar. Ingresando al buscar e inyectando el hash del archivo, nos vamos hasta el apartado de YARA. Aquí es donde encontraremos el nombre de la YARA rule correspondiente.


<img width="1359" height="677" alt="Captura de pantalla 2026-03-12 034905" src="https://github.com/user-attachments/assets/feb052c9-cb5f-4e3e-a2c4-c6bf3359c689" />



**R:**`detect_Redline_Stealer` 

-----

| Q7 | Understanding which malware families are targeting the organization helps in strategic security planning for the future and prioritizing resources based on the threat. Can you provide the different malware alias associated with the malicious IP address according to ThreatFox?
-

Teniendo en cuenta que el malware con el que estamos tratando es *"Redline"*, ingresamos en ThreatFox y buscamos por *"malware:Redline"*. Acá podemos entrar a cualquiera que nos salga y veremos que se hace llamar también *"RecordStealer"*

<img width="1359" height="677" alt="Captura de pantalla 2026-03-12 043035" src="https://github.com/user-attachments/assets/995a1d9d-0c1e-42a2-bea7-2a6698f5e06d" />



**R:**`RecordStealer`

-----

| Q8 | By identifying the malware's imported DLLs, we can configure security tools to monitor for the loading or unusual usage of these specific DLLs. Can you provide the DLL utilized by the malware for privilege escalation?

En VT, si nos posicionamos en "Details" y luego buscamos en "Imports" vemos como primera opción "ADVAPI32.dll" si nos fijamos en la info relacionada con esta librería, vemos claramente que apunta a escalación de privilegios.

<img width="1359" height="679" alt="Captura de pantalla 2026-03-12 035940" src="https://github.com/user-attachments/assets/fecb3742-2293-4ee2-a797-ee0b12d7bc13" />



**R:** `ADVAPI32.dll`











## 🛡️ Proceso de CTI (Cyber Threat Intelligence)

### 1. **Verificación Inicial de Hash**


SHA256: 248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B




**VirusTotal**: 50+ AV hits, first seen 2023-10-06

**MalwareBazaar**: Redline Stealer family confirmed

**ANY.RUN**: Active C2 config extraction: Confirmación stealer capabilities



### 2. **Análisis Dinámico (ANY.RUN Sandbox)**

#### **Proceso Principal Observado**:

VPN.exe.bin → .dll malicious → Network Activity → Data Exfil → Self-Delete



### 3. **Análisis de Comportamiento**

🔍 TTPs Identificados:

├── T1068 - Exploitation for Privilege Escalation

├── T1071.001 - Application Layer Protocol

├── T1005 - Data from Local System

└── T1027 - Obfuscated Files/Information



### 4. **Comportamiento Específico del Stealer**

1. **wextract.exe** ejecutado → PID 2893 (parent: explorer.exe)
   
2. **ADVAPI32.dll** loaded → Privilege escalation attempt
   
3. **DNS Resolution** → facebook.com (domain fronting)

4. **C2 Beacon** → 77.91.124.55:19071 (TCP connection)

5. **Data Collection** → Clipboard data, local files (T1005)

6. **Network Activity** → HTTP POST con system info + creds

---



## 🔬 Herramientas Utilizadas

Análisis Dinámico

├── VirusTotal → Hash reputation, behavior, imports

├── MalwareBazaar → YARA rules, sample metadata

├── ANY.RUN → Dynamic analysis, C2 configuration

├── ThreatFox → IOC relationships, malware aliases

└── Whois → IP geolocation/ownership


---

## 📊 Lecciones Aprendidas

1. **T1555 Hunting**: Monitorear *.dll fuera de browsers legítimos
2. **C2 Patterns**: IPs China (171.x.x.x) + PHP endpoints = alta sospecha
3. **Evasion**: Self-delete timers requieren memory forensics inmediata

---


> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: Oski (Threat Intel Category)*
