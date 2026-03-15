# 🔍 Ramnit Lab WriteUp – Endpoint Forensics (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: IDS alerta comportamiento sospechoso en workstation. Memory dump disponible para análisis forense.  
**Objetivo**: Identificar proceso malicioso, extraer IOCs de red, hash del ejecutable y timestamp de compilación correlacionando con Threat Intelligence externa.  
**Herramientas**: Volatility 3, VirusTotal.  
**Tácticas**: Execution | Defense Evasion | Command and Control.

El escenario presenta un dump de memoria para realizar análisis forense y aplicar técnicas Volatility para detectar actividad maliciosa.

## 📋 Preguntas del Laboratorio & Respuestas

| Q1 | What is the name of the process responsible for the suspicious activity? 
-

**Primero corroboramos los procesos ejecutándose con**:  

`python3 vol.py -f (PATH al dump) Windows.pslist`  

Al revisar la lista inicialmente no vemos procesos potencialmente maliciosos evidentes, por lo que procedemos a analizar los comandos ejecutados en el sistema con:  

`python3 vol.py -f (PATH al dump) Windows.cmdline`  

![image alt](https://github.com/santis6/SOC-Practitioner-Labs/blob/a84ba7df59a89dac99516a0c3300307227b60f67/222.png)



Aquí podemos observar claramente una línea de comando sospechosa: **ChromeSetup.exe**. Este comportamiento es anómalo ya que un instalador legítimo de Chrome se cierra automáticamente tras completar la instalación, no permanece activo en el sistema. Con este criterio podemos responder tanto la primera como la segunda pregunta del laboratorio.  

**R:** `ChromeSetup.exe`



| Q2 | What is the exact path of the executable for the malicious process? 
-

Path del proceso malicioso confirmado desde los flags de cmdline en Volatility.  

**R:** `C:\Users\alex\Downloads\ChromeSetup.exe`



| Q3 | Identifying network connections is crucial for understanding the malware's communication strategy. What IP address did the malware attempt to connect to?  
-

**Para contestar esta pregunta recurrimos al plugin Windows.netscan** para enumerar todas las conexiones de red realizadas por los procesos del dump. Para reducir ruido y filtrar específicamente el proceso malicioso, aplicamos un grep sobre el PID extraído anteriormente (4628):  

`python3 vol.py -f (PATH al dump) Windows.netscan | grep -i "4628"`  

![image alt](https://github.com/santis6/SOC-Practitioner-Labs/blob/d8b2e4c99556308e9b398a666b613c8a4e1a8f99/Screenshot_2026-03-14_16_19_13.png)


**R:** `58.64.204.181`



| Q4 |To determine the specific geographical origin of the attack, Which city is associated with the IP address the malware communicated with?  
-

**Para geolocalizar la IP maliciosa recurrimos a plataformas como geodatatool, VirusTotal, WhatIsMyIPAddress**, entre otras herramientas de inteligencia de IP. 

![image alt](https://github.com/santis6/SOC-Practitioner-Labs/blob/d8b2e4c99556308e9b398a666b613c8a4e1a8f99/Screenshot_2026-03-14_16_21_14.png)


**R:** `Hong Kong`



| Q5 | Hashes serve as unique identifiers for files, assisting in the detection of similar threats across different machines. What is the SHA1 hash of the malware executable?  
-

**Ya con el proceso malicioso identificado (PID 4628), realizamos dump del ejecutable** para posteriormente calcular su hash. Utilizamos el plugin Windows.dumpfiles con el parámetro --pid para especificar el proceso objetivo:  

`python3 vol.py -f (PATH al dump) Windows.dumpfiles --pid 4628`  

![image alt](https://github.com/santis6/SOC-Practitioner-Labs/blob/d8b2e4c99556308e9b398a666b613c8a4e1a8f99/Screenshot_2026-03-14_16_37_39.png)


Tras el dumpeo exitoso del ejecutable, calculamos el hash SHA1:  

`sha1sum file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img` 

**R:** `280c9d36039f9432433893dee6126d72b9112ad2`



| Q6 | Examining the malware's development timeline can provide insights into its deployment. What is the compilation timestamp for the malware?
-

**Realizamos análisis de Threat Intelligence en VirusTotal** ingresando el hash SHA1 extraído. En el apartado "Details" de la muestra identificamos la fecha de compilación del malware. 


![image alt](https://github.com/santis6/SOC-Practitioner-Labs/blob/d8b2e4c99556308e9b398a666b613c8a4e1a8f99/Screenshot_2026-03-14_16_42_04.png)


**R:** `2019-12-01 08:36`



| Q7 | Identifying the domains associated with this malware is crucial for blocking future malicious communications and detecting any ongoing interactions with those domains within our network. Can you provide the domain connected to the malware?
-

**En VirusTotal navegamos al apartado "Relations"** de la muestra analizada. En la sección "Contacted Domains" identificamos el dominio C2 asociado al malware.  


![image alt](https://github.com/santis6/SOC-Practitioner-Labs/blob/d8b2e4c99556308e9b398a666b613c8a4e1a8f99/Screenshot_2026-03-14_16_43_21.png)



**R:** `dnsnb8.net`



## 🛡️ Proceso de CTI (Cyber Threat Intelligence)

### 1. **Process Enumeration y Behavioral Analysis**
python3 vol.py -f dump.mem Windows.pslist → Process baseline
python3 vol.py -f dump.mem Windows.cmdline → ChromeSetup.exe (PID 4628) persistente
Razón: Installers legítimos auto-cierran post-instalación



### 2. **Network IOC Extraction**
python3 vol.py -f dump.mem Windows.netscan | grep 4628
→ C2 IP: 58.64.204.181 (Hong Kong)
Geolocalización confirmada via GeoDataTool



### 3. **Malware Sample Recovery**
python3 vol.py -f dump.mem Windows.dumpfiles --pid 4628
→ ChromeSetup.exe.img extraído exitosamente
SHA1: 280c9d36039f9432433893dee6126d72b9112ad2



### 4. **Threat Intelligence Enrichment**

VirusTotal Analysis:

├── Compilation: 2019-12-01 08:36

├── C2 Domain: dnsnb8.net (Relations → Contacted Domains)

└── Family: Ramnit (comportamiento + IOCs)



## 🔬 Herramientas Utilizadas

🔍 Memoria Forense

├── Volatility 3 → pslist, cmdline, netscan, dumpfiles

└── sha1sum → Hash calculation

🛡️ Threat Intelligence

├── VirusTotal → Sample analysis, timestamps, domains

└── WhatIsMyIPAddress → IP geolocation



## 📊 Lecciones Aprendidas

1. **Process Hunting**: `Windows.cmdline` > `pslist` para detectar persistence anómalo.
2. **PID Correlation**: Siempre filtrar netscan por PID sospechoso (`grep PID`).
3. **Memory Forensics Workflow**: Dump → Hash → VT Enrichment = IOCs accionables.

---

> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: Ramnit (Endpoint Forensics Category)*
