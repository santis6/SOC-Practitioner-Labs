# 🔍 3CX Supply Chain Lab WriteUp – Threat Intel (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: Una multinacional que depende de **3CX** para sus comunicaciones detecta alertas de antivirus esporádicas post-actualización, degradación de rendimiento y tráfico de red anómalo hacia servidores desconocidos.  
**Objetivo**: Examinar el posible ataque de supply chain sobre 3CX, identificar al threat actor responsable y evaluar el alcance total del incidente.  
**Herramientas**: VirusTotal.  
**Tácticas**: Persistence | Privilege Escalation | Defense Evasion | Discovery.

En el contenido del laboratorio nos entregan un archivo (3CXDesktopApp-18.12.416.msi) el cual usaremos para la investigación.

<img width="186" height="196" alt="11" src="https://github.com/user-attachments/assets/45119053-ca12-4ab6-8676-b5e68ab91bb3" />

----

Y un poco de info sobre como ocurren estas infecciones a nivel corporativos por el compromiso de la supply chain.

<img width="1280" height="720" alt="figure-03-2" src="https://github.com/user-attachments/assets/9ed91e04-67be-4acf-bda8-bcd0427ed982" />

----

### 📖 Contexto Previo

Antes de iniciar el análisis es importante entender qué es **3CX**. Se trata de un sistema telefónico empresarial basado en software (IP PBX) de estándares abiertos que ofrece una plataforma completa de comunicaciones unificadas, permitiendo realizar llamadas de voz, videollamadas, chat en vivo y videoconferencias a través de Internet. Al ser un componente crítico de las operaciones empresariales, su compromiso a nivel de supply chain representa un vector de ataque de altísimo impacto.

## 📋 Preguntas del Laboratorio & Respuestas

| Q1 | Understanding the scope of the attack and identifying which versions exhibit malicious behavior is crucial for making informed decisions if these compromised versions are present in the organization. How many versions of 3CX running on Windows have been flagged as malware?   
-

Teniendo en cuenta que ya sabemos el tipo de corporación y el sistema que usan, es cuestión de activar la inteligencia de amenazas y buscar información relevante en foros de seguridad y reportes vinculados a las vulnerabilidades asociadas a las versiones presentes. Investigando podemos confirmar que las versiones afectadas son **18.12.407** y **18.12.416**, ambas con comportamiento malicioso documentado.  

<img width="498" height="236" alt="1" src="https://github.com/user-attachments/assets/b19c209b-02b7-4236-b6c8-18ba8794615a" />


**R:** `2`

-----

| Q2 | Determining the age of the malware can help assess the extent of the compromise and track the evolution of malware families and variants. What's the UTC creation time of the .msi malware?   
-

Para facilitar el input en los motores de threat intel, extraemos el SHA256 del archivo malicioso proporcionado por el laboratorio mediante PowerShell:  
`Get-FileHash (Path al archivo) -Algorithm SHA256`  
Obteniendo el hash: `59E1EDF4D82FAE4978E97512B0331B7EB21DD4B838B850BA46794D9C7A2C0983`.  
Insertándolo en VirusTotal y navegando al apartado **Details → History**, podemos visualizar el **Creation Time** del archivo malicioso.  

<img width="640" height="186" alt="2" src="https://github.com/user-attachments/assets/8c891f15-c939-4aec-83a8-f691e3571368" />


**R:** `2023-03-13 06:33`

-----

| Q3 | Executable files (.exe) are frequently used as primary or secondary malware payloads, while dynamic link libraries (.dll) often load malicious code or enhance malware functionality. Analyzing files deposited by the Microsoft Software Installer (.msi) is crucial for identifying malicious files and investigating their full potential. Which malicious DLLs were dropped by the .msi file?   
-

En VirusTotal podemos corroborar que el archivo `.msi` malicioso deposita varios archivos durante su ejecución. Al analizar los **Dropped Files**, identificamos 2 DLLs como los payloads principales, diferenciados por poseer el mayor porcentaje de detección entre los motores de antivirus. Al verificar las categorías de detección de ambas, confirmamos que estos son los principales payloads inyectados en el sistema por parte del instalador malicioso.  

<img width="1001" height="369" alt="3" src="https://github.com/user-attachments/assets/0c72cdb2-7ea4-42a9-bccb-53b51cae5d87" />



**R:** `ffmpeg.dll, d3dcompiler_47.dll`

-----

| Q4 | Recognizing the persistence techniques used in this incident is essential for current mitigation strategies and future defense improvements. What is the MITRE Technique ID employed by the .msi files to load the malicious DLL?   
-

Continuando con la temática de Threat Intelligence, buscamos un mapeo de las TTPs MITRE ATT&CK empleadas en el ataque. Encontramos un reporte bien estructurado y completo que detalla el **MITRE TID Mapping** del incidente, donde se confirma que la técnica empleada para cargar la DLL maliciosa es **DLL Side-Loading**, una técnica donde un ejecutable legítimo es manipulado para cargar una DLL maliciosa en su lugar.  

<img width="1019" height="754" alt="4" src="https://github.com/user-attachments/assets/1d64fd7f-f3c9-4fd5-b785-de14dc28e264" />



**R:** `T1574`

-----

| Q5 | Recognizing the malware type (threat category) is essential to your investigation, as it can offer valuable insight into the possible malicious actions you'll be examining. What is the threat category of the two malicious DLLs?   
-

Al revisar los reportes individuales de las 2 DLLs maliciosas en VirusTotal, vemos que ambas se encuentran categorizadas de forma consistente por los motores de detección como **Trojan**.  

<img width="1919" height="990" alt="5" src="https://github.com/user-attachments/assets/02af2b87-c276-44d4-98b4-0d019492a7ae" />

<img width="1919" height="989" alt="6" src="https://github.com/user-attachments/assets/60ac348a-2088-4390-bc62-7e3ef0fa39fc" />


**R:** `Trojan`

-----

| Q6 | As a threat intelligence analyst conducting dynamic analysis, it's vital to understand how malware can evade detection in virtualized environments or analysis systems. This knowledge will help you effectively mitigate or address these evasive tactics. What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?   
-

Retomando el reporte del MITRE TID Mapping identificado en Q4, navegamos hasta la sección correspondiente a técnicas de evasión de entornos virtualizados y de análisis, donde encontramos la TID directamente relacionada con **Virtualization/Sandbox Evasion**.  

<img width="971" height="580" alt="7" src="https://github.com/user-attachments/assets/3cee1ea6-7a4b-47a6-918f-c0b4c5b79b30" />



**R:** `T1497`

-----

| Q7 | When conducting malware analysis and reverse engineering, understanding anti-analysis techniques is vital to avoid wasting time. Which hypervisor is targeted by the anti-analysis techniques in the ffmpeg.dll file?  
-


En VirusTotal, en el apartado **Behavior** del análisis de `ffmpeg.dll`, podemos ver las **capabilities** detalladas del DLL malicioso. Aquí se expone claramente el hipervisor objetivo de las técnicas anti-análisis implementadas por el malware.  


<img width="453" height="304" alt="8" src="https://github.com/user-attachments/assets/54e6eb7b-cf5a-4773-aed2-2f1c50068e23" />



**R:** `VMware`

-----

| Q8 | Identifying the cryptographic method used in malware is crucial for understanding the techniques employed to bypass defense mechanisms and execute its functions fully. What encryption algorithm is used by the ffmpeg.dll file?  
-


En el apartado de comportamiento del análisis de `ffmpeg.dll`, dentro de la sección de **Cryptography**, podemos ver que el malware hace uso de **RC4** para encriptar el payload malicioso, dificultando su análisis estático y evadiendo firmas basadas en strings en texto plano.  


<img width="732" height="658" alt="9" src="https://github.com/user-attachments/assets/ba800fb9-c19b-4fbe-a9e5-ede42f08ced7" />



**R:** `RC4`

-----

| Q9 | As an analyst, you've recognized some TTPs involved in the incident, but identifying the APT group responsible will help you search for their usual TTPs and uncover other potential malicious activities. Which group is responsible for this attack?  
-


Para la atribución del ataque podemos consultar el artículo de Qualys referenciado en los reportes del incidente, o bien revisar la sección **Community** en VirusTotal sobre los archivos maliciosos analizados. Ambas fuentes atribuyen de forma consistente el ataque al grupo APT **Lazarus**, actor de amenazas patrocinado por el Estado norcoreano con historial documentado de ataques de supply chain de alto perfil.  


<img width="1919" height="874" alt="10" src="https://github.com/user-attachments/assets/13339241-d0ee-4517-9b52-0c0d5483b2f4" />



**R:** `Lazarus`

-----



## 🛡️ Proceso de CTI (Cyber Threat Intelligence)

### 1. **Identificación del Scope del Ataque**

Versiones comprometidas: 18.12.407 y 18.12.416

SHA256 MSI: 59E1EDF4D82FAE4978E97512B0331B7EB21DD4B838B850BA46794D9C7A2C0983

Tipo: Supply Chain Attack sobre instalador oficial de 3CX



### 2. **Análisis de Artefactos Maliciosos**

Instalador: 3CXDesktopApp.msi (creation: 2023-03-13 06:33)

Dropped DLLs:

├── ffmpeg.dll → Trojan (RC4 encryption, VMware detection)

└── d3dcompiler_47.dll → Trojan (DLL Side-Loading payload)



### 3. **Análisis de Comportamiento y Evasión**

DLL Side-Loading: Ejecutable legítimo 3CX carga DLLs maliciosas (T1574)

Sandbox Evasion: Anti-VM checks targeting VMware (T1497)

Encryption: RC4 para ofuscación del payload malicioso



### 4. **Threat Intelligence y Atribución**

MITRE Mapping: T1574 (Side-Loading) + T1497 (Sandbox Evasion)

APT Group: Lazarus Group (DPRK-linked)

Fuentes: VirusTotal Community, Qualys Threat Report



## 🎯 MITRE ATT&CK Mapping

| Táctica | Técnica | ID | Descripción Observada |
|---------|---------|----|-----------------------|
| Initial Access | Supply Chain Compromise | T1195.002 | Compromiso del instalador oficial de 3CX |
| Persistence | Hijack Execution Flow: DLL Side-Loading | T1574.002 | `ffmpeg.dll` y `d3dcompiler_47.dll` cargadas por ejecutable legítimo |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | Anti-análisis targeting VMware en `ffmpeg.dll` |
| Defense Evasion | Obfuscated Files or Information | T1027 | Payload encriptado con RC4 |
| Discovery | Software Discovery | T1518 | Fingerprinting del entorno de ejecución previo a payload |


## 🔬 Herramientas Utilizadas

🛡️ Threat Intelligence

├── VirusTotal → Hash analysis, dropped files, behavior, community

├── PowerShell → SHA256 extraction (Get-FileHash)

└── Qualys Threat Report → MITRE TID Mapping, APT attribution



## 📊 Lecciones Aprendidas

1. **Supply Chain Awareness**: Validar integridad de instaladores legítimos con hash verification antes de cualquier deployment organizacional.
   
2. **DLL Side-Loading Detection**: Monitorear DLLs cargadas por procesos confiables contra un baseline conocido y verificado.
  
3. **APT Attribution Value**: Identificar el grupo responsable (Lazarus) permite anticipar TTPs adicionales y buscar proactivamente IOCs relacionados en la red.

---

> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: 3CX Supply Chain (Threat Intel Category)*
