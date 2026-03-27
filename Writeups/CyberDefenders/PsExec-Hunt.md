# 🔍 PsExec Hunt Lab WriteUp – Network Forensics (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: El IDS alertó actividad sospechosa de lateral movement mediante PsExec. El objetivo es rastrear las actividades del atacante, identificar el punto de entrada, las máquinas comprometidas y los indicadores clave de sus tácticas.  
**Objetivo**: Analizar archivo PCAP con Wireshark para identificar movimiento lateral via PsExec, sistemas comprometidos, credenciales y shares administrativos utilizados.  
**Herramientas**: Wireshark.  
**Tácticas**: Execution | Defense Evasion | Discovery | Lateral Movement.

El escenario nos presenta un archivo `.PCAP` el cual analizaremos para dar con las respuestas del laboratorio.

### 📖 Conceptos Previos

Antes de iniciar cualquier tipo de análisis, es importante comprender qué es **PsExec** y cómo funciona el protocolo **SMB**, ya que son los pilares de este escenario.

**PsExec** es una utilidad de línea de comandos de Microsoft Sysinternals que permite a los administradores ejecutar procesos de forma remota en máquinas de una red sin instalar software adicional, utilizando credenciales de administrador.

**Complemento con SMB**: La herramienta se integra nativamente con el protocolo **Server Message Block (SMB)**, específicamente en los puertos TCP **445** (y tradicionalmente **139**), para establecer canales de comunicación. Este protocolo permite copiar el archivo ejecutable `PSEXESVC.exe` (un servicio de Windows) al recurso compartido administrativo oculto **ADMIN$** del sistema remoto, donde se instala y ejecuta para procesar los comandos. Además, utiliza **Named Pipes** y llamadas **MSRPC** (como SVCCTL) para gestionar el inicio del servicio, redirigir la entrada/salida de consola, y eliminar el ejecutable al finalizar la tarea.

## 📋 Preguntas del Laboratorio & Respuestas

| Q1 | To effectively trace the attacker's activities within our network, can you identify the IP address of the machine from which the attacker initially gained access?
-

Como primeras instancias de análisis siempre recomiendo revisar **Statistics → Conversations**, ya que aquí podemos encontrar información relevante acerca del escenario general que estamos observando. En este caso podemos ver un gran volumen de intercambio de datos entre 2 IPs.  

<img width="1359" height="720" alt="1" src="https://github.com/user-attachments/assets/84cb6e3b-8629-406a-8898-b64e8a6ed125" />


Aplicando el filtro:  

`ip.src == (ip sospechosa) && smb2`  

Podemos ver claramente el inicio de la conversación: **Create Request**, **File PSEXECSVC.EXE**, la creación del archivo `.key`, y demás información que confirma el origen del ataque. 

<img width="1359" height="143" alt="1 1" src="https://github.com/user-attachments/assets/c733cb89-926b-4e22-adfe-61598ec96572" />


**R:** `10.0.0.130`


---



| Q2 | To fully understand the extent of the breach, can you determine the machine's hostname to which the attacker first pivoted?  
-


Siguiendo la conversación identificada previamente, podemos visualizar directamente el nombre del host objetivo. También podemos aplicar un **Follow → TCP Stream** sobre los paquetes SMB relevantes y ver en texto claro el nombre del host al que el atacante realizó el pivoting.  

<img width="1359" height="720" alt="4" src="https://github.com/user-attachments/assets/2b70021f-082b-4906-a677-bc9b3cb0ed43" />


**R:** `Sales-PC`


---

| Q3 | What is the username utilized by the attacker for authentication?   
-

En el mismo TCP Stream de la respuesta anterior, podemos ver claramente el usuario ingresado por el atacante para autenticarse contra el host objetivo, expuesto en texto claro dentro de los paquetes de negociación NTLM.  

<img width="1358" height="719" alt="3" src="https://github.com/user-attachments/assets/aa286e4d-6720-4a8c-980e-80b9266fd280" />


**R:** `ssales`


---

| Q4 | What's the name of the service executable the attacker set up on the target?   
-

Como mencionamos al inicio del laboratorio en el análisis del funcionamiento de PsExec, esta herramienta instala en el host objetivo el servicio `PSEXESVC.exe` para poder ejecutar comandos de forma remota. Esto se confirma en la conversación SMB capturada, donde vemos un **Create Request, File: PSEXESVC.exe** dirigido al sistema comprometido.  

<img width="1359" height="720" alt="5" src="https://github.com/user-attachments/assets/a015f3e3-a366-4677-a110-361bee8f24eb" />


**R:** `PSEXESVC`


---

| Q5 | Which network share was used by PsExec to install the service on the target machine?   
-

En la misma conversación inicial entre atacante y objetivo, dentro del **Create Request**, podemos ver claramente que el archivo `PSEXESVC.exe` es creado en el share **ADMIN$**, lo cual se alinea perfectamente con el comportamiento documentado y esperado de PsExec para instalar su servicio de forma remota.  


<img width="1359" height="719" alt="6" src="https://github.com/user-attachments/assets/388afcec-5bfa-40bc-b327-b737bfc6028e" />


**R:** `ADMIN$`



---

| Q6 | Which network share did PsExec use for communication?  
-

Previo a la conexión con el share **ADMIN$**, podemos observar claramente en el flujo de paquetes cómo el atacante establece primero una conexión al share **IPC$** antes de iniciar el intercambio principal. Este share es utilizado por PsExec para establecer el canal de comunicación via Named Pipes y llamadas MSRPC.  

<img width="1359" height="100" alt="7" src="https://github.com/user-attachments/assets/9240fc73-151f-4c66-b4d9-0005f7cacb9b" />


**R:** `IPC$`


---

| Q7 | What is the hostname of the second machine the attacker targeted to pivot within our network?  
-


Para identificar el segundo objetivo del atacante, podemos filtrar directamente los **NTLM Challenges** en Wireshark y analizar las requests realizadas mediante **Follow → TCP Stream**, donde veremos que el atacante replicó exactamente el mismo método de acceso. Alternativamente, filtrando por paquetes SMB podemos identificar otro intento de comunicación con un host distinto de la red, al cual también podemos aplicar **Follow → TCP Stream** para extraer el hostname solicitado.  


<img width="1359" height="719" alt="8" src="https://github.com/user-attachments/assets/222a4dd6-19c0-4944-bfd3-86f01eefa080" />


**R:** `Marketing-PC`


## 🛡️ Proceso de CTI (Cyber Threat Intelligence)

### 1. **Reconocimiento del Tráfico de Red**

Wireshark → Statistics → Conversations

→ Volume de datos anómalo entre 10.0.0.130 y hosts internos

Filtro aplicado: ip.src == 10.0.0.130 && smb2




### 2. **Identificación del Movimiento Lateral**

PsExec Execution Flow observado:

10.0.0.130 → Sales-PC (ADMIN$) → PSEXESVC.exe instalado

10.0.0.130 → Marketing-PC → Mismo método replicado

Autenticación: NTLM con credenciales ssales



### 3. **Shares y Canales de Comunicación**

IPC$ → Canal inicial (Named Pipes / MSRPC / SVCCTL)

ADMIN$ → Instalación de PSEXESVC.exe

Protocolo: SMB2 sobre TCP 445



### 4. **Lateral Movement Timeline**

Pivot 1: 10.0.0.130 → Sales-PC (user: ssales)

Pivot 2: 10.0.0.130 → Marketing-PC (mismo método)

IOC: PSEXESVC.exe en ADMIN$ de ambos hosts



## 🔬 Herramientas Utilizadas

🔍 Análisis de Red

├── Wireshark → PCAP analysis, SMB2 filtering

├── Statistics → Conversations (traffic overview)

└── Follow TCP Stream → Cleartext credential extraction

## 🎯 MITRE ATT&CK Mapping

| Táctica | Técnica | ID | Descripción Observada |
|---------|---------|----|-----------------------|
| Execution | Remote Services: SMB/Windows Admin Shares | T1021.002 | PsExec ejecuta comandos remotos via SMB/ADMIN$ |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | Pivoting de Sales-PC a Marketing-PC |
| Defense Evasion | Use Alternate Authentication Material | T1550 | Reutilización de credenciales NTLM (ssales) |
| Discovery | Network Share Discovery | T1135 | Enumeración de shares IPC$ y ADMIN$ |
| Execution | System Services: Service Execution | T1569.002 | PSEXESVC.exe instalado como servicio remoto |
| Credential Access | Brute Force: Password Spraying | T1110.003 | Autenticación NTLM con credenciales comprometidas |

## 📊 Lecciones Aprendidas

1. **Statistics → Conversations** es el primer paso para identificar hosts con volumen de tráfico anómalo en cualquier PCAP.
2. **PsExec Detection**: Monitorear creación de `PSEXESVC.exe` en `ADMIN$` + tráfico SMB2 sobre TCP 445 entre hosts internos.
3. **NTLM Challenges**: Seguir TCP Streams de autenticación NTLM para extraer credenciales y hostnames comprometidos.

---

> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: PsExec Hunt (Network Forensics Category)*
