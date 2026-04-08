# 🔍 Insider Lab WriteUp – Endpoint Forensics (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: Karen, empleada de TAAUSAI, es sospechosa de realizar actividades ilegales dentro de la organización. Se dispone de una imagen forense de disco de su workstation Linux para análisis.  
**Objetivo**: Analizar la imagen de disco para reconstruir las acciones del usuario, identificar herramientas maliciosas descargadas, archivos creados y actividad de escalación de privilegios.  
**Herramientas**: FTK Imager.  
**Tácticas**: Execution | Credential Access.

### 📖 Herramienta Principal – FTK Imager

Para el análisis de la imagen de disco se utiliza **FTK Imager**, una herramienta ampliamente utilizada en el ámbito de la informática forense. Su función principal es crear, analizar y examinar imágenes forenses de discos de almacenamiento, realizando copias **bit a bit** de discos duros, unidades USB, tarjetas de memoria y otros medios sin alterar los datos originales, garantizando así la **integridad de la evidencia** (cadena de custodia). En este laboratorio inyectaremos el archivo `.ad1` proporcionado para su análisis.

## 📋 Preguntas del Laboratorio & Respuestas

| Q1 | Which Linux distribution is being used on this machine? 
-

Para identificar la distribución Linux del sistema analizamos múltiples rutas que contienen metadata del sistema operativo. La primera opción es revisar la carpeta `/boot/`, donde los archivos del kernel frecuentemente incluyen información sobre la versión y distribución cargada durante el booteo. Como alternativa complementaria, el archivo `grub.cfg` también expone información relevante sobre la distro. Finalmente, una tercera fuente confiable es el archivo `syslog` ubicado en `/var/log/installer/`, el cual es generado automáticamente durante la instalación del sistema operativo y contiene información detallada sobre la distribución instalada. Cualquiera de estas fuentes confirma la distribución utilizada por Karen en su workstation.  

<img width="1919" height="1031" alt="1" src="https://github.com/user-attachments/assets/6ce6484d-266e-4f70-a405-540a34dc166d" />



**R:** `Kali Linux`

-----

| Q2 | What is the MD5 hash of the Apache access.log file? 
-

Para calcular el hash MD5 del archivo `access.log` de Apache contamos con tres métodos válidos:  
**Método 1**: Exportar el archivo a la máquina host (Windows) y calcular el hash con PowerShell:  
`Get-FileHash (path al archivo) -Algorithm MD5`  
**Método 2**: Utilizar la funcionalidad nativa de FTK Imager de exportar hashes en formato `.csv`, los cuales pueden ser examinados directamente.  
**Método 3**: Seleccionar el archivo en FTK Imager y visualizar el hash en el panel inferior izquierdo de propiedades del archivo. El valor hash resultante corresponde al hash MD5 de un archivo vacío, lo que es consistente con la ausencia de registros en el archivo `access.log`, confirmando que Apache nunca fue ejecutado (relevante para Q7). 

<img width="1712" height="38" alt="2" src="https://github.com/user-attachments/assets/ca14b408-c609-4804-a8d1-9e1e0be75e93" />


<img width="1919" height="1031" alt="1 1" src="https://github.com/user-attachments/assets/1985fc5c-5035-4788-b1dc-136937aa8def" />

**R:** `d41d8cd98f00b204e9800998ecf8427e`

-----

| Q3 | It is suspected that a credential dumping tool was downloaded. What is the name of the downloaded file? 
-

Navegando directamente a la carpeta `Downloads` del usuario `root` (`/root/Downloads/`), encontramos un archivo `.zip` que corresponde a **Mimikatz**, una herramienta de código abierto ampliamente conocida en el ámbito ofensivo. Mimikatz está diseñada principalmente para extraer credenciales en texto plano, hashes NTLM, PINs y tickets Kerberos directamente desde la memoria de sistemas Windows comprometidos. Su presencia en el sistema de Karen es un indicador claro de intención de credential dumping sobre otros sistemas de la red. 

<img width="1919" height="1033" alt="3" src="https://github.com/user-attachments/assets/0665a7fa-0120-40bd-9c78-1dabc4c50392" />


**R:** `mimikatz_trunk.zip`


-----

| Q4 | A super-secret file was created. What is the absolute path to this file? 
-

El análisis del archivo `.bash_history` ubicado en `/root/.bash_history` nos permite reconstruir cronológicamente los comandos ejecutados por el usuario en sus sesiones de terminal. Este archivo registra el historial completo de comandos ejecutados una vez que la sesión de terminal es cerrada. En su contenido, podemos observar que Karen utiliza el comando `touch` combinado con redirección de output (`>`) para crear un archivo en la ruta `/root/Desktop/SuperSecretFile.txt`, constituyendo esta la ruta absoluta del archivo sospechoso.  

<img width="1919" height="1032" alt="4" src="https://github.com/user-attachments/assets/029196a9-f756-412c-b22c-30a99d29991f" />


**R:** `/root/Desktop/SuperSecretFile.txt`



-----

| Q5 | What program used the file didyouthinkwedmakeiteasy.jpg during its execution? 
-

Continuando el análisis del archivo `.bash_history`, encontramos una entrada que referencia el archivo `didyouthinkwedmakeiteasy.jpg` siendo procesado por **binwalk**. Esta herramienta es utilizada en análisis forense y reversing, diseñada específicamente para escanear, identificar y extraer archivos embebidos dentro de binarios y firmwares. Su uso sobre un archivo `.jpg` es indicativo de esteganografía o análisis de archivos con datos ocultos embebidos, una técnica frecuentemente empleada para ocultar payloads maliciosos dentro de imágenes aparentemente legítimas. 


<img width="1918" height="1030" alt="5" src="https://github.com/user-attachments/assets/08588095-df75-4481-8b7f-2d7b2d414c41" />



**R:** `binwalk`



-----

| Q6 | What is the third goal from the checklist Karen created? 
-

En el directorio `/root/Desktop/` localizamos un archivo denominado `Checklist`. Al examinar su contenido, podemos ver que Karen documentó tres objetivos planificados para su actividad maliciosa dentro de la organización. El tercer y último ítem de dicho listado revela la motivación final de sus acciones.  

<img width="1919" height="1030" alt="6" src="https://github.com/user-attachments/assets/2323a598-cdaa-446a-8833-a406f774f4ef" />


**R:** `profit`



-----

| Q7 | How many times was Apache run? 
-

Para determinar la cantidad de ejecuciones del servidor Apache, navegamos a su directorio de logs en `/var/log/apache2/`. Al examinar los tres archivos `.log` presentes (`access.log`, `error.log`, `other_vhosts_access.log`), encontramos que todos se encuentran completamente vacíos, sin ningún registro de actividad. Esto es consistente con el hash MD5 obtenido en Q2 (`d41d8cd98f00b204e9800998ecf8427e`), que corresponde exactamente al hash de un archivo vacío en cualquier sistema, confirmando que Apache nunca fue iniciado en esta máquina.  

<img width="1919" height="1031" alt="7" src="https://github.com/user-attachments/assets/03df5e8e-b6b9-4fc5-946d-783ee1ef99b8" />



**R:** `0`



-----

| Q8 | This machine was used to launch an attack on another. Which file contains the evidence for this? 
-

En el directorio del usuario `root` localizamos un archivo de imagen `.jpeg`. Al exportarlo a nuestra máquina host y visualizarlo, podemos observar que la imagen captura un escritorio con una interfaz de línea de comandos ejecutando **Flightsim**, una utilidad diseñada para generar patrones de tráfico de red malicioso con fines de auditoría. Esta herramienta simula tráfico de túnel DNS, tráfico DGA (Domain Generation Algorithm), solicitudes a servidores C2 activos y otros patrones de red sospechosos. La presencia de esta imagen constituye evidencia directa de que la máquina de Karen fue utilizada para lanzar ataques simulados contra la infraestructura de red de la organización.  

<img width="1318" height="300" alt="8" src="https://github.com/user-attachments/assets/79f5e163-2c52-4a60-8cbd-04fe53ee2548" />

----
![evidence](https://github.com/user-attachments/assets/e4144317-79f8-421b-9308-63bdf4067f06)

**R:** `irZLAohL.jpeg`



-----

| Q9 | It is believed that Karen was taunting a fellow computer expert through a bash script within the Documents directory. Who was the expert that Karen was taunting? 
-

Analizando el script Bash presente en la carpeta `/root/Documents/`, podemos ver que Karen desarrolló un script con las siguientes funciones operativas:  
1. Mostrar el directorio de trabajo actual (`pwd`).  
2. Mostrar todas las rutas, puertas de enlace e interfaces configuradas en el sistema (`ip route`).  
3. Mostrar conexiones establecidas y filtrar específicamente las relacionadas al puerto 80 (`netstat | grep --color 80`).  

Al final del script, Karen incluye un mensaje dirigido explícitamente a un compañero: `"Heck yeah! I can write bash too Young"`, revelando así el nombre del experto al que intentaba intimidar o provocar.  

<img width="1919" height="1030" alt="9" src="https://github.com/user-attachments/assets/83037076-3a1c-4980-8c13-181b51d91be0" />


**R:** `Young`



-----

| Q10 | A user executed the su command to gain root access multiple times at 11:26. Who was the user? 
-

Para esta investigación navegamos hasta el directorio centralizado de logs del sistema `/var/log/` y examinamos específicamente el archivo `auth.log`, el cual registra todos los eventos de autenticación, autorización y escalación de privilegios del sistema. Analizando las entradas correspondientes a las **11:26**, encontramos que el usuario **postgres** ejecuta reiteradamente el comando `su` para obtener acceso con privilegios root. Esto es especialmente relevante desde una perspectiva de seguridad, ya que si PostgreSQL está configurado para correr como root (mala práctica de hardening), puede ser abusado para ejecutar comandos arbitrarios del sistema operativo con máximos privilegios.  

<img width="1919" height="1030" alt="10" src="https://github.com/user-attachments/assets/84734ccb-16c0-414b-a218-791d79072737" />


**R:** `postgres`



-----

| Q11 | Based on the bash history, what is the current working directory? 
-

Realizando un análisis completo y cronológico del archivo `.bash_history` en `/root/.bash_history`, podemos observar el patrón de navegación del sistema de Karen. Se evidencia claramente que el atacante realiza un `cd` hacia el directorio `/root/Documents/myfirsthack/`, y es desde esa ubicación desde donde ejecuta la totalidad de los comandos posteriores registrados en el historial, estableciéndola como el directorio de trabajo activo al momento del análisis.

<img width="1919" height="1032" alt="11" src="https://github.com/user-attachments/assets/79cb80a3-1314-4a27-ad8f-02ab720b2778" />


**R:** `/root/Documents/myfirsthack/`

-----

## 🛡️ Proceso de Análisis y Vista General

### 1. **Reconocimiento del Sistema**

/boot/ + grub.cfg + /var/log/installer/syslog

→ Distribución identificada: Kali Linux

→ Sistema orientado a operaciones ofensivas



### 2. **Análisis de Artefactos Maliciosos**

/root/Downloads/mimikatz_trunk.zip → Credential dumping tool

/root/Desktop/SuperSecretFile.txt → Archivo creado vía touch

/root/Documents/myfirsthack/ → Working directory del ataque

irZLAohL.jpeg → Evidencia visual de uso de Flightsim



### 3. **Reconstrucción de Actividad via Bash History**

/root/.bash_history timeline:

├── cd /root/Documents/myfirsthack/

├── touch /root/Desktop/SuperSecretFile.txt

├── binwalk didyouthinkwedmakeiteasy.jpg

└── Ejecución de script con mensaje a "Young"



### 4. **Análisis de Logs de Autenticación**

/var/log/auth.log → 11:26

Usuario: postgres → múltiples ejecuciones de su

Riesgo: PostgreSQL corriendo como root (misconfiguration)

Apache logs: vacíos → d41d8cd98f00b204e9800998ecf8427e (MD5 archivo vacío)



## 🎯 MITRE ATT&CK Mapping

| Táctica | Técnica | ID | Descripción Observada |
|---------|---------|----|-----------------------|
| Credential Access | OS Credential Dumping | T1003 | Descarga de `mimikatz_trunk.zip` en `/root/Downloads/` |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Script Bash malicioso en `/root/Documents/` |
| Privilege Escalation | Abuse Elevation Control Mechanism: Sudo and su | T1548.003 | Usuario `postgres` ejecuta `su` reiteradamente a las 11:26 |
| Discovery | System Network Configuration Discovery | T1016 | Script ejecuta `ip route` y `netstat` para mapear la red |
| Execution | User Execution | T1204 | Uso de `binwalk` sobre imagen `.jpg` para extraer datos embebidos |
| Impact | Network Denial of Service / Traffic Generation | T1498 | Uso de Flightsim para generar tráfico malicioso simulado |

## 🔬 Herramientas Utilizadas

🔍 Forense de Disco

├── FTK Imager → Análisis de imagen .ad1, exportación de archivos y hashes

└── PowerShell → Get-FileHash para cálculo MD5/SHA

📂 Artefactos Analizados

├── /root/.bash_history → Reconstrucción cronológica de actividad

├── /var/log/auth.log → Eventos de autenticación y escalación

├── /var/log/apache2/*.log → Estado de ejecución de Apache

└── /root/Desktop/Checklist → Objetivos planificados del atacante



## 📊 Lecciones Aprendidas

1. **Bash History como Evidencia Forense**: El archivo `.bash_history` es una de las fuentes más valiosas en forense Linux, permitiendo reconstruir cronológicamente las acciones del usuario con alto nivel de detalle.
2. **Privilegios de Servicios**: Ejecutar servicios como PostgreSQL con privilegios root es una misconfiguration crítica que puede ser abusada para escalación de privilegios lateral.
3. **Presencia de Kali Linux en Endpoints Corporativos**: La existencia de Kali Linux en la workstation de un empleado sin rol de seguridad justificado es una red flag inmediata que debería generar alertas en cualquier entorno SOC.

---

> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: Insider (Endpoint Forensics Category)*
