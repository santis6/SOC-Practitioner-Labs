# 🔍 Silent Breach Lab WriteUp – Endpoint Forensics (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: La IMF sufre un ciberataque que compromete datos sensibles. Ethan descarga información de un servidor comprometido que posteriormente se vuelve ilegible. Para recuperarla, crea una imagen forense y solicita ayuda para decodificar los archivos afectados.  
**Objetivo**: Analizar la imagen forense para extraer artefactos de comunicación, identificar comportamiento malicioso y descifrar archivos encriptados por un ransomware dirigido.  
**Herramientas**: FTK Imager, Text Editor, SQLite Viewer, Strings, CyberChef.  
**Táctica**: Execution.

El laboratorio provee un archivo `.ad1` (imagen forense del host de Ethan) para análisis con FTK Imager.

## 📋 Preguntas del Laboratorio & Respuestas

| Q1 | What is the MD5 hash of the potentially malicious EXE file the user downloaded? 
-

Una vez inyectado el archivo `.ad1` en FTK Imager, navegamos directamente a la carpeta `Downloads` del usuario para examinar las descargas realizadas. En su contenido encontramos un archivo que presenta una **doble extensión** (`.pdf.exe`), una red flag altamente relevante desde el punto de vista forense, ya que es una técnica clásica de ofuscación del tipo de archivo real con el objetivo de engañar al usuario haciéndolo creer que se trata de un documento PDF legítimo. Para extraer el hash MD5 del archivo, lo seleccionamos en FTK Imager y visualizamos sus propiedades en el panel inferior izquierdo, donde el hash MD5 es calculado y mostrado directamente por la herramienta.  

<img width="1005" height="1030" alt="1" src="https://github.com/user-attachments/assets/edb535db-8b60-47bf-92f2-49bb9976dfc9" />

**R:** `336a7cf476ebc7548c93507339196abb`

-----

| Q2 | What is the URL from which the file was downloaded?  
-

La URL de descarga del archivo malicioso se encuentra en el archivo `Zone.Identifier` asociado al ejecutable. Es importante comprender la función de este archivo: **Zone.Identifier** es un metadato de seguridad que Windows crea automáticamente para rastrear el origen y la zona de seguridad de cualquier archivo descargado desde Internet. Funciona como una **"Mark of the Web" (MotW)**, permitiendo al sistema operativo aplicar advertencias de seguridad como bloquear la ejecución automática de scripts o activar SmartScreen. Los archivos provenientes de Internet reciben `ZoneId=3`, que es precisamente el valor presente en este caso, confirmando que el archivo fue descargado desde una fuente externa. El contenido del `Zone.Identifier` expone la URL completa de origen.  

<img width="1048" height="544" alt="2" src="https://github.com/user-attachments/assets/1b8f7ad5-dbc5-48d5-8bcf-f3ad92455397" />


**R:** `http://192.168.16.128:8000/IMF-Info.pdf.exe`

-----

| Q3 | What application did the user use to download this file?  
-

Para identificar el navegador utilizado en la descarga, realizamos un análisis comparativo de los historiales de los navegadores instalados en el sistema (Chrome y Edge). Es importante tener en cuenta que todos los navegadores modernos almacenan su historial de navegación en **bases de datos SQLite**, las cuales pueden ser analizadas con herramientas como **DB Browser for SQLite** o **SQLite Viewer**. Las rutas de los historiales son las siguientes:  
- Chrome: `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History`  
- Edge: `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\History`  

Al abrir el historial de **Chrome** con DB Browser for SQLite, la única descarga registrada corresponde al instalador de **TeamViewer**, descartando este navegador como origen. En cambio, al analizar el historial de **Microsoft Edge**, podemos ver claramente múltiples descargas registradas, incluyendo de forma explícita el archivo malicioso `IMF-Info.pdf.exe`, confirmando así el navegador utilizado.  

<img width="1919" height="608" alt="3" src="https://github.com/user-attachments/assets/12298d37-097c-4ad7-9a2e-052847ce1474" />

<img width="1919" height="609" alt="3 1" src="https://github.com/user-attachments/assets/f68aa84e-4958-460e-bfb0-df7eead40efc" />


**R:** `Microsoft Edge`

-----

| Q4 | By examining Windows Mail artifacts, we found an email address mentioning three IP addresses of servers that are at risk or compromised. What are the IP addresses?  
-

El proceso de análisis para esta pregunta involucra múltiples etapas. En primer lugar, examinamos el archivo **NTUSER.DAT** del usuario `ethan`. Este es el archivo del registro de Windows específico de cada usuario: cuando el usuario inicia sesión, Windows carga este archivo y lo mapea a la rama `HKEY_CURRENT_USER` del registro, y al cerrar sesión todos los cambios se persisten nuevamente en él. Desde la perspectiva forense, es una fuente extremadamente valiosa ya que contiene el historial detallado de la actividad del usuario en la sesión.

Exportamos el archivo desde la imagen y lo procesamos con **RegRipper**, dirigiendo el output hacia un archivo `Reporte.txt` para su análisis. Dentro del reporte buscamos específicamente la clave **UserAssist**, que es el mecanismo que Windows utiliza para registrar qué aplicaciones con interfaz gráfica ejecutó el usuario, cuántas veces y cuándo fue la última ejecución. Encontramos la siguiente entrada relevante:

`2025-02-09 22:26:14Z`

`microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail → 16 ejecuciones`


Esto confirma el uso frecuente de **Windows Mail** por parte del usuario. El siguiente paso es localizar y analizar el archivo **HxStore.hxd**, que es el archivo propietario de Windows Mail utilizado para almacenar los datos de correos electrónicos en caché localmente. Este archivo se encuentra en:  
`C:\Users\ethan\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\HxStore.hxd`

Una vez exportado, lo introducimos en **CyberChef** mediante la opción `Open file as input`. Aplicamos la receta `Extract IP Addresses` con la opción `Unique` habilitada para eliminar duplicados del output. El resultado expone las tres IPs mencionadas en los correos electrónicos cacheados localmente.  
<img width="1919" height="506" alt="4" src="https://github.com/user-attachments/assets/4a56f69a-bdce-4d51-9ef7-722bd323503f" />

<img width="1919" height="656" alt="4 1" src="https://github.com/user-attachments/assets/a8fb7a43-b78b-485c-ba74-1851a43263c0" />


**R:** `145.67.29.88, 212.33.10.112, 192.168.16.128`

-----

| Q5 | By examining the malicious executable, we found that it uses an obfuscated PowerShell script to decrypt specific files. What predefined password does the script use for encryption? 
-

Para analizar el contenido del ejecutable malicioso sin ejecutarlo, lo extraemos de la imagen del disco y lo introducimos en **CyberChef** mediante `Open file as input`. Aplicamos la receta `Strings` para extraer todas las cadenas de texto legibles del binario y buscamos en el output la palabra clave `PowerShell`, encontrando un **payload claramente ofuscado**. 

Introducimos dicho payload en CyberChef para identificar el método de ofuscación. Tras probar distintas combinaciones, la receta correcta resulta ser **Reverse + From Base64**, la cual decodifica exitosamente el script, revelando un **ransomware dirigido específicamente a dos archivos concretos del sistema de Ethan**. Esto indica que el atacante realizó un reconocimiento previo del endpoint antes de desplegar el malware, seleccionando manualmente los archivos de mayor valor. En la primera línea del script decodificado se puede observar la **contraseña hardcodeada** utilizada para la encriptación de los archivos objetivo.  

<img width="1538" height="923" alt="5" src="https://github.com/user-attachments/assets/7085e74c-4b58-4a80-bb4b-646c107d33ac" />

<img width="1680" height="923" alt="5 1" src="https://github.com/user-attachments/assets/04e4b21d-8a5b-4496-b38c-919dfe1a9b4e" />


**R:** `Imf!nfo#2025Sec$`

-----

| Q6 | After identifying how the script works, decrypt the files and submit the secret string. 
-

Con el funcionamiento completo del script ransomware identificado (algoritmo de cifrado, contraseña hardcodeada y archivos objetivo), procedemos a pedirle a nuestra IA de confianza un **script decrypter** basado en la lógica inversa del payload analizado.

Al ejecutar el proceso de descifrado sobre los archivos encriptados, podemos corroborar que los mismos contienen **información claramente confidencial de la IMF**, lo que confirma que el ataque fue meticulosamente dirigido contra activos de alto valor. Al examinar el contenido del archivo `IMF-Mission.pdf` descifrado, encontramos al final del documento la **flag** que confirma la resolución exitosa del laboratorio.

<img width="1265" height="718" alt="6" src="https://github.com/user-attachments/assets/76658b9d-df08-4374-8d2a-ea8d9da0a3fb" />

<img width="1919" height="952" alt="6 1" src="https://github.com/user-attachments/assets/4447564c-b0f6-407a-80e8-4bbf34258150" />


**R:** `CyberDefenders{N3v3r_eX3cuTe_F!l3$_dOwnL0ded_fr0m_M@lic10u5_$erV3r}`

-----

*(Flag: visible al final del archivo IMF-Mission.pdf descifrado)*

## 🛡️ Proceso de CTI (Cyber Threat Intelligence)

### 1. **Identificación del Artefacto Malicioso**

Ruta: C:\Users\ethan\Downloads\IMF-Info.pdf.exe

MD5: 336a7cf476ebc7548c93507339196abb

Red flag: Doble extensión .pdf.exe (filename spoofing)

Origen: Zone.Identifier → ZoneId=3 → Internet

URL: http://192.168.16.128:8000/IMF-Info.pdf.exe



### 2. **Análisis de Artefactos del Navegador**

Chrome History (SQLite) → Descarga de TeamViewer únicamente

Edge History (SQLite) → Descarga confirmada de IMF-Info.pdf.exe

Conclusión: Microsoft Edge utilizado para descarga maliciosa



### 3. **Análisis de Artefactos de Correo (Windows Mail)**
NTUSER.DAT → UserAssist:

└── WindowsMail ejecutado 16 veces (último: 2025-02-09 22:26:14Z)

HxStore.hxd → CyberChef Extract IPs:

└── 145.67.29.88, 212.33.10.112, 192.168.16.128




### 4. **Análisis Estático del Payload**
CyberChef Strings → PowerShell payload ofuscado encontrado

Deofuscación: Reverse + From Base64

Tipo: Ransomware dirigido (2 archivos específicos)

Password hardcodeada: Imf!nfo#2025Sec$

Indicador de reconocimiento previo del endpoint



## 🎯 MITRE ATT&CK Mapping

| Táctica | Técnica | ID | Descripción Observada |
|---------|---------|----|-----------------------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Descarga inducida del ejecutable malicioso vía URL directa |
| Defense Evasion | Masquerading: Double File Extension | T1036.007 | Archivo `IMF-Info.pdf.exe` con doble extensión para ofuscación |
| Defense Evasion | Obfuscated Files or Information | T1027 | Payload PowerShell ofuscado con Reverse+Base64 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Script PowerShell embebido en ejecutable para cifrado de archivos |
| Impact | Data Encrypted for Impact | T1486 | Ransomware dirigido cifra archivos específicos del endpoint |
| Collection | Email Collection: Local Email Collection | T1114.001 | IPs de servidores comprometidos encontradas en caché de Windows Mail |

## 🔬 Herramientas Utilizadas

🔍 Forense de Disco

├── FTK Imager → Análisis imagen .ad1, extracción de artefactos y hashes

└── RegRipper → Extracción y análisis de NTUSER.DAT

📊 Análisis de Artefactos

├── DB Browser for SQLite → Análisis históricos Chrome y Edge

├── CyberChef → Extracción de IPs (HxStore.hxd) + deofuscación payload

└── Strings → Extracción de cadenas del binario malicioso



## 📊 Lecciones Aprendidas

1. **Doble Extensión como Red Flag**: Implementar reglas de detección para archivos con extensiones compuestas (`.pdf.exe`, `.doc.exe`) en soluciones EDR y filtros de email gateway.
2. **Zone.Identifier como Evidencia Forense**: El archivo `Zone.Identifier` es frecuentemente ignorado pero constituye evidencia forense directa sobre el origen de archivos descargados desde Internet, incluyendo la URL exacta de descarga.
3. **Análisis de HxStore.hxd**: Los artefactos de Windows Mail cacheados localmente (`HxStore.hxd`) pueden contener información crítica sobre comunicaciones internas y C2 incluso cuando los correos originales son eliminados del servidor.

---

> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: Silent Breach (Endpoint Forensics Category)*
