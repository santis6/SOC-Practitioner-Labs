# 🔍 Web Investigation Lab WriteUp – Network Forensics (CyberDefenders)

## 🧩 Escenario del Laboratorio

**Contexto**: BookWorld (e-commerce libros) reporta spike en queries DB y uso de recursos. Alerta automatizada indica actividad maliciosa en tráfico de red.  
**Objetivo**: Analizar PCAP con Wireshark para identificar SQLi, credenciales atacante, malware subido y directorios expuestos.  
**Herramientas**: Wireshark, NetworkMiner.  
**Tácticas**: Initial Access | Persistence | Command and Control.

En el laboratorio nos entregan un PCAP para análisis de compromiso web server.



## 📋 Preguntas del Laboratorio & Respuestas

| Q1 | By knowing the attacker's IP, we can analyze all logs and actions related to that IP. Can you provide the attacker's IP?  
-
Siguiendo el nombre "Web Investigation" filtramos HTTP conversations. Observamos volumen masivo de GET requests desde **111.224.250.131**.

<img width="1355" height="608" alt="image" src="https://github.com/user-attachments/assets/dbe31eed-9a78-4ae2-a788-40298f3654fc" />


**R:** `111.224.250.131`

------

| Q2 | If the geographical origin of an IP address is known to be from a region that has no business traffic, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker? 
-
Usando WhatIsMyIPAddress con la IP maliciosa identificamos origen geográfico.  

<img width="1358" height="570" alt="image" src="https://github.com/user-attachments/assets/bfc43e89-8e5d-4ffb-beb3-318f481611bf" />



**R:** `Shijiazhuang`

------

| Q3 | Identifying the exploited script allows security teams to understand exactly which vulnerability was used. Can you provide the vulnerable PHP script name? 
-

En las primeras interacciones de la IP maliciosa con el servidor web, podemos ver que después del request al "search.php" empiezan las peticiones comprometedoras.

<img width="1360" height="608" alt="image" src="https://github.com/user-attachments/assets/68a2b322-60e4-4f67-bec0-6d57bc5cb249" />


**R:** `search.php`

------

| Q4 | Establishing the timeline of an attack, what is the complete request URI of the first SQLi attempt by the attacker?   
-

Viendo las peticiones posteriores a la petición del script vulnerable, se hace un intento de SQLi para testear parámetros vulnerables en el servidor, si al payload lo limpiamos ("%20" se traduce a " ") encontramos la respuesta.

<img width="1360" height="607" alt="image" src="https://github.com/user-attachments/assets/555162bb-ccba-4c9d-8532-7fc76ee765f6" />


**R:** `/search.php?search=book and 1=1; -- -`

------

| Q5 | Can you provide the complete request URI that was used to read the web server's available databases?   
-

Para encontrar  la respuesta tenemos que buscar patrones en el reconocimiento de DB disponibles en el servidor como por ej ("schema" o "information_schema" - SELECT schema_name FROM information_schema.schemata).
Aplicando dichos filtros en la búsqueda de paquetes encontramos que en el paquete 1525 lista todas las DB disponibles del servidor.

<img width="1360" height="643" alt="image" src="https://github.com/user-attachments/assets/bb92c51d-db0f-4a3a-9788-daa5167844f7" />

<img width="1360" height="607" alt="image" src="https://github.com/user-attachments/assets/ba67bfd3-7cd0-4551-ab19-5ba23d397923" />


**R:** `/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -`

------

| Q6 | What's the table name containing the website users data?   
-

Teniendo en cuenta la syntaxis de SQL y demás parámetros para agilizar la búsqueda buscamos directamente los frames que contenga la siguiente info: "table_name".
Haciendo un follow HTTP stream del segundo paquete que encontramos, podemos ver claramente que se lista la table_name **Customers**.

<img width="1360" height="608" alt="image" src="https://github.com/user-attachments/assets/85cf449c-f932-4976-b8be-a07818f27dff" />

<img width="1360" height="609" alt="image" src="https://github.com/user-attachments/assets/d34c3b30-1a71-4157-892e-d9a034bdc390" />

**R:** `customers`

------

| Q7 | The website directories hidden from the public could serve as unauthorized access. Can you provide the name of the directory discovered by the attacker?   
-
Si nos vamos al apartado de "Statistics" - "HTTP" - "Requests" podemos encontrar una cantidad exorbitante de requests solicitadas por el atacante. Claramente un intento de enumeración de directorios web, y viendo el User-Agent se trata de la conocida herramienta "GoBuster".
Teniendo en cuenta la respuesta de la pregunta anterior podemos aplicar un "http.request.method==POST" y podemos ver el atacante interactuando con el directorio "/admin/".

<img width="1360" height="609" alt="image" src="https://github.com/user-attachments/assets/1391a5c4-b2aa-4557-a483-6b020e48c2a7" />

<img width="1360" height="607" alt="image" src="https://github.com/user-attachments/assets/6e16c15f-b41b-4122-b8c9-138ec6c04076" />

**R:** `/admin/`

------

| Q8 | Knowing which credentials were used allows us to determine the extent of account compromise. What are the credentials used by the attacker for logging in?  
-

Después de buscar el timeline para correlacionar la respuesta de la pregunta anterior, podemos ver que encontró las credenciales para iniciar sesión desde el panel de Admin.

<img width="1360" height="733" alt="image" src="https://github.com/user-attachments/assets/452e7ffa-e8f7-47c3-abad-0e1b0e1284b6" />


**R:** `admin:admin123!`

------

| Q9 | We need to determine if the attacker gained further access. What's the name of the malicious script uploaded by the attacker? 
-

Después de que el atacante inició sesión mandó un POST request en el paquete N°88757 si hacemos un Follow HTTP Stream, encontramos que subió un archivo en el index.php.

<img width="1360" height="608" alt="image" src="https://github.com/user-attachments/assets/f5a8f30a-219b-4bf5-8ab7-fec075a8613f" />


**R:** `NVri2vhp.php`

------

## 🛡️ Proceso de CTI (Cyber Threat Intelligence)

### 1. **Identificación Inicial del Atacante**
Filtro: Statistics - Conversations - (Packets)
IP sospechosa: 111.224.250.131 (Shijiazhuang, China)
Volumen: ~1000+ requests en minutos



### 2. **Análisis SQL Injection Timeline**
Paq. inicial → /search.php?search=book and 1=1; -- -
Paq. 1525 → DB enumeration (information_schema)
Tabla target: customers (user data)



### 3. **Enumeración y Acceso Administrativo**
Herramienta: GoBuster (User-Agent detectado)
Directorio: /admin/ (200 OK)
Credenciales: admin:admin123!



### 4. **Persistence via Webshell**
Upload: NVri2vhp.php (paq. 88757)
Ubicación: /admin/index.php probable
MITRE: T1505.003 - Web Shell



## 🔬 Herramientas Utilizadas

Análisis de Red

├── Wireshark → PCAP dissection, HTTP streams

└── WhatIsMyIPAddress → IP geolocation



## 📊 Lecciones Aprendidas

1. **SQLi Detection**: Monitorear `UNION SELECT`, `information_schema` en web logs.
   
2. **Directory Enumeration**: Bloquear GoBuster User-Agents + rate limiting.
  
3. **Webshell Hunting**: Regex para nombres randomizados PHP (`^[A-Z]{8}\.php$`).

---

> **Santiago Daniel Sandili** – SOC Analyst L1 Portfolio  
> *CyberDefenders Blue Team Lab: Web Investigation (Network Forensics Category)*
