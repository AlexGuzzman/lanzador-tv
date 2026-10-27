# Lanzador TV

Lanzador con aspecto de tvOS para teles Samsung (Tizen) con [TizenBrew](https://github.com/reisxd/TizenBrew).

- Fondos 4K de Wikimedia Commons con zoom lento y fundido (autor y licencia en pantalla).
- Hora y tiempo de Barcelona (Open-Meteo): actual, máxima/mínima y las próximas 12 horas de 2 en 2.
- Una sola fila de iconos a la vista; abajo/arriba cambia a la otra fila (con puntos de página).
- Tarjeta con el cielo de Barcelona ahora: alterna las webcams de Collserola y Port Olímpic (Webcams provided by Windy.com).
- Iconos que abren apps en un Apple TV de la misma red (protocolo Companion), cambian de entrada HDMI/USB de la tele o abren otros módulos de TizenBrew.

## Cómo funciona

`app/index.html` es la interfaz. `service.js` es un pequeño servicio que TizenBrew ejecuta en la tele (Node antiguo, ES5) y escucha en `127.0.0.1:8095`:

| Ruta | Qué hace |
|---|---|
| `GET /status` | Estado del puente |
| `POST /config` | Recibe `atvHost`, `atvCreds` (credenciales Companion de pyatv), `tvToken`, `windyKey` (clave gratuita de la API de webcams de Windy) `homeGuard` (Home de Samsung → lanzador, desactivado por defecto) y `homeKey` (volver al lanzador desde YouTube con Home, activado por defecto) |
| `GET /atv/launch?id=<bundle>` | Abre una app en el Apple TV |
| `GET /tv/source?pos=<n>` | Elige la entrada *n* del menú Fuentes de la tele |
| `GET /tv/settings` | Abre la Configuración de la tele (`org.tizen.menu`) con Vetro |
| `GET /launcher?state=loaded\|module` | La interfaz avisa de si el lanzador está cargado o se ha ido a otro módulo |
| `GET /webcam?id=<n>` | Imagen actual de una webcam de [Windy](https://api.windy.com/webcams) (necesita `windyKey` en `POST /config`) |
| `GET /tv/input?to=<entrada>` | Cambia directamente a `tv`, `hdmi1`…`hdmi4` (necesita [Vetro](https://github.com/andrearicci93/vetro) con root en el puerto 9000) |

**Tecla Home y YouTube.** YouTube (TizenTube) se ejecuta dentro de TizenBrew, igual que el lanzador, así que abrir TizenBrew no basta para volver. Con la interceptación de Vetro (su Remapper abre TizenBrew al pulsar Home), el puente consulta cada segundo las pulsaciones que Vetro apunta en `GET /input`; si se pulsa Home y el lanzador no está cargado, reinicia TizenBrew como lo hace su propia interfaz (`homeKey`, activado por defecto): por su canal interno (`ws://127.0.0.1:8081`) le envía un módulo vacío de tipo `app`, que borra su modo depuración y olvida YouTube, y la orden de reabrirse en modo depuración; después cierra la app. El servicio de TizenBrew la reabre y lanza el *Auto launch*. Cerrarla sin más no basta: la interfaz se saltaría el *Auto launch*.

**Alternativa sin interceptar el mando.** El Home de Samsung (`com.samsung.tv.csfs`) está siempre en marcha en segundo plano. Cada segundo, el puente pregunta a Vetro si ha pasado a primer plano y, si es así, abre TizenBrew encima; si TizenBrew no tiene el lanzador cargado, lo cierra antes para que arranque en él. No captura el mando. Está desactivado por defecto; se activa con `POST /config {"homeGuard": true}`.

Una app no puede cambiar de entrada en Tizen. Para eso el puente pide a Vetro, que corre con root en la propia tele, que pulse la tecla de entrada directa del sistema (`XF86DiscretHDMI3`, etc.). El puente solo acepta esas cinco entradas. Al abrir una app del Apple TV, el puente también cambia la tele a `hdmi1`.

Este repositorio **no contiene credenciales**. Se envían una vez desde la red local a `POST /config` y el lanzador las guarda en el almacenamiento local de la tele.

## Desarrollo

Para publicar una versión nueva: sube `version` en `package.json` (es la que muestra TizenBrew), ejecuta `./build.sh`, que la copia al puente, y etiqueta el commit como `vN`.

`service.js` se genera con `./build.sh`, que junta `service/bridge.js` con [tweetnacl](https://github.com/dchest/tweetnacl-js) (dominio público). `node service/test-crypto.js` comprueba el cifrado contra el de Node.

Los iconos son composiciones propias con los colores de cada servicio; las marcas pertenecen a sus dueños. Este proyecto no está afiliado a Samsung, Apple ni a ninguno de los servicios.
