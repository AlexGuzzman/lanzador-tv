# Lanzador TV

Lanzador con aspecto de tvOS para teles Samsung (Tizen) con [TizenBrew](https://github.com/reisxd/TizenBrew).

- Fondos 4K de Wikimedia Commons con zoom lento y fundido (autor y licencia en pantalla).
- Hora y tiempo de Barcelona (Open-Meteo): actual, máxima/mínima y próximas 6 horas.
- Iconos que abren apps en un Apple TV de la misma red (protocolo Companion), cambian de entrada HDMI/USB de la tele o abren otros módulos de TizenBrew.

## Cómo funciona

`app/index.html` es la interfaz. `service.js` es un pequeño servicio que TizenBrew ejecuta en la tele (Node antiguo, ES5) y escucha en `127.0.0.1:8095`:

| Ruta | Qué hace |
|---|---|
| `GET /status` | Estado del puente |
| `POST /config` | Recibe `atvHost`, `atvCreds` (credenciales Companion de pyatv) y `tvToken` |
| `GET /atv/launch?id=<bundle>` | Abre una app en el Apple TV |
| `GET /tv/source?pos=<n>` | Elige la entrada *n* del menú Fuentes de la tele |
| `GET /tv/settings` | Abre la Configuración de la tele (`org.tizen.menu`) con Vetro |
| `GET /tv/input?to=<entrada>` | Cambia directamente a `tv`, `hdmi1`…`hdmi4` (necesita [Vetro](https://github.com/andrearicci93/vetro) con root en el puerto 9000) |

Una app no puede cambiar de entrada en Tizen. Para eso el puente pide a Vetro, que corre con root en la propia tele, que pulse la tecla de entrada directa del sistema (`XF86DiscretHDMI3`, etc.). El puente solo acepta esas cinco entradas. Al abrir una app del Apple TV, el puente también cambia la tele a `hdmi1`.

Este repositorio **no contiene credenciales**. Se envían una vez desde la red local a `POST /config` y el lanzador las guarda en el almacenamiento local de la tele.

## Desarrollo

`service.js` se genera con `./build.sh`, que junta `service/bridge.js` con [tweetnacl](https://github.com/dchest/tweetnacl-js) (dominio público). `node service/test-crypto.js` comprueba el cifrado contra el de Node.

Los iconos son composiciones propias con los colores de cada servicio; las marcas pertenecen a sus dueños. Este proyecto no está afiliado a Samsung, Apple ni a ninguno de los servicios.
