# 🌌 N E O N  G R I D 🌌
> **Network Threat Intelligence Dashboard  |  Powered by Suricata + Zeek**

![Python](https://img.shields.io/badge/System-Python_3.8+-00f5ff.svg?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Web_Engine-Flask-ff2d78.svg?style=for-the-badge&logo=flask)
![Tkinter](https://img.shields.io/badge/Desktop_Engine-Tkinter-bf00ff.svg?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-ffe600.svg?style=for-the-badge)

Bienvenido al Grid, usuario. 

**NEON GRID** es un analizador de logs para Monitorización de Seguridad de Red (NSM) y Sistemas de Detección de Intrusos (IDS) diseñado para aquellos que operan en las sombras de la red. Deja atrás las interfaces aburridas y adéntrate en un dashboard de inteligencia de amenazas envuelto en una estética puramente **Retrowave / Synthwave / Outrun**.

Procesa el tráfico, caza las anomalías y visualiza los datos de **Suricata** y **Zeek** al vuelo, sin bases de datos pesadas. Solo tú, tus logs y el resplandor del neón.

---

## 📸 G A L E R Í A  V I S U A L

### 🌐 [ WEB EDITION ] 
Acceso remoto activado. Sirve la inteligencia de amenazas a través de tu red con el motor Flask.

**» Vista General y Estadísticas de Protocolos**
![Web Overview](assets/web_overview.jpg)

**» Panel de Suricata y Registro de Alertas**
![Web Suricata](assets/web_suricata.jpg)

### 💻 [ DESKTOP EDITION ] 
Inmersión total. Ejecuta el binario local impulsado por Tkinter para análisis *offline* y táctico.

**» Consola de Vista General**
![Desktop Overview](assets/desktop_overview.png)

**» Trazado de Suricata y Descubrimiento de Nodos (Archivos)**
![Desktop Suricata](assets/desktop_suricata.jpg)

---

## ⚡ C A R A C T E R Í S T I C A S  S Y S T E M A

* 👾 **Doble Interfaz**: Elige tu vector de ataque. Corre la versión local de Escritorio (ligera y nativa) o despliega el servidor Web para acceso desde cualquier terminal.
* 🕶️ **Vibe Outrun**: Una interfaz de usuario retro-futurista con paletas de colores *cyan*, *magenta* y *amarillo neón*, gráficos brillantes y tipografía de terminal antiguo.
* 📡 **Auto-Descubrimiento**: El analizador rastrea automáticamente los logs de Zeek y Suricata en directorios planos o subcarpetas. Cero configuración, máxima acción.
* 📊 **Analítica Táctica**:
    * **Visión Global**: Conexiones totales, tráfico masivo, distribución de protocolos y Top IPs.
    * **Radar de Alertas**: Gravedad de impactos, categorías y un feed en tiempo real interceptando `fast.log` y `eve.json`.
    * **Capa de Red y DNS**: Puertos de destino más atacados, códigos de respuesta DNS y auditoría de certificados TLS/X.509.
    * **Motor Suricata**: Análisis profundo de paquetes decodificados, flujos TCP/UDP y estado de las reglas.
* 💾 **Cero Bases de Datos**: Lee, parsea y renderiza directamente desde los archivos JSON y texto. Rápido y letal.

---

## 🛠️ E Q U I P A M I E N T O  N E C E S A R I O

* **Python 3.8+** instalado en tu mainframe.
* Archivos de log generados por **Suricata** y/o **Zeek**.

---

## 🚀 S E C U E N C I A  D E  A R R A N Q U E

**1. Descarga el código fuente en tu terminal:**
```bash
git clone [https://github.com/robertotejado/neon-grid.git](https://github.com/tu-usuario/neon-grid.git)
cd neon-grid
