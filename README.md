<div align="center">

# ◈ NEON GRID ◈
**Dashboard de Inteligencia de Amenazas de Red // Suricata + Zeek**

[![Python 3.x](https://img.shields.io/badge/Python-3.x-00f5ff.svg?style=for-the-badge&logo=python&logoColor=white)](#)
[![GUI](https://img.shields.io/badge/Tkinter-Escritorio-ff2d78.svg?style=for-the-badge)](#)
[![Web](https://img.shields.io/badge/Flask-Web-ffe600.svg?style=for-the-badge)](#)
[![License: MIT](https://img.shields.io/badge/Licencia-MIT-bf00ff.svg?style=for-the-badge)](#)

*Bienvenido a la Red.* **NEON GRID** es un analizador de logs y dashboard para **Zeek** y **Suricata** con temática *retrowave/synthwave*. Visualiza el tráfico de tu red, caza ciberamenazas y monitoriza tu mainframe con estilo.

[Características](#-características) • [Vistas Previas](#-conéctate-vistas-previas) • [Instalación](#-instalación-paso-a-paso) • [Configuración PRO](#-configuración-del-entorno-pro) • [Uso](#-manual-de-operaciones-uso)

</div>

---

---

## 🕶️ LA VISIÓN

Olvídate de los aburridos y clínicos visores de logs. NEON GRID trae la estética del *cyberpunk* de los 80s y el *outrun* a tu stack de Monitorización de Seguridad de Red (NSM). Ya sea que estés operando un SOC local, analizando un PCAP, o simplemente quieras que tu *homelab* parezca sacado de una película de hackers, NEON GRID procesa tus logs crudos (texto/JSON) y los convierte en visualizaciones espectaculares bañadas en luces de neón.

Disponible en dos versiones distintas:
1. **Edición de Escritorio:** Una interfaz gráfica (GUI) ligera y ultrarrápida impulsada por Tkinter.
2. **Edición Web:** Un dashboard para navegador impulsado por Flask, perfecto para monitorización remota.

---

## ⚡ CARACTERÍSTICAS

* **Sobrecarga de Interfaz Dual:** Elige entre una aplicación de escritorio independiente o un panel de control web.
* **Autodescubrimiento "Zero-Config":** Apunta a un directorio y automáticamente rastreará tus logs de Zeek y Suricata (soporta estructura plana o subcarpetas `zeek/` y `suricata/`).
* **Visualización de Datos Synthwave:** Gráficos de barras de neón personalizados, gráficos circulares brillantes y tablas de datos con temática retro.
* **Métricas Completas de Amenazas:**
    * Top IPs y Puertos de Origen/Destino
    * Distribuciones de Protocolos y Estados de Conexión
    * Consultas DNS y Códigos de Respuesta
    * Versiones TLS/SSL y rastreo de Certificados X.509
    * Categorías de Alertas de Suricata y Distribución de Severidad

---

## 📸 CONÉCTATE: VISTAS PREVIAS

### 🌐 Edición Web
Accede a tu inteligencia de amenazas desde cualquier lugar de la red. Cuenta con diseños responsivos dinámicos y recarga de datos.

![Web Dashboard - Overview](zeek_suricata_neon_dashboard_web1.png)
*Fig 1: Edición Web - Visión General y Estadísticas de Red*

![Web Dashboard - Suricata](zeek_suricata_neon_dashboard_web2.png)
*Fig 2: Edición Web - Alertas de Suricata y análisis de Fast.log*

### 💻 Edición de Escritorio
Un script de Python ejecutable e independiente que utiliza Tkinter. No requiere navegador.

![Desktop Dashboard - Overview](zeek_suricata_neon_dashboard_desktop1.png)
*Fig 3: Edición de Escritorio - Conexiones y Análisis de Protocolos*

![Desktop Dashboard - Suricata](zeek_suricata_neon_dashboard_desktop2.png)
*Fig 4: Edición de Escritorio - Flujos de Capa de Aplicación y Descubrimiento de Archivos*

---

## ⚙️ INSTALACIÓN PASO A PASO

Para que todo funcione a la perfección en tu sistema, sigue estos pasos.

**Requisitos Previos:**
* Python 3.7 o superior instalado.
* Git instalado en tu sistema.
* *Nota para usuarios Linux:* Es posible que necesites instalar Tkinter para la versión de escritorio (`sudo apt-get install python3-tk`).

### 1. Clonar el Repositorio
Abre tu terminal y descarga el código fuente a tu máquina local:
```bash
git clone https://github.com/robertotejado/neon-grid.git
(https://github.com/robertotejado/neon-grid.git)
cd neon-grid

## Crear un Entorno Virtual (Recomendado)

Aísla las dependencias del proyecto para evitar conflictos:
Bash

# En Windows:
python -m venv venv
venv\Scripts\activate

# En Linux/macOS:
python3 -m venv venv
source venv/bin/activate


🚀 MANUAL DE OPERACIONES (USO)

NEON GRID es flexible. Puedes iniciar el entorno gráfico local o levantar el servidor web.
💻 Lanzar la Edición de Escritorio

Puedes iniciar la aplicación directamente. Si no le pasas ninguna ruta, el programa te pedirá a través de una ventana emergente que selecciones la carpeta donde guardas tus logs.
Bash

# Iniciar sin parámetros (te pedirá seleccionar la carpeta)
python neon_dashboard_desktop.py

# Iniciar apuntando directamente a tu carpeta de logs
python neon_dashboard_desktop.py /ruta/a/tus/logs

🌐 Lanzar la Edición Web

El servidor web es ideal para dejarlo corriendo en una Raspberry Pi, un servidor dedicado, o visualizarlo en remoto.
Bash

# Lanzamiento básico (escanea el directorio actual y abre en el puerto 5000)
python neon_dashboard_web.py /ruta/a/tus/logs

Una vez que veas el mensaje de inicio en la terminal, abre tu navegador y entra en: http://localhost:5000

Opciones Avanzadas para la Edición Web:
Puedes usar banderas (flags) para personalizar exactamente cómo y dónde se ejecuta el servidor:
Argumento	Descripción	Ejemplo de uso
log_dir	(Opcional) Directorio raíz donde buscar.	python neon_dashboard_web.py /var/log/
--suricata	Ruta específica solo para los logs de Suricata.	--suricata /var/log/suricata
--zeek	Ruta específica solo para los logs de Zeek.	--zeek /opt/zeek/logs/current
--port	Puerto donde se alojará el servidor (por defecto: 5000).	--port 8080
--host	Interfaz de red (usa 0.0.0.0 para acceso en red local).	--host 0.0.0.0
