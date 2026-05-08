# Script de Hardening para Ubuntu/Debian

## 📋 Descripción

Script automatizado en Python para hardening de servidores Ubuntu/Debian basado en **CIS Benchmarks**. Aplica configuraciones de seguridad estándar de la industria para proteger servidores contra amenazas comunes.

## 🚀 Características

- ✅ **Deshabilitación de servicios innecesarios** (avahi, cups, nfs, etc.)
- 🔥 **Configuración de firewall** (iptables con políticas DROP)
- 🔐 **Configuración SSH segura** (sin root login, sin contraseñas)
- 👁️ **Auditoría con auditd** (monitoreo de eventos críticos)
- 📊 **Análisis de seguridad con Lynis**
- 📝 **Reportes detallados** (JSON + texto)
- 🛡️ **Medidas adicionales** (fail2ban, protección kernel, límites de recursos)

## 📦 Requisitos Previos

- **Sistema operativo**: Ubuntu 18.04+ / Debian 10+
- **Privilegios**: Root (sudo)
- **Python**: 3.6 o superior
- **Conexión a internet**: Para instalar paquetes necesarios

## 🔧 Instalación

```bash
# 1. Clonar o descargar el script
wget https://tu-servidor/hardening_script.py

# 2. Dar permisos de ejecución
chmod +x hardening_script.py

# 3. Ejecutar como root
sudo python3 hardening_script.py
