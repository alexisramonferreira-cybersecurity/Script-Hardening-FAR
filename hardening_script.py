#!/usr/bin/env python3
"""
===============================================================================
SCRIPT DE HARDENING PARA UBUNTU/DEBIAN
Basado en CIS Benchmarks
===============================================================================
Este script automatiza el hardening (endurecimiento) de servidores Linux
siguiendo los estándares de seguridad CIS (Center for Internet Security)

Funcionalidades:
- Deshabilita servicios innecesarios
- Configura firewall iptables con políticas restrictivas
- Asegura la configuración de SSH
- Implementa auditoría con auditd
- Ejecuta análisis de seguridad con Lynis
- Genera reportes detallados
===============================================================================
"""

# =============================================================================
# IMPORTACIONES DE LIBRERÍAS
# =============================================================================
import subprocess  # Para ejecutar comandos del sistema operativo
import os           # Para operaciones del sistema (verificar root, rutas, etc.)
import sys          # Para manejar salida del script y argumentos
import logging      # Para registrar eventos y errores en logs
import json         # Para generar reportes en formato JSON
import re           # Para expresiones regulares (buscar patrones en texto)
from datetime import datetime  # Para obtener fechas y horas en logs
from pathlib import Path       # Para manejo seguro de rutas de archivos
import argparse     # Para procesar argumentos de línea de comandos (--dry-run, --apply)


# =============================================================================
# CONFIGURACIÓN DE ARCHIVOS DE LOG Y REPORTES
# =============================================================================
# Los logs guardan todo lo que ocurre durante la ejecución
# El nombre incluye timestamp para no sobrescribir ejecuciones anteriores
LOG_FILE = f"/var/log/hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# El reporte guarda los resultados estructurados en JSON para análisis posterior
REPORT_FILE = f"/var/log/hardening_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"


# =============================================================================
# CONFIGURACIÓN DEL SISTEMA DE LOGGING
# =============================================================================
# level=logging.INFO: Muestra mensajes de información (no solo errores)
# format: Define cómo se ve cada línea de log (fecha - nivel - mensaje)
# handlers: Define dónde se guardan los logs (archivo Y consola)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),   # Guarda en archivo
        logging.StreamHandler()           # Muestra en pantalla
    ]
)


# =============================================================================
# CLASE PRINCIPAL: HardeningTool
# =============================================================================
# Esta clase contiene todos los métodos necesarios para aplicar hardening
class HardeningTool:
    """
    Clase que agrupa todas las funciones de hardening del sistema
    """
    
    # -------------------------------------------------------------------------
    # MÉTODO CONSTRUCTOR (__init__)
    # -------------------------------------------------------------------------
    # Se ejecuta automáticamente al crear una instancia de la clase
    def __init__(self, dry_run=False):
        """
        Constructor de la clase HardeningTool
        
        Parámetros:
            dry_run (bool): Si es True, solo simula acciones sin aplicarlas.
                           Si es False, aplica los cambios realmente.
        """
        
        # Guarda el modo dry_run como atributo de la clase
        # self.xxx hace que la variable sea accesible desde todos los métodos
        self.dry_run = dry_run
        
        # Lista para almacenar todas las acciones que se simularían en dry-run
        # Útil para generar reportes de lo que se habría hecho
        self.actions = []
        
        # Verifica que el script se ejecute como root (necesario para cambios)
        self.check_root()
        
        # Diccionario que almacenará todos los resultados del hardening
        # Esto se convertirá a JSON al final para el reporte
        self.results = {
            "timestamp": datetime.now().isoformat(),           # Fecha y hora actual
            "hostname": subprocess.getoutput("hostname"),       # Nombre del servidor
            "dry_run": dry_run,                                 # Indica si fue simulación
            "checks": []                                        # Lista de verificaciones
        }
        
        # Mensaje informativo sobre el modo de ejecución
        if self.dry_run:
            logging.info("🔍 MODO DRY-RUN ACTIVADO - Solo se mostrarán acciones, no se aplicarán cambios")
        else:
            logging.info("🚀 MODO REAL ACTIVADO - Se aplicarán cambios al sistema")
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: check_root()
    # -------------------------------------------------------------------------
    # Verifica que el usuario que ejecuta el script sea root
    def check_root(self):
        """
        Verifica que el script se ejecute con privilegios de root (administrador)
        Los cambios de hardening requieren permisos elevados
        
        Si no es root, muestra error y sale del script
        """
        # os.geteuid() devuelve 0 para root, cualquier otro número para usuario normal
        if os.geteuid() != 0:
            logging.error("❌ Este script debe ejecutarse como root (sudo)")
            sys.exit(1)  # Sale del script con código de error
        else:
            logging.info("✅ Verificado: ejecutando como root")
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: run_command()
    # -------------------------------------------------------------------------
    # Ejecuta comandos del sistema de forma segura, con soporte para dry-run
    def run_command(self, command, check=True):
        """
        Ejecuta un comando del sistema o lo simula en modo dry-run
        
        Parámetros:
            command (str): Comando a ejecutar (ej: "ls -la")
            check (bool): Si es True, lanza excepción si el comando falla
        
        Retorna:
            tuple: (código_retorno, stdout, stderr)
        """
        
        # ===== MODO DRY-RUN =====
        # Si estamos simulando, solo mostramos el comando sin ejecutarlo
        if self.dry_run:
            logging.info(f"🔍 [DRY-RUN] Ejecutaría: {command}")
            self.actions.append(command)  # Guardamos el comando para el reporte
            return 0, "", ""  # Retornamos éxito simulado
        
        # ===== MODO REAL =====
        # Ejecutamos el comando realmente en el sistema
        try:
            # subprocess.run() ejecuta el comando y espera a que termine
            # shell=True permite usar comandos con pipes (|) y redirecciones (>)
            # capture_output=True captura stdout y stderr
            # text=True devuelve strings en lugar de bytes
            result = subprocess.run(
                command,
                shell=True if isinstance(command, str) else False,
                capture_output=True,
                text=True,
                check=check
            )
            # Retornamos código de salida, salida estándar y errores
            return result.returncode, result.stdout, result.stderr
            
        # Si hay error y check=True, capturamos la excepción
        except subprocess.CalledProcessError as e:
            logging.error(f"❌ Error ejecutando comando '{command}': {e}")
            return e.returncode, e.stdout, e.stderr
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: write_file()
    # -------------------------------------------------------------------------
    # Escribe contenido en un archivo, con soporte para dry-run
    def write_file(self, filepath, content):
        """
        Escribe contenido en un archivo o lo simula en modo dry-run
        
        Parámetros:
            filepath (str): Ruta del archivo a crear/modificar
            content (str): Contenido a escribir en el archivo
        """
        
        # ===== MODO DRY-RUN =====
        if self.dry_run:
            logging.info(f"🔍 [DRY-RUN] Crearía archivo: {filepath}")
            # Mostramos primeras 200 caracteres del contenido para no saturar
            preview = content[:200].replace('\n', '\\n')
            logging.info(f"🔍 [DRY-RUN] Contenido: {preview}...")
            self.actions.append(f"WRITE_FILE: {filepath}")
        
        # ===== MODO REAL =====
        else:
            # open() abre el archivo en modo escritura ('w')
            # Si no existe, lo crea. Si existe, lo sobrescribe
            with open(filepath, 'w') as f:
                f.write(content)  # Escribe el contenido
            logging.info(f"✅ Archivo creado/modificado: {filepath}")
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: disable_unnecessary_services()
    # -------------------------------------------------------------------------
    # Deshabilita servicios que no son necesarios para reducir superficie de ataque
    def disable_unnecessary_services(self):
        """
        Deshabilita servicios innecesarios según CIS Benchmarks
        
        Servicios comunes a deshabilitar:
        - avahi-daemon: Descubrimiento de red mDNS (no necesario en servidores)
        - cups: Sistema de impresión (no necesario en servidores)
        - nfs-server: Compartir archivos (solo si se usa)
        - telnetd: Telnet (inseguro, usar SSH)
        - etc.
        """
        logging.info("="*60)
        logging.info("1. DESHABILITANDO SERVICIOS INNECESARIOS")
        logging.info("="*60)
        
        # Lista de servicios a deshabilitar
        # Estos servicios son comunes en desktop pero no en servidores
        services_to_disable = [
            "avahi-daemon",   # Descubrimiento de red (Bonjour/mDNS)
            "cups",           # Servicio de impresión
            "cups-browsed",   # Descubrimiento automático de impresoras
            "nfs-server",     # Servidor NFS (compartir archivos)
            "rpcbind",        # Mapeo de puertos RPC (necesario para NFS)
            "slapd",          # Servidor LDAP
            "bind9",          # Servidor DNS
            "vsftpd",         # Servidor FTP (inseguro)
            "apache2",        # Servidor web (solo si no se usa)
            "nginx",          # Servidor web (solo si no se usa)
            "samba",          # Compartir archivos estilo Windows
            "smbd",           # Demonio Samba
            "nmbd",           # NetBIOS name server
            "telnetd",        # Telnet (MUY inseguro)
            "xinetd"          # Super servidor (obsoleto)
        ]
        
        # Recorremos cada servicio de la lista
        for service in services_to_disable:
            logging.info(f"📦 Procesando servicio: {service}")
            
            # 1. Detener el servicio si está corriendo
            # check=False para que no falle si el servicio no existe
            self.run_command(f"systemctl stop {service} 2>/dev/null", check=False)
            
            # 2. Deshabilitar el servicio (no inicia al boot)
            return_code, _, _ = self.run_command(f"systemctl disable {service} 2>/dev/null", check=False)
            
            # 3. Registramos el resultado
            if return_code == 0 and not self.dry_run:
                logging.info(f"   ✅ Servicio {service} deshabilitado")
            elif self.dry_run:
                logging.info(f"   🔍 Se deshabilitaría {service}")
        
        # Guardamos el resultado en el reporte
        self.results["checks"].append({
            "category": "disable_services",
            "status": "simulated" if self.dry_run else "success",
            "message": f"Procesados {len(services_to_disable)} servicios"
        })
        
        logging.info("✅ Fase 1 completada")
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: configure_iptables()
    # -------------------------------------------------------------------------
    # Configura el firewall usando iptables con políticas restrictivas
    def configure_iptables(self):
        """
        Configura iptables (firewall) con política de denegar por defecto
        
        Reglas implementadas:
        - Política DROP para tráfico entrante (denegar todo por defecto)
        - Permitir tráfico local (loopback)
        - Permitir conexiones establecidas
        - Permitir puertos esenciales (SSH, HTTP, HTTPS, DNS)
        - Protección contra ataques comunes
        """
        logging.info("="*60)
        logging.info("2. CONFIGURANDO IPTABLES (FIREWALL)")
        logging.info("="*60)
        
        # ===== MODO DRY-RUN =====
        if self.dry_run:
            logging.info("🔍 [DRY-RUN] Reglas de iptables que se aplicarían:")
            rules = [
                "iptables -F                       # Limpiar reglas existentes",
                "iptables -X                       # Limpiar cadenas personalizadas",
                "iptables -P INPUT DROP            # Denegar todo tráfico entrante",
                "iptables -P FORWARD DROP          # Denegar reenvío de paquetes",
                "iptables -P OUTPUT ACCEPT         # Permitir tráfico saliente",
                "iptables -A INPUT -i lo -j ACCEPT # Permitir tráfico local",
                "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # SSH",
                "iptables -A INPUT -p tcp --dport 80 -j ACCEPT  # HTTP",
                "iptables -A INPUT -p tcp --dport 443 -j ACCEPT # HTTPS",
                "netfilter-persistent save         # Guardar reglas"
            ]
            for rule in rules:
                logging.info(f"   {rule}")
        
        # ===== MODO REAL =====
        else:
            # 1. Limpiar reglas existentes (empezar desde cero)
            logging.info("🧹 Limpiando reglas existentes...")
            self.run_command("iptables -F")      # Limpia tabla filter
            self.run_command("iptables -X")      # Elimina cadenas personalizadas
            self.run_command("iptables -t nat -F")   # Limpia tabla NAT
            self.run_command("iptables -t mangle -F") # Limpia tabla mangle
            
            # 2. Establecer políticas por defecto
            logging.info("🚫 Estableciendo políticas DROP por defecto...")
            self.run_command("iptables -P INPUT DROP")   # Denegar entrante
            self.run_command("iptables -P FORWARD DROP") # Denegar reenvío
            self.run_command("iptables -P OUTPUT ACCEPT") # Permitir saliente
            
            # 3. Permitir tráfico local (loopback)
            logging.info("🏠 Permitiendo tráfico local (loopback)...")
            self.run_command("iptables -A INPUT -i lo -j ACCEPT")
            self.run_command("iptables -A OUTPUT -o lo -j ACCEPT")
            
            # 4. Permitir conexiones establecidas
            # Esto es CRÍTICO: permite que respuestas a conexiones iniciadas por el servidor entren
            logging.info("🔗 Permitiendo conexiones establecidas...")
            self.run_command("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
            
            # 5. Permitir puertos esenciales
            logging.info("🔓 Permitiendo puertos esenciales...")
            essential_ports = [22, 80, 443, 53]  # SSH, HTTP, HTTPS, DNS
            for port in essential_ports:
                logging.info(f"   - Puerto {port}")
                self.run_command(f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
            
            # 6. Protecciones adicionales contra ataques
            logging.info("🛡️ Aplicando protecciones adicionales...")
            # Prevenir ataques SYN flood
            self.run_command("iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP")
            # Prevenir escaneo de puertos (XMAS packets)
            self.run_command("iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP")
            
            # 7. Guardar reglas para que persistan después de reiniciar
            logging.info("💾 Guardando reglas para que persistan...")
            self.run_command("apt-get install iptables-persistent -y -qq", check=False)
            self.run_command("netfilter-persistent save")
            
            # 8. Mostrar reglas aplicadas (para verificar)
            _, stdout, _ = self.run_command("iptables -L -n -v")
            logging.info(f"📋 Reglas actuales:\n{stdout[:500]}")  # Mostramos primeras 500 chars
            
            logging.info("✅ Firewall configurado correctamente")
        
        # Guardamos resultado en el reporte
        self.results["checks"].append({
            "category": "firewall",
            "status": "simulated" if self.dry_run else "success",
            "message": "Firewall configurado con políticas DROP"
        })
        
        logging.info("✅ Fase 2 completada")
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: secure_ssh()
    # -------------------------------------------------------------------------
    # Configura SSH de forma segura según mejores prácticas
    def secure_ssh(self):
        """
        Configura SSH con opciones de seguridad:
        - Deshabilita login de root
        - Deshabilita autenticación por contraseña (solo llaves SSH)
        - Limita intentos de autenticación
        - Usa protocolo SSH versión 2
        - Configura timeouts para sesiones inactivas
        """
        logging.info("="*60)
        logging.info("3. CONFIGURANDO SSH SEGURO")
        logging.info("="*60)
        
        # Rutas de archivos de configuración
        sshd_config = "/etc/ssh/sshd_config"  # Archivo de configuración del servidor SSH
        backup_file = f"{sshd_config}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Lista de configuraciones seguras (clave, valor)
        # Cada tupla representa una línea en el archivo de configuración
        ssh_configs = [
            ("PermitRootLogin", "no"),              # No permitir login como root
            ("PasswordAuthentication", "no"),       # No usar contraseñas (solo llaves)
            ("PermitEmptyPasswords", "no"),         # No permitir contraseñas vacías
            ("ChallengeResponseAuthentication", "no"),  # Deshabilitar autenticación desafío
            ("Protocol", "2"),                      # Usar solo SSH protocolo 2 (más seguro)
            ("LoginGraceTime", "60"),               # 60 segundos para autenticarse
            ("MaxAuthTries", "3"),                  # Máximo 3 intentos de autenticación
            ("MaxSessions", "5"),                   # Máximo 5 sesiones por conexión
            ("X11Forwarding", "no"),                # Deshabilitar forwarding X11
            ("AllowAgentForwarding", "no"),         # Deshabilitar forwarding de agente
            ("ClientAliveInterval", "900"),         # 15 minutos de inactividad
            ("ClientAliveCountMax", "0"),           # Cerrar sesión al expirar
            ("LogLevel", "VERBOSE")                 # Logs detallados
        ]
        
        # ===== MODO DRY-RUN =====
        if self.dry_run:
            logging.info(f"🔍 [DRY-RUN] Se crearía backup en: {backup_file}")
            logging.info(f"🔍 [DRY-RUN] Se modificaría {sshd_config} con:")
            for key, value in ssh_configs:
                logging.info(f"      {key} {value}")
            logging.info("🔍 [DRY-RUN] Se reiniciaría el servicio SSH")
        
        # ===== MODO REAL =====
        else:
            # Verificar que el archivo de configuración existe
            if not os.path.exists(sshd_config):
                logging.error(f"❌ No se encuentra {sshd_config}")
                return
            
            # 1. Crear backup de la configuración actual
            logging.info(f"📁 Creando backup en {backup_file}")
            self.run_command(f"cp {sshd_config} {backup_file}")
            
            # 2. Escribir nueva configuración
            logging.info("✏️ Escribiendo nueva configuración SSH...")
            with open(sshd_config, 'w') as f:
                # Cabecera del archivo
                f.write("# ================================================================\n")
                f.write("# CONFIGURACIÓN SSH HARDENED - Generada automáticamente\n")
                f.write("# Basado en CIS Benchmarks\n")
                f.write(f("# Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# ================================================================\n\n")
                
                # Escribir cada configuración
                for key, value in ssh_configs:
                    f.write(f"{key} {value}\n")
            
            # 3. Validar la configuración antes de reiniciar
            logging.info("🔍 Validando configuración SSH...")
            return_code, _, stderr = self.run_command("sshd -t")
            
            if return_code == 0:
                # Configuración válida, reiniciar servicio
                logging.info("✅ Configuración válida. Reiniciando SSH...")
                self.run_command("systemctl restart ssh")
                logging.info("✅ SSH configurado correctamente")
            else:
                # Error en configuración, restaurar backup
                logging.error(f"❌ Error en configuración SSH: {stderr}")
                logging.info("🔄 Restaurando configuración original...")
                self.run_command(f"cp {backup_file} {sshd_config}")
                logging.info("✅ Configuración original restaurada")
                return
        
        # Guardamos resultado
        self.results["checks"].append({
            "category": "ssh",
            "status": "simulated" if self.dry_run else "success",
            "message": "SSH hardening aplicado"
        })
        
        logging.info("✅ Fase 3 completada")
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: configure_auditd()
    # -------------------------------------------------------------------------
    # Configura auditd para monitorear eventos críticos de seguridad
    def configure_auditd(self):
        """
        Configura auditd (auditoría del sistema) para monitorear:
        - Cambios en archivos críticos (/etc/passwd, /etc/shadow, etc.)
        - Ejecución de comandos sensibles (sudo, su, login)
        - Cambios en configuración de red y servicios
        """
        logging.info("="*60)
        logging.info("4. CONFIGURANDO AUDITD (AUDITORÍA)")
        logging.info("="*60)
        
        # Ruta donde se guardarán las reglas de auditoría
        rules_file = "/etc/audit/rules.d/hardening.rules"
        
        # Definición de reglas de auditoría
        # Formato: -w [archivo] -p [permisos] -k [clave]
        # Permisos: r=read, w=write, x=execute, a=attribute change
        audit_rules = """# ================================================================
# REGLAS DE AUDITORÍA PARA HARDENING
# Basado en CIS Benchmarks
# ================================================================

# --- Limpiar reglas existentes ---
-D

# --- Monitorear archivos de autenticación (identidad) ---
-w /etc/passwd -p wa -k identity      # Usuarios del sistema
-w /etc/shadow -p wa -k identity      # Contraseñas encriptadas
-w /etc/group -p wa -k identity       # Grupos del sistema
-w /etc/gshadow -p wa -k identity     # Contraseñas de grupos
-w /etc/sudoers -p wa -k sudo_changes # Configuración de sudo

# --- Monitorear configuraciones críticas ---
-w /etc/ssh/sshd_config -p wa -k ssh_config     # Configuración SSH
-w /etc/iptables/ -p wa -k firewall_changes     # Reglas de firewall
-w /etc/hosts -p wa -k network_changes          # Resolución de nombres
-w /etc/hostname -p wa -k network_changes       # Nombre del host

# --- Monitorear comandos críticos (ejecución) ---
-w /bin/login -p x -k login           # Intentos de login
-w /bin/su -p x -k su_usage           # Cambio a usuario root
-w /usr/bin/sudo -p x -k sudo_execution # Uso de sudo

# --- Monitorear tareas programadas (cron) ---
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.hourly/ -p wa -k cron_changes
-w /etc/cron.daily/ -p wa -k cron_changes
-w /etc/cron.weekly/ -p wa -k cron_changes

# --- Monitorear módulos del kernel ---
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

# --- Configuración final ---
-e 2  # Modo de auditoría: bloqueante (no se pueden modificar reglas)
"""
        
        # ===== MODO DRY-RUN =====
        if self.dry_run:
            logging.info(f"🔍 [DRY-RUN] Se crearía archivo de reglas: {rules_file}")
            logging.info("🔍 [DRY-RUN] Reglas incluirían monitoreo de archivos críticos")
        
        # ===== MODO REAL =====
        else:
            # 1. Instalar auditd si no está presente
            logging.info("📦 Instalando auditd...")
            self.run_command("apt-get update -qq", check=False)
            self.run_command("apt-get install auditd audispd-plugins -y -qq", check=False)
            
            # 2. Escribir archivo de reglas
            self.write_file(rules_file, audit_rules)
            
            # 3. Cargar las reglas
            logging.info("🔄 Cargando reglas de auditoría...")
            self.run_command("augenrules --load")
            
            # 4. Reiniciar auditd para aplicar cambios
            logging.info("🔄 Reiniciando servicio auditd...")
            self.run_command("systemctl restart auditd")
            self.run_command("systemctl enable auditd")
            
            # 5. Verificar que auditd está corriendo
            return_code, _, _ = self.run_command("systemctl is-active auditd")
            if return_code == 0:
                logging.info("✅ Auditd está activo y funcionando")
            else:
                logging.warning("⚠️ Auditd no está activo - revisar logs")
        
        # Guardamos resultado
        self.results["checks"].append({
            "category": "auditd",
            "status": "simulated" if self.dry_run else "success",
            "message": "Auditd configurado con reglas de auditoría"
        })
        
        logging.info("✅ Fase 4 completada")
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: run_lynis_audit()
    # -------------------------------------------------------------------------
    # Ejecuta Lynis para analizar la seguridad del sistema
    def run_lynis_audit(self):
        """
        Ejecuta Lynis, una herramienta de auditoría de seguridad para Linux
        
        Lynis analiza:
        - Configuración del sistema
        - Permisos de archivos
        - Servicios en ejecución
        - Configuración de red
        - Y genera un puntaje (Hardening Index) de 0 a 100
        """
        logging.info("="*60)
        logging.info("5. EJECUTANDO LYNIS AUDIT")
        logging.info("="*60)
        
        # ===== MODO DRY-RUN =====
        if self.dry_run:
            logging.info("🔍 [DRY-RUN] Se instalaría Lynis (si no está presente)")
            logging.info("🔍 [DRY-RUN] Se ejecutaría: lynis audit system --quick")
            logging.info("🔍 [DRY-RUN] Se generaría reporte con Hardening Index")
        
        # ===== MODO REAL =====
        else:
            # 1. Actualizar repositorios e instalar Lynis
            logging.info("📦 Instalando Lynis...")
            self.run_command("apt-get update -qq", check=False)
            self.run_command("apt-get install lynis -y -qq", check=False)
            
            # 2. Ejecutar Lynis
            lynis_log = f"/var/log/lynis_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            logging.info("🔍 Ejecutando Lynis (esto puede tomar 2-3 minutos)...")
            
            # --quick: modo rápido (omite algunas pruebas)
            # --log-file: guarda resultado en archivo
            result = self.run_command(f"lynis audit system --quick --log-file {lynis_log}", check=False)
            
            # 3. Extraer información importante del log
            if os.path.exists(lynis_log):
                with open(lynis_log, 'r') as f:
                    content = f.read()
                
                # Buscar el Hardening Index (puntaje de seguridad)
                hardening_index_match = re.search(r"Hardening index : \[(\d+)\]", content)
                if hardening_index_match:
                    hardening_index = hardening_index_match.group(1)
                    logging.info(f"📊 Hardening Index: {hardening_index}/100")
                    self.results["hardening_index"] = hardening_index
                
                # Contar sugerencias y advertencias
                suggestions = re.findall(r"Suggestion: (.+)", content)
                warnings = re.findall(r"Warning: (.+)", content)
                
                logging.info(f"💡 Sugerencias encontradas: {len(suggestions)}")
                logging.info(f"⚠️ Advertencias encontradas: {len(warnings)}")
                
                # Guardar en resultados
                self.results["lynis"] = {
                    "log_file": lynis_log,
                    "suggestions_count": len(suggestions),
                    "warnings_count": len(warnings),
                    "suggestions": suggestions[:10]  # Guardar primeras 10
                }
                
                logging.info(f"✅ Lynis completado. Log: {lynis_log}")
            else:
                logging.warning("⚠️ No se encontró el log de Lynis")
        
        # Guardamos resultado
        self.results["checks"].append({
            "category": "lynis",
            "status": "simulated" if self.dry_run else "success",
            "message": "Lynis audit ejecutado"
        })
        
        logging.info("✅ Fase 5 completada")
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: additional_hardening()
    # -------------------------------------------------------------------------
    # Aplica medidas adicionales de seguridad
    def additional_hardening(self):
        """
        Medidas de hardening adicionales no cubiertas en otras funciones:
        - Límites de recursos (evita DoS)
        - fail2ban (protección contra fuerza bruta)
        - Configuraciones de kernel
        """
        logging.info("="*60)
        logging.info("6. MEDIDAS ADICIONALES DE HARDENING")
        logging.info("="*60)
        
        # ===== MODO DRY-RUN =====
        if self.dry_run:
            logging.info("🔍 [DRY-RUN] Medidas adicionales que se aplicarían:")
            logging.info("   1. Límites de recursos (archivos, procesos)")
            logging.info("   2. fail2ban (protección contra fuerza bruta)")
            logging.info("   3. Protecciones del kernel (ASLR, etc.)")
        
        # ===== MODO REAL =====
        else:
            # -----------------------------------------------------------------
            # 1. CONFIGURAR LÍMITES DE RECURSOS
            # -----------------------------------------------------------------
            logging.info("📊 Configurando límites de recursos...")
            limits_conf = "/etc/security/limits.d/hardening.conf"
            limits_content = """# Límites de recursos para todos los usuarios
# Previene ataques DoS y fork bombs

* soft core 0        # Deshabilitar core dumps
* hard core 0
* soft nproc 1000    # Máximo 1000 procesos por usuario
* hard nproc 2000
* soft nofile 4096   # Máximo 4096 archivos abiertos
* hard nofile 8192
"""
            self.write_file(limits_conf, limits_content)
            
            # -----------------------------------------------------------------
            # 2. INSTALAR Y CONFIGURAR FAIL2BAN
            # -----------------------------------------------------------------
            logging.info("🛡️ Instalando y configurando fail2ban...")
            self.run_command("apt-get install fail2ban -y -qq", check=False)
            
            jail_local = "/etc/fail2ban/jail.local"
            jail_content = """# Configuración de fail2ban para proteger SSH
[DEFAULT]
bantime = 3600        # Banear por 1 hora
findtime = 600        # Ventana de 10 minutos
maxretry = 5          # 5 intentos fallidos

[sshd]
enabled = true        # Activar protección para SSH
port = ssh            # Puerto SSH
logpath = %(sshd_log)s
"""
            self.write_file(jail_local, jail_content)
            
            # Iniciar y habilitar fail2ban
            self.run_command("systemctl restart fail2ban")
            self.run_command("systemctl enable fail2ban")
            logging.info("✅ fail2ban configurado y activo")
            
            # -----------------------------------------------------------------
            # 3. PROTECCIONES DEL KERNEL
            # -----------------------------------------------------------------
            logging.info("🛡️ Configurando protecciones del kernel...")
            kernel_conf = "/etc/sysctl.d/99-kernel-hardening.conf"
            kernel_content = """# Protecciones de seguridad del kernel
# Basado en CIS Benchmarks

kernel.randomize_va_space = 2    # ASLR (Address Space Layout Randomization)
kernel.kptr_restrict = 2         # Restringir acceso a /proc/kernel
kernel.dmesg_restrict = 1        # Solo root puede ver dmesg
kernel.printk = 3 3 3 3          # Restringir logs del kernel
kernel.panic = 60                # Reiniciar después de 60 segundos de panic
"""
            self.write_file(kernel_conf, kernel_content)
            self.run_command("sysctl -p /etc/sysctl.d/99-kernel-hardening.conf")
            
            logging.info("✅ Medidas adicionales aplicadas correctamente")
        
        # Guardamos resultado
        self.results["checks"].append({
            "category": "additional",
            "status": "simulated" if self.dry_run else "success",
            "message": "Medidas adicionales de hardening aplicadas"
        })
        
        logging.info("✅ Fase 6 completada")
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: generate_report()
    # -------------------------------------------------------------------------
    # Genera reporte final con todos los resultados
    def generate_report(self):
        """
        Genera reporte final en formato JSON y muestra resumen en consola
        
        El reporte incluye:
        - Resumen de todas las acciones realizadas
        - Estado de cada fase (éxito/simulación)
        - Hardening Index de Lynis (si aplica)
        - Estadísticas generales
        """
        logging.info("="*60)
        logging.info("7. GENERANDO REPORTE FINAL")
        logging.info("="*60)
        
        # Calcular estadísticas del reporte
        total_checks = len(self.results["checks"])
        success_checks = len([c for c in self.results["checks"] if c.get("status") == "success"])
        
        # Agregar resumen al reporte
        self.results["summary"] = {
            "total_checks": total_checks,
            "successful_checks": success_checks if not self.dry_run else 0,
            "failed_checks": 0,
            "dry_run": self.dry_run,
            "total_actions_simulated": len(self.actions) if self.dry_run else 0
        }
        
        # Determinar nombre del archivo de reporte
        if self.dry_run:
            report_path = REPORT_FILE.replace('.json', '_dryrun.json')
        else:
            report_path = REPORT_FILE
        
        # Guardar reporte en formato JSON
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        logging.info(f"📄 Reporte guardado en: {report_path}")
        
        # =====================================================================
        # MOSTRAR RESUMEN EN CONSOLA
        # =====================================================================
        print("\n" + "="*70)
        print(" " * 20 + "RESUMEN FINAL DEL HARDENING")
        print("="*70)
        
        if self.dry_run:
            print("🔍 MODO: DRY-RUN (Simulación)")
            print(f"📋 Acciones simuladas: {len(self.actions)}")
            print("⚠️  Ningún cambio fue aplicado al sistema")
            print("\n✅ Para aplicar los cambios, ejecute:")
            print("   sudo python3 hardening_script.py --apply")
        else:
            print("🚀 MODO: REAL (Cambios aplicados)")
            print(f"✅ Checks exitosos: {success_checks}/{total_checks}")
            
            # Mostrar Hardening Index si está disponible
            if self.results.get("hardening_index"):
                print(f"📊 Hardening Index (Lynis): {self.results['hardening_index']}/100")
                
                # Interpretación del puntaje
                index = int(self.results['hardening_index'])
                if index >= 80:
                    print("   🎯 Nivel de seguridad: EXCELENTE")
                elif index >= 60:
                    print("   📈 Nivel de seguridad: BUENO")
                elif index >= 40:
                    print("   ⚠️  Nivel de seguridad: MEJORABLE")
                else:
                    print("   ❌ Nivel de seguridad: CRÍTICO - Revisar recomendaciones")
        
        print("\n" + "="*70)
        print("📂 ARCHIVOS GENERADOS")
        print("="*70)
        print(f"📋 Log completo: {LOG_FILE}")
        print(f"📊 Reporte JSON: {report_path}")
        
        # Mostrar ubicación de logs de Lynis si existen
        if self.results.get("lynis"):
            print(f"🔍 Log de Lynis: {self.results['lynis'].get('log_file', 'No disponible')}")
        
        print("="*70)
    
    
    # -------------------------------------------------------------------------
    # MÉTODO: run_all()
    # -------------------------------------------------------------------------
    # Ejecuta todas las fases de hardening en orden
    def run_all(self):
        """
        Método principal que ejecuta todas las fases de hardening en secuencia
        
        Orden de ejecución:
        1. Deshabilitar servicios innecesarios
        2. Configurar firewall (iptables)
        3. Asegurar SSH
        4. Configurar auditd
        5. Aplicar medidas adicionales
        6. Ejecutar Lynis
        7. Generar reporte
        """
        # Mostrar banner de inicio
        print("\n" + "="*70)
        print(" " * 15 + "🛡️  SCRIPT DE HARDENING LINUX  🛡️")
        print(" " * 20 + "Ubuntu/Debian - CIS Benchmarks")
        print("="*70)
        
        if self.dry_run:
            print("🔍 MODO DRY-RUN ACTIVADO")
            print("   Mostrando acciones que se ejecutarían sin aplicarlas")
        else:
            print("⚠️  MODO REAL ACTIVADO")
            print("   Se aplicarán cambios de seguridad al sistema")
            print("   Asegúrese de tener backup antes de continuar")
        
        print("="*70 + "\n")
        
        # Ejecutar cada fase
        self.disable_unnecessary_services()
        print("\n" + "─"*50 + "\n")
        
        self.configure_iptables()
        print("\n" + "─"*50 + "\n")
        
        self.secure_ssh()
        print("\n" + "─"*50 + "\n")
        
        self.configure_auditd()
        print("\n" + "─"*50 + "\n")
        
        self.additional_hardening()
        print("\n" + "─"*50 + "\n")
        
        self.run_lynis_audit()
        print("\n" + "─"*50 + "\n")
        
        self.generate_report()
        
        # Mensaje final
        print("\n" + "="*70)
        if self.dry_run:
            print("🔍 DRY-RUN COMPLETADO - Revise el reporte antes de aplicar cambios")
        else:
            print("✅ HARDENING COMPLETADO EXITOSAMENTE")
            print("   El servidor ha sido endurecido según CIS Benchmarks")
            print("   Revise el reporte para verificar el estado")
        print("="*70)


# =============================================================================
# FUNCIÓN PRINCIPAL (main)
# =============================================================================
# Punto de entrada del script - procesa argumentos y ejecuta
def main():
    """
    Función principal que procesa argumentos de línea de comandos
    y decide qué modo ejecutar
    
    Argumentos soportados:
        --dry-run  : Modo simulación (solo muestra qué haría)
        --apply    : Modo real (aplica cambios)
        sin argumentos: Modo interactivo (pregunta al usuario)
    """
    
    # Configurar el parser de argumentos
    parser = argparse.ArgumentParser(
        description='Script de Hardening para Ubuntu/Debian basado en CIS Benchmarks',
        epilog='Ejemplos:\n  sudo python3 hardening_script.py --dry-run\n  sudo python3 hardening_script.py --apply'
    )
    
    parser.add_argument('--dry-run', action='store_true', 
                       help='Modo simulación: muestra acciones sin aplicarlas')
    parser.add_argument('--apply', action='store_true',
                       help='Modo real: aplica cambios al sistema')
    
    args = parser.parse_args()
    
    # Caso 1: Modo dry-run explícito
    if args.dry_run:
        tool = HardeningTool(dry_run=True)
        tool.run_all()
    
    # Caso 2: Modo apply explícito
    elif args.apply:
        # Confirmación adicional para modo real
        print("\n⚠️  ADVERTENCIA ⚠️")
        print("Este script aplicará cambios significativos al sistema:")
        print("  - Deshabilitará servicios")
        print("  - Configurará firewall restrictivo")
        print("  - Modificará configuración SSH")
        print("  - Instalará y configurará auditd y fail2ban")
        print("\n⚠️  Asegúrese de tener:")
        print("  - Backup del sistema")
        print("  - Acceso de consola (por si SSH falla)")
        
        confirm = input("\n¿Está seguro de continuar? (yes/no): ")
        if confirm.lower() == 'yes':
            tool = HardeningTool(dry_run=False)
            tool.run_all()
        else:
            print("❌ Operación cancelada")
            sys.exit(0)
    
    # Caso 3: Sin argumentos - modo interactivo
    else:
        print("\n" + "="*50)
        print("   SCRIPT DE HARDENING LINUX")
        print("="*50)
        print("\nSeleccione modo de ejecución:")
        print("  1. 🔍 DRY-RUN (Simulación) - Recomendado primero")
        print("  2. 🚀 REAL (Aplicar cambios)")
        print("  3. ❌ Cancelar")
        
        choice = input("\nOpción (1/2/3): ").strip()
        
        if choice == '1':
            tool = HardeningTool(dry_run=True)
            tool.run_all()
        elif choice == '2':
            print("\n⚠️  ADVERTENCIA: Modo REAL - Se aplicarán cambios")
            confirm = input("Confirmar con 'yes' para continuar: ")
            if confirm.lower() == 'yes':
                tool = HardeningTool(dry_run=False)
                tool.run_all()
            else:
                print("❌ Operación cancelada")
        else:
            print("❌ Operación cancelada")
            sys.exit(0)


# =============================================================================
# PUNTO DE ENTRADA DEL SCRIPT
# =============================================================================
# Esta condición verifica que el script se ejecute directamente
# (no importado como módulo desde otro script)
if __name__ == "__main__":
    main()
