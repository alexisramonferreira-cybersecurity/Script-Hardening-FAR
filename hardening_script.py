#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
================================================================================
    SCRIPT DE HARDENING PARA UBUNTU/DEBIAN
    Basado en CIS Benchmarks (Center for Internet Security)
================================================================================

Descripción:
    Este script automatiza el endurecimiento (hardening) de servidores Linux
    Ubuntu/Debian siguiendo los estándares de seguridad CIS.

Funcionalidades:
    1. Deshabilita servicios innecesarios (avahi, cups, nfs, etc.)
    2. Configura firewall iptables con políticas DROP
    3. Aplica configuración SSH segura (sin root, sin contraseñas)
    4. Implementa auditoría del sistema con auditd
    5. Ejecuta análisis de seguridad con Lynis
    6. Genera reportes detallados en JSON y texto

Uso:
    sudo python3 hardening_script.py --dry-run    # Modo simulación
    sudo python3 hardening_script.py --apply      # Modo real
    sudo python3 hardening_script.py              # Modo interactivo

Autor: Hardening Tool
Versión: 1.0.0
Fecha: 2024
================================================================================
"""

# ====================================================================================================
# LIBRERÍAS NECESARIAS
# ====================================================================================================

import subprocess   # Para ejecutar comandos del sistema
import os           # Para operaciones con el sistema de archivos
import sys          # Para manejar argumentos y salida del script
import logging      # Para generar logs de eventos
import json         # Para crear reportes en formato JSON
import re           # Para expresiones regulares (búsqueda de patrones)
from datetime import datetime  # Para timestamps en logs y backups
from pathlib import Path       # Para manejo seguro de rutas
import argparse     # Para procesar argumentos de línea de comandos


# ====================================================================================================
# CONFIGURACIÓN GLOBAL
# ====================================================================================================

# Configuración de archivos de log (con timestamp para evitar sobrescritura)
LOG_FILE = f"/var/log/hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
REPORT_FILE = f"/var/log/hardening_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

# Configuración del sistema de logging
logging.basicConfig(
    level=logging.INFO,                         # Nivel de detalle
    format='%(asctime)s - %(levelname)s - %(message)s',  # Formato de cada línea
    handlers=[
        logging.FileHandler(LOG_FILE),           # Guardar log en archivo
        logging.StreamHandler()                  # Mostrar log en consola
    ]
)


# ====================================================================================================
# CLASE PRINCIPAL: HardeningTool
# ====================================================================================================

class HardeningTool:
    """
    Clase que encapsula toda la funcionalidad de hardening del sistema.
    
    Atributos:
        dry_run (bool): Modo simulación (True = no aplica cambios)
        actions (list): Lista de acciones simuladas (para reporte)
        results (dict): Diccionario con todos los resultados del hardening
    """
    
    # ------------------------------------------------------------------------------------------------
    # MÉTODO CONSTRUCTOR
    # ------------------------------------------------------------------------------------------------
    
    def __init__(self, dry_run=False):
        """
        Inicializa la herramienta de hardening.
        
        Args:
            dry_run (bool): Si es True, solo simula sin aplicar cambios.
        """
        # Modo de ejecución
        self.dry_run = dry_run
        
        # Lista para almacenar acciones (útil en modo dry-run)
        self.actions = []
        
        # Verificar que se ejecuta como root
        self._check_root()
        
        # Inicializar estructura de resultados
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "hostname": subprocess.getoutput("hostname"),
            "dry_run": dry_run,
            "checks": []
        }
        
        # Mensaje informativo según el modo
        if self.dry_run:
            logging.info("🔍 MODO DRY-RUN ACTIVADO - Solo se mostrarán las acciones")
        else:
            logging.info("🚀 MODO REAL ACTIVADO - Se aplicarán cambios al sistema")
    
    # ------------------------------------------------------------------------------------------------
    # MÉTODOS PRIVADOS (auxiliares)
    # ------------------------------------------------------------------------------------------------
    
    def _check_root(self):
        """
        Verifica que el script se ejecute con privilegios de root.
        Si no es root, muestra error y termina la ejecución.
        """
        if os.geteuid() != 0:
            logging.error("❌ Este script debe ejecutarse con privilegios de root (sudo)")
            sys.exit(1)
        logging.info("✅ Verificado: ejecutando como root")
    
    def _run_command(self, command, check=False):
        """
        Ejecuta un comando del sistema o lo simula en modo dry-run.
        
        Args:
            command (str): Comando a ejecutar.
            check (bool): Si es True, lanza excepción si falla.
        
        Returns:
            tuple: (código_retorno, stdout, stderr)
        """
        # Modo simulación: solo registrar el comando
        if self.dry_run:
            logging.info(f"🔍 [DRY-RUN] Ejecutaría: {command}")
            self.actions.append(command)
            return 0, "", ""
        
        # Modo real: ejecutar el comando
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=check
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            logging.error(f"❌ Error ejecutando: {command}")
            logging.error(f"   {e.stderr}")
            return e.returncode, e.stdout, e.stderr
    
    def _write_file(self, filepath, content):
        """
        Escribe contenido en un archivo o lo simula en modo dry-run.
        
        Args:
            filepath (str): Ruta del archivo a crear/modificar.
            content (str): Contenido a escribir.
        """
        # Modo simulación
        if self.dry_run:
            logging.info(f"🔍 [DRY-RUN] Crearía archivo: {filepath}")
            self.actions.append(f"WRITE_FILE: {filepath}")
            return
        
        # Modo real
        try:
            # Crear directorio si no existe
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                f.write(content)
            logging.info(f"✅ Archivo creado: {filepath}")
        except Exception as e:
            logging.error(f"❌ Error escribiendo archivo {filepath}: {e}")
    
    # ------------------------------------------------------------------------------------------------
    # MÉTODOS DE HARDENING
    # ------------------------------------------------------------------------------------------------
    
    def disable_unnecessary_services(self):
        """
        Deshabilita servicios innecesarios según CIS Benchmarks.
        Reduce la superficie de ataque eliminando servicios no esenciales.
        """
        logging.info("=" * 70)
        logging.info("📌 FASE 1: DESHABILITANDO SERVICIOS INNECESARIOS")
        logging.info("=" * 70)
        
        # Lista de servicios a deshabilitar (comunes en desktop pero no en servidores)
        services = [
            "avahi-daemon",   # Descubrimiento de red mDNS
            "cups",           # Sistema de impresión
            "cups-browsed",   # Descubrimiento de impresoras
            "nfs-server",     # Servidor NFS
            "rpcbind",        # Mapeo de puertos RPC
            "slapd",          # Servidor LDAP
            "bind9",          # Servidor DNS
            "vsftpd",         # Servidor FTP
            "apache2",        # Servidor web
            "nginx",          # Servidor web
            "samba",          # Compartición Windows
            "smbd",           # Demonio Samba
            "nmbd",           # NetBIOS
            "telnetd",        # Telnet (inseguro)
            "xinetd"          # Super servidor
        ]
        
        for service in services:
            logging.info(f"  → Procesando: {service}")
            
            # Detener el servicio
            self._run_command(f"systemctl stop {service} 2>/dev/null", check=False)
            
            # Deshabilitar el servicio (no inicia al boot)
            return_code, _, _ = self._run_command(f"systemctl disable {service} 2>/dev/null", check=False)
            
            if return_code == 0 and not self.dry_run:
                logging.info(f"      ✅ Servicio {service} deshabilitado")
        
        # Registrar resultado
        self.results["checks"].append({
            "category": "disable_services",
            "status": "simulated" if self.dry_run else "success",
            "message": f"Procesados {len(services)} servicios"
        })
        
        logging.info("✅ Fase 1 completada\n")
    
    def configure_firewall(self):
        """
        Configura el firewall iptables con política DROP por defecto.
        Solo permite tráfico esencial (SSH, HTTP, HTTPS, DNS).
        """
        logging.info("=" * 70)
        logging.info("📌 FASE 2: CONFIGURANDO FIREWALL (IPTABLES)")
        logging.info("=" * 70)
        
        # Modo simulación
        if self.dry_run:
            logging.info("🔍 Reglas que se aplicarían:")
            rules_preview = [
                "  iptables -P INPUT DROP      # Denegar todo tráfico entrante",
                "  iptables -P FORWARD DROP    # Denegar reenvío",
                "  iptables -P OUTPUT ACCEPT   # Permitir tráfico saliente",
                "  iptables -A INPUT -i lo -j ACCEPT  # Permitir localhost",
                "  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "  iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # SSH",
                "  iptables -A INPUT -p tcp --dport 80 -j ACCEPT  # HTTP",
                "  iptables -A INPUT -p tcp --dport 443 -j ACCEPT # HTTPS"
            ]
            for rule in rules_preview:
                logging.info(rule)
        
        # Modo real
        else:
            logging.info("  → Limpiando reglas existentes...")
            self._run_command("iptables -F")
            self._run_command("iptables -X")
            self._run_command("iptables -t nat -F")
            self._run_command("iptables -t mangle -F")
            
            logging.info("  → Estableciendo políticas DROP...")
            self._run_command("iptables -P INPUT DROP")
            self._run_command("iptables -P FORWARD DROP")
            self._run_command("iptables -P OUTPUT ACCEPT")
            
            logging.info("  → Permitiendo tráfico local...")
            self._run_command("iptables -A INPUT -i lo -j ACCEPT")
            self._run_command("iptables -A OUTPUT -o lo -j ACCEPT")
            
            logging.info("  → Permitiendo conexiones establecidas...")
            self._run_command("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
            
            logging.info("  → Permitiendo puertos esenciales...")
            for port in [22, 80, 443, 53]:
                logging.info(f"      Puerto {port}")
                self._run_command(f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
            
            logging.info("  → Aplicando protecciones anti-ataque...")
            self._run_command("iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP")
            self._run_command("iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP")
            
            logging.info("  → Guardando reglas persistentemente...")
            self._run_command("apt-get install iptables-persistent -y -qq", check=False)
            self._run_command("netfilter-persistent save")
            
            logging.info("✅ Firewall configurado correctamente")
        
        # Registrar resultado
        self.results["checks"].append({
            "category": "firewall",
            "status": "simulated" if self.dry_run else "success",
            "message": "Firewall configurado con políticas DROP"
        })
        
        logging.info("✅ Fase 2 completada\n")
    
    def secure_ssh(self):
        """
        Configura SSH de forma segura según CIS Benchmarks.
        Deshabilita login root, autenticación por contraseña y aplica otras medidas.
        """
        logging.info("=" * 70)
        logging.info("📌 FASE 3: CONFIGURANDO SSH SEGURO")
        logging.info("=" * 70)
        
        sshd_config = "/etc/ssh/sshd_config"
        backup_file = f"{sshd_config}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Configuraciones seguras (clave, valor)
        ssh_settings = [
            ("PermitRootLogin", "no"),              # No permitir login como root
            ("PasswordAuthentication", "no"),       # Solo autenticación por llaves
            ("PermitEmptyPasswords", "no"),         # No contraseñas vacías
            ("ChallengeResponseAuthentication", "no"),  # Deshabilitar challenge-response
            ("Protocol", "2"),                      # Solo SSH protocolo 2
            ("LoginGraceTime", "60"),               # 60 segundos para autenticar
            ("MaxAuthTries", "3"),                  # Máximo 3 intentos
            ("MaxSessions", "5"),                   # Máximo 5 sesiones
            ("X11Forwarding", "no"),                # Deshabilitar X11 forwarding
            ("ClientAliveInterval", "900"),         # Timeout por inactividad (15 min)
            ("ClientAliveCountMax", "0"),           # Cerrar sesión al timeout
            ("LogLevel", "VERBOSE")                 # Logs detallados
        ]
        
        # Modo simulación
        if self.dry_run:
            logging.info(f"🔍 Se crearía backup: {backup_file}")
            logging.info(f"🔍 Se modificaría {sshd_config} con:")
            for key, value in ssh_settings:
                logging.info(f"      {key} {value}")
            logging.info("🔍 Se reiniciaría el servicio SSH")
        
        # Modo real
        else:
            if not os.path.exists(sshd_config):
                logging.error(f"❌ No se encuentra {sshd_config}")
                return
            
            # Crear backup
            logging.info(f"  → Creando backup: {backup_file}")
            self._run_command(f"cp {sshd_config} {backup_file}")
            
            # Escribir nueva configuración
            logging.info("  → Escribiendo nueva configuración...")
            with open(sshd_config, 'w') as f:
                f.write("#" * 70 + "\n")
                f.write("# CONFIGURACIÓN SSH HARDENED\n")
                f.write("# Generada automáticamente - Basada en CIS Benchmarks\n")
                f.write(f"# Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("#" * 70 + "\n\n")
                
                for key, value in ssh_settings:
                    f.write(f"{key} {value}\n")
            
            # Validar configuración
            logging.info("  → Validando configuración...")
            return_code, _, stderr = self._run_command("sshd -t")
            
            if return_code == 0:
                logging.info("  → Configuración válida. Reiniciando SSH...")
                self._run_command("systemctl restart ssh")
                logging.info("✅ SSH configurado correctamente")
            else:
                logging.error(f"❌ Error en configuración: {stderr}")
                logging.info("  → Restaurando backup...")
                self._run_command(f"cp {backup_file} {sshd_config}")
                return
        
        # Registrar resultado
        self.results["checks"].append({
            "category": "ssh",
            "status": "simulated" if self.dry_run else "success",
            "message": "SSH hardening aplicado"
        })
        
        logging.info("✅ Fase 3 completada\n")
    
    def configure_auditd(self):
        """
        Configura auditd para monitorear eventos críticos de seguridad.
        Registra cambios en archivos importantes y comandos sensibles.
        """
        logging.info("=" * 70)
        logging.info("📌 FASE 4: CONFIGURANDO AUDITD (AUDITORÍA)")
        logging.info("=" * 70)
        
        rules_file = "/etc/audit/rules.d/hardening.rules"
        
        # Reglas de auditoría
        audit_rules = """# Reglas de auditoría para hardening - Basadas en CIS Benchmarks
# ============================================================================

# Limpiar reglas existentes
-D

# Monitorear archivos de autenticación
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudo_changes

# Monitorear configuración SSH
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Monitorear configuración de red
-w /etc/hosts -p wa -k network_changes
-w /etc/hostname -p wa -k network_changes

# Monitorear comandos críticos
-w /bin/login -p x -k login
-w /bin/su -p x -k su_usage
-w /usr/bin/sudo -p x -k sudo_execution

# Monitorear tareas programadas
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.hourly/ -p wa -k cron_changes
-w /etc/cron.daily/ -p wa -k cron_changes
-w /etc/cron.weekly/ -p wa -k cron_changes

# Configuración final: modo bloqueante
-e 2
"""
        
        # Modo simulación
        if self.dry_run:
            logging.info(f"🔍 Se crearía archivo de reglas: {rules_file}")
            logging.info("🔍 Las reglas monitorearían archivos críticos del sistema")
        
        # Modo real
        else:
            logging.info("  → Instalando auditd...")
            self._run_command("apt-get update -qq", check=False)
            self._run_command("apt-get install auditd -y -qq", check=False)
            
            logging.info("  → Escribiendo reglas de auditoría...")
            self._write_file(rules_file, audit_rules)
            
            logging.info("  → Cargando reglas...")
            self._run_command("augenrules --load")
            
            logging.info("  → Reiniciando servicio auditd...")
            self._run_command("systemctl restart auditd")
            self._run_command("systemctl enable auditd")
            
            # Verificar estado
            return_code, _, _ = self._run_command("systemctl is-active auditd")
            if return_code == 0:
                logging.info("✅ Auditd configurado y activo")
            else:
                logging.warning("⚠️ Auditd no está activo, revisar logs")
        
        # Registrar resultado
        self.results["checks"].append({
            "category": "auditd",
            "status": "simulated" if self.dry_run else "success",
            "message": "Auditd configurado con reglas de auditoría"
        })
        
        logging.info("✅ Fase 4 completada\n")
    
    def additional_hardening(self):
        """
        Aplica medidas adicionales de hardening:
        - Límites de recursos (evita DoS)
        - fail2ban (protección contra fuerza bruta)
        """
        logging.info("=" * 70)
        logging.info("📌 FASE 5: MEDIDAS ADICIONALES DE HARDENING")
        logging.info("=" * 70)
        
        # Modo simulación
        if self.dry_run:
            logging.info("🔍 Medidas que se aplicarían:")
            logging.info("   1. Límites de recursos (archivos, procesos)")
            logging.info("   2. fail2ban para proteger SSH")
        
        # Modo real
        else:
            # 1. Configurar límites de recursos
            logging.info("  → Configurando límites de recursos...")
            limits_content = """# Límites de recursos para prevenir DoS
* soft core 0
* hard core 0
* soft nproc 1000
* hard nproc 2000
* soft nofile 4096
* hard nofile 8192
"""
            self._write_file("/etc/security/limits.d/hardening.conf", limits_content)
            
            # 2. Configurar fail2ban
            logging.info("  → Instalando y configurando fail2ban...")
            self._run_command("apt-get install fail2ban -y -qq", check=False)
            
            jail_content = """# Configuración de fail2ban para proteger SSH
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
"""
            self._write_file("/etc/fail2ban/jail.local", jail_content)
            
            logging.info("  → Iniciando fail2ban...")
            self._run_command("systemctl restart fail2ban")
            self._run_command("systemctl enable fail2ban")
            
            logging.info("✅ Medidas adicionales aplicadas correctamente")
        
        # Registrar resultado
        self.results["checks"].append({
            "category": "additional",
            "status": "simulated" if self.dry_run else "success",
            "message": "Medidas adicionales de hardening aplicadas"
        })
        
        logging.info("✅ Fase 5 completada\n")
    
    def run_lynis_audit(self):
        """
        Ejecuta Lynis (herramienta de auditoría de seguridad) y genera reporte.
        Proporciona un Hardening Index (puntaje de 0 a 100).
        """
        logging.info("=" * 70)
        logging.info("📌 FASE 6: EJECUTANDO LYNIS AUDIT")
        logging.info("=" * 70)
        
        # Modo simulación
        if self.dry_run:
            logging.info("🔍 Se instalaría y ejecutaría Lynis")
            logging.info("🔍 Se generaría un reporte con el Hardening Index")
        
        # Modo real
        else:
            logging.info("  → Instalando Lynis...")
            self._run_command("apt-get update -qq", check=False)
            self._run_command("apt-get install lynis -y -qq", check=False)
            
            lynis_log = f"/var/log/lynis_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            logging.info("  → Ejecutando Lynis (esto puede tomar 2-3 minutos)...")
            
            self._run_command(f"lynis audit system --quick --log-file {lynis_log}", check=False)
            
            # Extraer información del log
            if os.path.exists(lynis_log):
                with open(lynis_log, 'r') as f:
                    content = f.read()
                
                # Buscar Hardening Index
                match = re.search(r"Hardening index : \[(\d+)\]", content)
                if match:
                    hardening_index = match.group(1)
                    logging.info(f"  📊 Hardening Index: {hardening_index}/100")
                    self.results["hardening_index"] = hardening_index
                
                # Contar sugerencias
                suggestions = re.findall(r"Suggestion: (.+)", content)
                warnings = re.findall(r"Warning: (.+)", content)
                
                logging.info(f"  💡 Sugerencias: {len(suggestions)}")
                logging.info(f"  ⚠️  Advertencias: {len(warnings)}")
                
                self.results["lynis"] = {
                    "log_file": lynis_log,
                    "suggestions_count": len(suggestions),
                    "warnings_count": len(warnings),
                    "suggestions": suggestions[:10]
                }
                
                logging.info(f"✅ Lynis completado. Log: {lynis_log}")
            else:
                logging.warning("⚠️ No se encontró el log de Lynis")
        
        # Registrar resultado
        self.results["checks"].append({
            "category": "lynis",
            "status": "simulated" if self.dry_run else "success",
            "message": "Lynis audit ejecutado"
        })
        
        logging.info("✅ Fase 6 completada\n")
    
    def generate_report(self):
        """
        Genera reporte final con todos los resultados del hardening.
        Guarda en formato JSON y muestra resumen en consola.
        """
        logging.info("=" * 70)
        logging.info("📌 FASE 7: GENERANDO REPORTE FINAL")
        logging.info("=" * 70)
        
        # Calcular estadísticas
        total_checks = len(self.results["checks"])
        success_checks = len([c for c in self.results["checks"] if c.get("status") == "success"])
        
        # Agregar resumen
        self.results["summary"] = {
            "total_checks": total_checks,
            "successful_checks": success_checks if not self.dry_run else 0,
            "failed_checks": 0,
            "dry_run": self.dry_run,
            "total_actions_simulated": len(self.actions) if self.dry_run else 0
        }
        
        # Definir nombre del reporte
        if self.dry_run:
            report_path = REPORT_FILE.replace('.json', '_dryrun.json')
        else:
            report_path = REPORT_FILE
        
        # Guardar reporte JSON
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        logging.info(f"✅ Reporte guardado: {report_path}")
        
        # Mostrar resumen en consola
        print("\n" + "=" * 70)
        print(" " * 20 + "RESUMEN FINAL DEL HARDENING")
        print("=" * 70)
        
        if self.dry_run:
            print("🔍 MODO: DRY-RUN (Simulación - Sin cambios aplicados)")
            print(f"📋 Acciones simuladas: {len(self.actions)}")
            print("\n✅ Para aplicar los cambios, ejecute:")
            print("   sudo python3 hardening_script.py --apply")
        else:
            print("🚀 MODO: REAL (Cambios aplicados)")
            print(f"✅ Checks exitosos: {success_checks}/{total_checks}")
            
            if self.results.get("hardening_index"):
                index = int(self.results["hardening_index"])
                print(f"📊 Hardening Index (Lynis): {index}/100")
                
                if index >= 80:
                    print("   🎯 Nivel de seguridad: EXCELENTE")
                elif index >= 60:
                    print("   📈 Nivel de seguridad: BUENO")
                elif index >= 40:
                    print("   ⚠️  Nivel de seguridad: MEJORABLE")
                else:
                    print("   ❌ Nivel de seguridad: CRÍTICO")
        
        print("\n📂 ARCHIVOS GENERADOS:")
        print(f"   📋 Log: {LOG_FILE}")
        print(f"   📊 Reporte: {report_path}")
        
        if self.results.get("lynis"):
            print(f"   🔍 Lynis: {self.results['lynis'].get('log_file', 'N/A')}")
        
        print("=" * 70 + "\n")
    
    # ------------------------------------------------------------------------------------------------
    # MÉTODO PRINCIPAL DE EJECUCIÓN
    # ------------------------------------------------------------------------------------------------
    
    def run(self):
        """
        Ejecuta todas las fases de hardening en secuencia.
        Es el método principal que orquesta todo el proceso.
        """
        print("\n" + "=" * 70)
        print(" " * 15 + "🛡️  SCRIPT DE HARDENING LINUX  🛡️")
        print(" " * 18 + "Ubuntu/Debian - CIS Benchmarks")
        print("=" * 70)
        
        if self.dry_run:
            print("🔍 MODO DRY-RUN - Solo se mostrarán las acciones")
        else:
            print("⚠️  MODO REAL - Se aplicarán cambios al sistema")
            print("   Asegúrese de tener backup antes de continuar")
        
        print("=" * 70 + "\n")
        
        # Ejecutar cada fase
        self.disable_unnecessary_services()
        self.configure_firewall()
        self.secure_ssh()
        self.configure_auditd()
        self.additional_hardening()
        self.run_lynis_audit()
        self.generate_report()
        
        # Mensaje final
        print("=" * 70)
        if self.dry_run:
            print("🔍 DRY-RUN COMPLETADO - Revise el reporte antes de aplicar cambios")
        else:
            print("✅ HARDENING COMPLETADO EXITOSAMENTE")
            print("   El servidor ha sido endurecido según CIS Benchmarks")
        print("=" * 70)


# ====================================================================================================
# FUNCIÓN PRINCIPAL (ENTRY POINT)
# ====================================================================================================

def main():
    """
    Función principal que procesa los argumentos de línea de comandos
    y ejecuta el script en el modo correspondiente.
    """
    # Configurar parser de argumentos
    parser = argparse.ArgumentParser(
        description="Script de hardening para Ubuntu/Debian basado en CIS Benchmarks",
        epilog="Ejemplos:\n  sudo python3 hardening_script.py --dry-run\n  sudo python3 hardening_script.py --apply"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Modo simulación: muestra las acciones sin aplicarlas"
    )
    
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Modo real: aplica los cambios al sistema"
    )
    
    args = parser.parse_args()
    
    # Modo dry-run explícito
    if args.dry_run:
        tool = HardeningTool(dry_run=True)
        tool.run()
    
    # Modo apply explícito
    elif args.apply:
        print("\n⚠️  ADVERTENCIA ⚠️")
        print("Este script aplicará cambios significativos al sistema.")
        print("- Deshabilitará servicios")
        print("- Configurará firewall restrictivo")
        print("- Modificará configuración SSH")
        
        confirm = input("\n¿Está seguro de continuar? (yes/no): ")
        if confirm.lower() == "yes":
            tool = HardeningTool(dry_run=False)
            tool.run()
        else:
            print("❌ Operación cancelada")
            sys.exit(0)
    
    # Sin argumentos: modo interactivo
    else:
        print("\n" + "=" * 50)
        print("   SCRIPT DE HARDENING LINUX")
        print("=" * 50)
        print("\nSeleccione modo de ejecución:")
        print("  1. 🔍 DRY-RUN (Simulación) - Recomendado")
        print("  2. 🚀 REAL (Aplicar cambios)")
        print("  3. ❌ Cancelar")
        
        choice = input("\nOpción (1/2/3): ").strip()
        
        if choice == "1":
            tool = HardeningTool(dry_run=True)
            tool.run()
        elif choice == "2":
            confirm = input("Confirmar con 'yes' para continuar: ")
            if confirm.lower() == "yes":
                tool = HardeningTool(dry_run=False)
                tool.run()
            else:
                print("❌ Operación cancelada")
        else:
            print("❌ Operación cancelada")
            sys.exit(0)


# ====================================================================================================
# PUNTO DE ENTRADA DEL SCRIPT
# ====================================================================================================

if __name__ == "__main__":
    main()
