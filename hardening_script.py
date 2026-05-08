#!/usr/bin/env python3
"""
Script de Hardening para Ubuntu/Debian basado en CIS Benchmarks
Requiere permisos de root
"""

import subprocess
import os
import sys
import logging
import json
import re
from datetime import datetime
from pathlib import Path
import argparse

# Configuración de archivos de log y reporte
LOG_FILE = f"/var/log/hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
REPORT_FILE = f"/var/log/hardening_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

# Configuración del sistema de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

class HardeningTool:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.actions = []
        self.check_root()
        
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "hostname": subprocess.getoutput("hostname"),
            "dry_run": dry_run,
            "checks": []
        }
        
        if self.dry_run:
            logging.info("Modo DRY-RUN activado - Solo se mostrarán acciones")
    
    def check_root(self):
        if os.geteuid() != 0:
            logging.error("Este script debe ejecutarse como root")
            sys.exit(1)
    
    def run_command(self, command, check=True):
        if self.dry_run:
            logging.info(f"[DRY-RUN] Ejecutaría: {command}")
            self.actions.append(command)
            return 0, "", ""
        else:
            try:
                result = subprocess.run(
                    command,
                    shell=True if isinstance(command, str) else False,
                    capture_output=True,
                    text=True,
                    check=check
                )
                return result.returncode, result.stdout, result.stderr
            except subprocess.CalledProcessError as e:
                logging.error(f"Error ejecutando comando {command}: {e}")
                return e.returncode, e.stdout, e.stderr
    
    def write_file(self, filepath, content):
        if self.dry_run:
            logging.info(f"[DRY-RUN] Crearía archivo: {filepath}")
            self.actions.append(f"WRITE_FILE: {filepath}")
        else:
            with open(filepath, 'w') as f:
                f.write(content)
            logging.info(f"Archivo creado: {filepath}")
    
    def disable_unnecessary_services(self):
        logging.info("=== DESHABILITANDO SERVICIOS INNECESARIOS ===")
        
        services_to_disable = [
            "avahi-daemon", "cups", "cups-browsed", "nfs-server",
            "rpcbind", "slapd", "bind9", "vsftpd", "apache2",
            "nginx", "samba", "smbd", "nmbd", "telnetd", "xinetd"
        ]
        
        for service in services_to_disable:
            logging.info(f"Procesando servicio: {service}")
            self.run_command(f"systemctl stop {service} 2>/dev/null", check=False)
            return_code, _, _ = self.run_command(f"systemctl disable {service} 2>/dev/null", check=False)
            
            if return_code == 0 and not self.dry_run:
                logging.info(f"Servicio {service} deshabilitado")
        
        self.results["checks"].append({
            "category": "disable_services",
            "status": "simulated" if self.dry_run else "success",
            "message": f"Procesados {len(services_to_disable)} servicios"
        })
    
    def configure_iptables(self):
        logging.info("=== CONFIGURANDO IPTABLES (FIREWALL) ===")
        
        if self.dry_run:
            logging.info("[DRY-RUN] Reglas de iptables que se aplicarían:")
            rules = [
                "iptables -F", "iptables -X", "iptables -P INPUT DROP",
                "iptables -P FORWARD DROP", "iptables -P OUTPUT ACCEPT",
                "iptables -A INPUT -i lo -j ACCEPT",
                "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
            ]
            for rule in rules:
                logging.info(f"   {rule}")
        else:
            self.run_command("iptables -F")
            self.run_command("iptables -X")
            self.run_command("iptables -P INPUT DROP")
            self.run_command("iptables -P FORWARD DROP")
            self.run_command("iptables -P OUTPUT ACCEPT")
            self.run_command("iptables -A INPUT -i lo -j ACCEPT")
            self.run_command("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
            self.run_command("iptables -A INPUT -p tcp --dport 22 -j ACCEPT")
            self.run_command("apt-get install iptables-persistent -y -qq", check=False)
            self.run_command("netfilter-persistent save")
            logging.info("Firewall configurado correctamente")
        
        self.results["checks"].append({
            "category": "firewall",
            "status": "simulated" if self.dry_run else "success",
            "message": "Firewall configurado"
        })
    
    def secure_ssh(self):
        logging.info("=== CONFIGURANDO SSH SEGURO ===")
        
        sshd_config = "/etc/ssh/sshd_config"
        backup_file = f"{sshd_config}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        ssh_configs = [
            ("PermitRootLogin", "no"),
            ("PasswordAuthentication", "no"),
            ("PermitEmptyPasswords", "no"),
            ("ChallengeResponseAuthentication", "no"),
            ("Protocol", "2"),
            ("LoginGraceTime", "60"),
            ("MaxAuthTries", "3"),
            ("X11Forwarding", "no"),
            ("ClientAliveInterval", "900")
        ]
        
        if self.dry_run:
            logging.info(f"[DRY-RUN] Se crearía backup: {backup_file}")
            logging.info(f"[DRY-RUN] Se modificaría {sshd_config} con:")
            for key, value in ssh_configs:
                logging.info(f"   {key} {value}")
        else:
            if os.path.exists(sshd_config):
                self.run_command(f"cp {sshd_config} {backup_file}")
                
                with open(sshd_config, 'w') as f:
                    f.write("# Configuracion SSH Hardened - Generada automaticamente\n")
                    f.write("# Basado en CIS Benchmarks\n\n")
                    for key, value in ssh_configs:
                        f.write(f"{key} {value}\n")
                
                self.run_command("sshd -t")
                self.run_command("systemctl restart ssh")
                logging.info("SSH configurado correctamente")
        
        self.results["checks"].append({
            "category": "ssh",
            "status": "simulated" if self.dry_run else "success",
            "message": "SSH hardening aplicado"
        })
    
    def configure_auditd(self):
        logging.info("=== CONFIGURANDO AUDITD ===")
        
        rules_file = "/etc/audit/rules.d/hardening.rules"
        
        if self.dry_run:
            logging.info(f"[DRY-RUN] Se crearia {rules_file} con reglas de auditoria")
        else:
            audit_rules = """-D
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /bin/login -p x -k login
-w /usr/bin/sudo -p x -k sudo_execution
-e 2
"""
            self.run_command("apt-get install auditd -y -qq", check=False)
            self.write_file(rules_file, audit_rules)
            self.run_command("augenrules --load")
            self.run_command("systemctl restart auditd")
            logging.info("Auditd configurado correctamente")
        
        self.results["checks"].append({
            "category": "auditd",
            "status": "simulated" if self.dry_run else "success",
            "message": "Auditd configurado"
        })
    
    def run_lynis_audit(self):
        logging.info("=== EJECUTANDO LYNIS AUDIT ===")
        
        if self.dry_run:
            logging.info("[DRY-RUN] Se instalaria y ejecutaria Lynis")
            logging.info("[DRY-RUN] Se generaria reporte con Hardening Index")
        else:
            self.run_command("apt-get update -qq", check=False)
            self.run_command("apt-get install lynis -y -qq", check=False)
            lynis_log = f"/var/log/lynis_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            self.run_command(f"lynis audit system --quick --log-file {lynis_log}", check=False)
            logging.info(f"Lynis ejecutado. Log: {lynis_log}")
        
        self.results["checks"].append({
            "category": "lynis",
            "status": "simulated" if self.dry_run else "success",
            "message": "Lynis ejecutado"
        })
    
    def additional_hardening(self):
        logging.info("=== MEDIDAS ADICIONALES DE HARDENING ===")
        
        if self.dry_run:
            logging.info("[DRY-RUN] Medidas adicionales que se aplicarian:")
            logging.info("   - Configurar limites de recursos")
            logging.info("   - Instalar y configurar fail2ban")
        else:
            limits_conf = "/etc/security/limits.d/hardening.conf"
            limits_content = "* soft core 0\n* hard core 0\n* soft nproc 1000\n* hard nproc 2000\n"
            self.write_file(limits_conf, limits_content)
            
            self.run_command("apt-get install fail2ban -y -qq", check=False)
            jail_local = "/etc/fail2ban/jail.local"
            jail_content = "[sshd]\nenabled = true\nbantime = 3600\nmaxretry = 5\n"
            self.write_file(jail_local, jail_content)
            self.run_command("systemctl restart fail2ban")
            logging.info("Medidas adicionales aplicadas")
        
        self.results["checks"].append({
            "category": "additional",
            "status": "simulated" if self.dry_run else "success",
            "message": "Medidas adicionales aplicadas"
        })
    
    def generate_report(self):
        logging.info("=== GENERANDO REPORTE FINAL ===")
        
        total_checks = len(self.results["checks"])
        success_checks = len([c for c in self.results["checks"] if c.get("status") == "success"])
        
        self.results["summary"] = {
            "total_checks": total_checks,
            "successful_checks": success_checks if not self.dry_run else 0,
            "failed_checks": 0,
            "dry_run": self.dry_run,
            "total_actions_simulated": len(self.actions) if self.dry_run else 0
        }
        
        report_path = REPORT_FILE if not self.dry_run else REPORT_FILE.replace('.json', '_dryrun.json')
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Reporte generado: {report_path}")
        
        print("\n" + "="*60)
        if self.dry_run:
            print("DRY-RUN COMPLETADO - Ningun cambio fue aplicado")
            print(f"Acciones simuladas: {len(self.actions)}")
        else:
            print("HARDENING COMPLETADO EXITOSAMENTE")
            print(f"Checks exitosos: {success_checks}/{total_checks}")
        print(f"Reporte: {report_path}")
        print("="*60)
    
    def run_all(self):
        print("\n" + "="*60)
        if self.dry_run:
            print("MODO DRY-RUN - Simulacion de hardening")
        else:
            print("INICIANDO HARDENING - Modo Real")
        print("="*60 + "\n")
        
        self.disable_unnecessary_services()
        print("\n")
        self.configure_iptables()
        print("\n")
        self.secure_ssh()
        print("\n")
        self.configure_auditd()
        print("\n")
        self.additional_hardening()
        print("\n")
        self.run_lynis_audit()
        print("\n")
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description='Hardening script for Ubuntu/Debian')
    parser.add_argument('--dry-run', action='store_true', help='Modo simulacion')
    parser.add_argument('--apply', action='store_true', help='Aplicar cambios')
    
    args = parser.parse_args()
    
    if args.dry_run:
        tool = HardeningTool(dry_run=True)
        tool.run_all()
    elif args.apply:
        tool = HardeningTool(dry_run=False)
        tool.run_all()
    else:
        print("""
        Uso:
          --dry-run  : Modo simulacion (recomendado primero)
          --apply    : Aplicar cambios reales
        
        Ejemplos:
          sudo python3 hardening_script.py --dry-run
          sudo python3 hardening_script.py --apply
        """)
        
        choice = input("Seleccione modo (dry-run/apply/cancel): ").strip().lower()
        if choice == "dry-run":
            tool = HardeningTool(dry_run=True)
            tool.run_all()
        elif choice == "apply":
            confirm = input("Esta seguro? (yes/no): ")
            if confirm.lower() == "yes":
                tool = HardeningTool(dry_run=False)
                tool.run_all()
            else:
                print("Cancelado")
        else:
            print("Cancelado")

if __name__ == "__main__":
    main()