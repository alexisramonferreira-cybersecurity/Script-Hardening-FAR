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
from datetime import datetime
from pathlib import Path

# Configuración de logging
LOG_FILE = f"/var/log/hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
REPORT_FILE = f"/var/log/hardening_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

class HardeningTool:
    def __init__(self):
        self.check_root()
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "hostname": subprocess.getoutput("hostname"),
            "checks": []
        }
    
    def check_root(self):
        """Verifica que el script se ejecute como root"""
        if os.geteuid() != 0:
            logging.error("Este script debe ejecutarse como root")
            sys.exit(1)
    
    def