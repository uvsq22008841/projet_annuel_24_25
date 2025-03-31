# modules/sandbox/sandbox_manager.py
import os
import subprocess
import tempfile
import json
import time
import threading
import psutil
import logging
from datetime import datetime

class SandboxManager:
    def __init__(self, timeout=60, log_dir="sandbox_logs"):
        self.timeout = timeout
        self.log_dir = log_dir
        
        # Créer le répertoire de logs s'il n'existe pas
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # Configurer le logger
        self.logger = logging.getLogger("sandbox")
        self.logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(os.path.join(self.log_dir, "sandbox.log"))
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
    
    def run_file(self, file_path):
        """Exécute un fichier dans un environnement sandbox et analyse son comportement"""
        self.logger.info(f"Début de l'analyse du fichier: {file_path}")
        
        # Générer un ID unique pour cette analyse
        analysis_id = datetime.now().strftime("%Y%m%d%H%M%S")
        analysis_dir = os.path.join(self.log_dir, analysis_id)
        os.makedirs(analysis_dir, exist_ok=True)
        
        # Préparer le dossier de logs pour cette analyse
        process_log = os.path.join(analysis_dir, "process.log")
        file_log = os.path.join(analysis_dir, "file.log")
        network_log = os.path.join(analysis_dir, "network.log")
        
        # Créer les résultats de base
        results = {
            "analysis_id": analysis_id,
            "file_path": file_path,
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "timeout": self.timeout,
            "execution_successful": False,
            "processes": [],
            "files": [],
            "network": [],
            "registry": [],
            "error": None
        }
        
        try:
            # Démarrer les moniteurs
            process_monitor = threading.Thread(target=self._monitor_processes, 
                                             args=(analysis_id, process_log, results))
            file_monitor = threading.Thread(target=self._monitor_files, 
                                          args=(analysis_id, file_log, results))
            network_monitor = threading.Thread(target=self._monitor_network, 
                                             args=(analysis_id, network_log, results))
            
            process_monitor.daemon = True
            file_monitor.daemon = True
            network_monitor.daemon = True
            
            process_monitor.start()
            file_monitor.start()
            network_monitor.start()
            
            # Exécuter le fichier (à adapter selon le type de fichier)
            exec_result = self._execute_file(file_path, analysis_dir)
            results["execution_output"] = exec_result.get("output", "")
            results["execution_successful"] = exec_result.get("success", False)
            
            # Attendre la fin des moniteurs
            process_monitor.join(self.timeout)
            file_monitor.join(self.timeout)
            network_monitor.join(self.timeout)
            
            # Enregistrer les résultats
            results["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            results["behavior_summary"] = self._generate_behavior_summary(results)
            
            with open(os.path.join(analysis_dir, "results.json"), "w") as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Analyse terminée pour {file_path}")
            return results
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse: {str(e)}")
            results["error"] = str(e)
            results["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(os.path.join(analysis_dir, "results.json"), "w") as f:
                json.dump(results, f, indent=2)
            
            return results
    
    def _execute_file(self, file_path, analysis_dir):
        """
        Exécute le fichier en fonction de son type
        Cette méthode doit être adaptée à l'environnement et aux types de fichiers
        """
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Commande d'exécution en fonction du type de fichier
        if file_ext in ['.exe', '.com']:
            cmd = [file_path]
        elif file_ext in ['.bat', '.cmd']:
            cmd = ['cmd', '/c', file_path]
        elif file_ext in ['.vbs', '.js']:
            cmd = ['cscript', '//E:vbscript', file_path]
        elif file_ext in ['.ps1']:
            cmd = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', file_path]
        elif file_ext in ['.py']:
            cmd = ['python', file_path]
        elif file_ext in ['.jar']:
            cmd = ['java', '-jar', file_path]
        elif file_ext in ['.sh']:
            cmd = ['bash', file_path]
        else:
            return {
                "success": False,
                "output": f"Type de fichier non pris en charge: {file_ext}"
            }
        
        try:
            # Exécution avec redirection de la sortie
            output_file = os.path.join(analysis_dir, "execution_output.txt")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                shell=False,  # Plus sécurisé, mais peut nécessiter shell=True pour certains fichiers
                cwd=os.path.dirname(file_path)
            )
            
            # Attendre la fin ou le timeout
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                success = process.returncode
                stdout, stderr = process.communicate(timeout=self.timeout)
                success = process.returncode == 0
                output = f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}"
               
                # Écrire la sortie dans un fichier
                with open(output_file, "w") as f:
                   f.write(output)
               
                return {
                   "success": success,
                   "output": output,
                   "return_code": process.returncode
               }
               
            except subprocess.TimeoutExpired:
               process.kill()
               return {
                   "success": False,
                   "output": f"L'exécution a dépassé le délai de {self.timeout} secondes",
                   "timeout": True
               }
       
        except Exception as e:
           return {
               "success": False,
               "output": f"Erreur lors de l'exécution: {str(e)}"
           }
   
    def _monitor_processes(self, analysis_id, log_file, results):
       """Moniteur des processus créés pendant l'exécution"""
       # Obtenir la liste des processus avant l'exécution
       processes_before = set(p.pid for p in psutil.process_iter())
       
       with open(log_file, "w") as f:
           f.write(f"[{datetime.now()}] Démarrage du moniteur de processus\n")
           
           # Boucle de surveillance
           end_time = time.time() + self.timeout
           while time.time() < end_time:
               # Obtenir la liste actuelle des processus
               current_processes = psutil.process_iter()
               
               for process in current_processes:
                   try:
                       if process.pid not in processes_before:
                           # Nouveau processus détecté
                           process_info = {
                               "pid": process.pid,
                               "name": process.name(),
                               "creation_time": datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                               "command_line": process.cmdline() if hasattr(process, "cmdline") else None,
                               "exe": process.exe() if hasattr(process, "exe") else None
                           }
                           
                           # Ajouter aux résultats
                           if process_info not in results["processes"]:
                               results["processes"].append(process_info)
                               
                               # Loguer le nouveau processus
                               log_entry = f"[{datetime.now()}] Nouveau processus: PID={process.pid}, Nom={process.name()}, Exe={process_info['exe']}\n"
                               f.write(log_entry)
                   except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                       continue
               
               time.sleep(0.5)
           
           f.write(f"[{datetime.now()}] Arrêt du moniteur de processus\n")
   
    def _monitor_files(self, analysis_id, log_file, results):
       """Moniteur des opérations de fichiers pendant l'exécution"""
       # Cette fonction est un placeholder
       # En environnement réel, il faudrait utiliser un hook système pour capturer les opérations de fichier
       # Comme ptrace sous Linux ou des hooks de filesystem sous Windows
       
       with open(log_file, "w") as f:
           f.write(f"[{datetime.now()}] Démarrage du moniteur de fichiers\n")
           f.write(f"[{datetime.now()}] Ce moniteur est un placeholder et nécessite une implémentation spécifique à l'OS\n")
           f.write(f"[{datetime.now()}] Arrêt du moniteur de fichiers\n")
   
    def _monitor_network(self, analysis_id, log_file, results):
       """Moniteur des connexions réseau pendant l'exécution"""
       # Obtenir les connexions avant l'exécution
       connections_before = set()
       for conn in psutil.net_connections(kind='all'):
           if conn.laddr and conn.raddr:
               connections_before.add((
                   conn.laddr.ip, conn.laddr.port,
                   conn.raddr.ip, conn.raddr.port,
                   conn.status, conn.type
               ))
       
       with open(log_file, "w") as f:
           f.write(f"[{datetime.now()}] Démarrage du moniteur réseau\n")
           
           # Boucle de surveillance
           end_time = time.time() + self.timeout
           while time.time() < end_time:
               # Obtenir les connexions actuelles
               try:
                   current_connections = psutil.net_connections(kind='all')
                   
                   for conn in current_connections:
                       if conn.laddr and conn.raddr:
                           connection_tuple = (
                               conn.laddr.ip, conn.laddr.port,
                               conn.raddr.ip, conn.raddr.port,
                               conn.status, conn.type
                           )
                           
                           if connection_tuple not in connections_before:
                               # Nouvelle connexion détectée
                               connection_info = {
                                   "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                                   "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                                   "status": conn.status,
                                   "type": "TCP" if conn.type == psutil.SOCK_STREAM else "UDP",
                                   "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                               }
                               
                               # Ajouter aux résultats
                               if connection_info not in results["network"]:
                                   results["network"].append(connection_info)
                                   
                                   # Loguer la nouvelle connexion
                                   log_entry = f"[{datetime.now()}] Nouvelle connexion: {connection_info['local_address']} -> {connection_info['remote_address']} ({connection_info['status']})\n"
                                   f.write(log_entry)
                                   
                               # Ajouter à la liste des connexions connues
                               connections_before.add(connection_tuple)
               except (psutil.AccessDenied, psutil.NoSuchProcess):
                   continue
               
               time.sleep(1)
           
           f.write(f"[{datetime.now()}] Arrêt du moniteur réseau\n")
   
    def _generate_behavior_summary(self, results):
       """Génère un résumé du comportement observé"""
       summary = {
           "risk_level": "Faible",
           "indicators": [],
           "mitre_techniques": []
       }
       
       # Analyse des processus
       if len(results["processes"]) > 5:
           summary["indicators"].append("Création d'un nombre élevé de processus")
           summary["mitre_techniques"].append({
               "id": "T1055",
               "name": "Process Injection",
               "description": "Création de multiples processus qui pourrait indiquer une injection de processus"
           })
       
       suspicious_processes = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe"]
       for process in results["processes"]:
           process_name = process.get("name", "").lower()
           if any(susp in process_name for susp in suspicious_processes):
               summary["indicators"].append(f"Processus suspect: {process_name}")
               summary["mitre_techniques"].append({
                   "id": "T1059",
                   "name": "Command and Scripting Interpreter",
                   "description": f"Utilisation de {process_name} pour l'exécution de commandes"
               })
       
       # Analyse des connexions réseau
       if len(results["network"]) > 0:
           summary["indicators"].append(f"Activité réseau détectée: {len(results['network'])} connexions")
           summary["mitre_techniques"].append({
               "id": "T1071",
               "name": "Application Layer Protocol",
               "description": "Communication via des protocoles de couche application"
           })
       
       # Déterminer le niveau de risque
       if len(summary["indicators"]) > 3:
           summary["risk_level"] = "Moyen"
       if len(summary["indicators"]) > 5:
           summary["risk_level"] = "Élevé"
       if "Processus suspect" in str(summary["indicators"]) or len(summary["network"]) > 2:
           summary["risk_level"] = "Élevé"
       
       return summary