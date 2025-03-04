import subprocess
import time
import logging
import os
import signal
import psutil
import requests
from typing import Optional, Tuple
from ..config import Config

logger = logging.getLogger(__name__)

class ModelManager:
    """Manages model installation and cleanup."""
    
    def __init__(self):
        self.current_model = None
        self.model_parameter = None
        self.api_base = "http://localhost:11434"
        
    def check_ollama_running(self) -> bool:
        """Check if ollama is running and responding"""
        try:
            # First check if process exists
            process_exists = False
            for proc in psutil.process_iter(['name']):
                if 'ollama' in proc.info['name']:
                    process_exists = True
                    break
                
            if not process_exists:
                return False
            
            # Then check if API is responding by listing models
            response = requests.get(f"{self.api_base}/api/tags")
            return response.status_code == 200
        except:
            return False
            
    def wait_for_ollama(self, timeout: int = 60) -> bool:
        """Wait for Ollama to be responsive"""
        logger.info("Waiting for Ollama to become responsive...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.check_ollama_running():
                logger.info("Ollama is now responsive")
                return True
            logger.debug("Waiting for Ollama to start...")
            time.sleep(2)
        return False

    def start_ollama(self):
        """Start ollama server"""
        logger.info("Please start Ollama manually using: nohup ~/ollama/bin/ollama serve &>/dev/null & disown")
        raise Exception("Ollama needs to be started manually")

    def kill_ollama_processes(self):
        """Kill all Ollama processes"""
        try:
            # First try SIGTERM
            for proc in psutil.process_iter(['name', 'pid', 'cmdline']):
                try:
                    if 'ollama' in proc.info['name'].lower():
                        logger.info(f"Found Ollama process: PID={proc.info['pid']}, CMD={' '.join(proc.info['cmdline'])}")
                        logger.info(f"Sending SIGTERM to Ollama process {proc.info['pid']}")
                        os.kill(proc.info['pid'], signal.SIGTERM)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Wait and check if processes are gone
            time.sleep(5)
            
            # If any remain, use SIGKILL
            for proc in psutil.process_iter(['name', 'pid']):
                try:
                    if 'ollama' in proc.info['name'].lower():
                        logger.info(f"Process {proc.info['pid']} still running, sending SIGKILL")
                        os.kill(proc.info['pid'], signal.SIGKILL)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                
            # Final wait
            time.sleep(2)
            
            # Verify all processes are gone
            remaining = []
            for proc in psutil.process_iter(['name', 'pid']):
                if 'ollama' in proc.info['name'].lower():
                    remaining.append(proc.info['pid'])
            
            if remaining:
                raise Exception(f"Failed to kill Ollama processes: {remaining}")
                
        except Exception as e:
            logger.error(f"Error killing Ollama processes: {e}")
            raise

    def ensure_ollama_running(self):
        """Ensure ollama is running"""
        try:
            # Kill any existing Ollama processes
            self.kill_ollama_processes()
            
            # Start fresh Ollama process
            logger.info("Starting fresh Ollama instance...")
            ollama_path = os.path.expanduser("~/ollama/bin/ollama")
            
            # First try to start the server
            start_cmd = f"nohup {ollama_path} serve &>/dev/null & disown"
            subprocess.run(start_cmd, shell=True)
            
            # Wait for it to become responsive
            logger.info("Waiting for Ollama to become responsive...")
            start_time = time.time()
            max_wait = 60  # Wait up to 60 seconds
            
            while time.time() - start_time < max_wait:
                try:
                    # Try to list models as a health check
                    response = requests.get(f"{self.api_base}/api/tags")
                    if response.status_code == 200:
                        logger.info("Ollama is now running and responsive")
                        return
                    else:
                        logger.debug(f"Ollama returned status {response.status_code}")
                except requests.exceptions.ConnectionError:
                    logger.debug("Connection refused - Ollama still starting")
                except Exception as e:
                    logger.debug(f"Error checking Ollama: {str(e)}")
                time.sleep(2)
            
            # If we get here, try to get more diagnostic information
            try:
                ps_output = subprocess.check_output(["ps", "aux", "|", "grep", "ollama"]).decode()
                logger.error(f"Ollama processes:\n{ps_output}")
            except:
                pass
                
            try:
                netstat_output = subprocess.check_output(["netstat", "-tlpn", "|", "grep", "11434"]).decode()
                logger.error(f"Port 11434 status:\n{netstat_output}")
            except:
                pass
            
            raise Exception("Ollama failed to become responsive after fresh start")
            
        except Exception as e:
            logger.error(f"Error ensuring Ollama is running: {e}")
            raise

    def restart_ollama(self):
        """Restart Ollama"""
        try:
            logger.info("Restarting Ollama...")
            self.ensure_ollama_running()
        except Exception as e:
            logger.error(f"Failed to restart Ollama: {e}")
            raise

    def install_model(self, model_name: str) -> Tuple[bool, str]:
        """Install a model using ollama."""
        try:
            if not self.check_ollama_running():
                return False, "Ollama is not running"

            self.current_model = model_name
            self.model_parameter = Config.get_model_identifier(model_name)
            
            # Create Modelfile
            modelfile_content = f"FROM {Config.MODELS[model_name].split()[0]}\n"
            modelfile_content += "PARAMETER num_ctx 16384\n"
            
            with open("Modelfile", "w") as f:
                f.write(modelfile_content)
            
            logger.info(f"Modelfile created with content:\n{modelfile_content}")
            
            # Create custom model
            create_cmd = f"ollama create -f Modelfile {self.model_parameter}"
            logger.info(f"Running command: {create_cmd}")
            result = subprocess.run(create_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                return False, f"Model creation failed: {result.stderr}"
            
            # Test run model
            run_cmd = f"ollama run {self.model_parameter}"
            logger.info(f"Installing model {model_name} using command: {run_cmd}")
            
            return True, "Model installed successfully"
            
        except Exception as e:
            return False, str(e)
