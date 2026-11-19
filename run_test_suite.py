"""
Ejecutor de la suite completa de pruebas:
Inicia los tres microservicios en subprocesos, espera a que estén listos,
ejecuta test_exploits.py y finalmente apaga los procesos de forma limpia.
"""
import sys
import subprocess
import time
import os
import requests

PYTHON_EXE = sys.executable

def wait_for_service(url, timeout=12):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=1)
            if r.status_code in [200, 404]:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False

def main():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.dirname(__file__))

    print("Iniciando Microservicio 1 (Puerto 8001)...")
    p1 = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "user_service.main:app", "--host", "127.0.0.1", "--port", "8001"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    print("Iniciando Microservicio 2 (Puerto 8002)...")
    p2 = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "cluster_service.main:app", "--host", "127.0.0.1", "--port", "8002"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    print("Iniciando API Gateway (Puerto 8000)...")
    p3 = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    try:
        print("Esperando conexión con el API Gateway...")
        if not wait_for_service("http://127.0.0.1:8000", timeout=12):
            print("Error: El API Gateway no respondió a tiempo.")
            return 1
        
        print("Servicios listos y en línea. Ejecutando exploits y pruebas...\n")
        res = subprocess.run([PYTHON_EXE, "test_exploits.py"], env=env)
        return res.returncode

    finally:
        print("\nApagando microservicios...")
        p3.terminate()
        p2.terminate()
        p1.terminate()
        p3.wait()
        p2.wait()
        p1.wait()
        print("Microservicios apagados correctamente.")

if __name__ == "__main__":
    sys.exit(main())
