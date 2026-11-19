"""
Orquestador local para iniciar los 3 servicios simultáneamente:
- Gateway (Proxy): Puerto 8000
- Microservicio 1 (User & Auth): Puerto 8001
- Microservicio 2 (Cluster & Deployment): Puerto 8002
"""
import sys
import subprocess
import time
import os
import signal

PYTHON_EXE = sys.executable

def start_services():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.dirname(__file__))

    print("=" * 60)
    print("🚀 INICIANDO ARQUITECTURA DE MICROSERVICIOS Y PROXY")
    print("=" * 60)

    p1 = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "user_service.main:app", "--host", "127.0.0.1", "--port", "8001"],
        env=env
    )
    print("  [+] Microservicio 1 (User & Auth) corriendo en http://127.0.0.1:8001")

    p2 = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "cluster_service.main:app", "--host", "127.0.0.1", "--port", "8002"],
        env=env
    )
    print("  [+] Microservicio 2 (Cluster & Deployment) corriendo en http://127.0.0.1:8002")

    time.sleep(1.5)

    p3 = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000"],
        env=env
    )
    print("  [+] API Gateway (Proxy) corriendo en http://127.0.0.1:8000")
    print("=" * 60)
    print("Accede a la documentación OpenAPI interactiva en: http://127.0.0.1:8000/docs")
    print("Presiona Ctrl+C para detener todos los servicios.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDeteniendo servicios...")
        p3.terminate()
        p2.terminate()
        p1.terminate()
        print("Servicios detenidos.")

if __name__ == "__main__":
    start_services()

