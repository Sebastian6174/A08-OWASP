import sys
import subprocess
import time
import os
import requests

PYTHON_EXE = sys.executable

def main():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.dirname(__file__))

    p1 = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "user_service.main:app", "--host", "127.0.0.1", "--port", "8001"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    p2 = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "cluster_service.main:app", "--host", "127.0.0.1", "--port", "8002"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    p3 = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    time.sleep(3)
    # Check if any exited
    for name, p in [("user", p1), ("cluster", p2), ("gateway", p3)]:
        if p.poll() is not None:
            stdout, stderr = p.communicate()
            print(f"Service {name} exited with code {p.returncode}")
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")

    try:
        r = requests.get("http://127.0.0.1:8000/", timeout=3)
        print("Gateway status code:", r.status_code)
    except Exception as e:
        print("Request failed:", e)
        for name, p in [("user", p1), ("cluster", p2), ("gateway", p3)]:
            stdout, stderr = p.communicate(timeout=1) if p.poll() is not None else ("", "")
            print(f"{name} poll={p.poll()} stdout={stdout} stderr={stderr}")
    finally:
        p3.terminate()
        p2.terminate()
        p1.terminate()

if __name__ == "__main__":
    main()

