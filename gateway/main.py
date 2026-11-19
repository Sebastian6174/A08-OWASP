"""
API Gateway / Proxy (Puerto 8000)
Actúa como punto único de entrada público que enruta hacia:
- Microservicio 1: Auth & User Service (Puerto 8001)
- Microservicio 2: Cluster & Deployment Service (Puerto 8002)

Demuestra el comportamiento de un Gateway en arquitecturas de microservicios:
- Tránsito sin validación: Reenvío ciego de payloads y tokens sin verificar firma ni integridad.
- Puerta de enlace hacia endpoints vulnerables y seguros.
"""
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
import httpx

from common.config import USER_SERVICE_URL, CLUSTER_SERVICE_URL

app = FastAPI(
    title="API Gateway / Proxy Inseguro vs Seguro",
    description="Gateway de Microservicios para Demostración de Vulnerabilidades OWASP y Soluciones",
    version="1.0.0"
)

async def forward_request(target_url: str, request: Request, method: str = "POST"):
    """Reenvía la petición al microservicio interno preservando cabeceras y contenido."""
    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)

    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.request(
            method=method,
            url=target_url,
            content=body if method != "GET" else None,
            headers=headers
        )
        return Response(
            content=res.content,
            status_code=res.status_code,
            media_type=res.headers.get("content-type")
        )

@app.get("/", response_class=HTMLResponse)
def index():
    """Página de inicio visual que resume la arquitectura y endpoints del prototipo."""
    return """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Microservicios: Vulnerabilidades vs Soluciones</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 30px; background: #0f172a; color: #f8fafc; }
            h1 { color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }
            .badge-vuln { background: #ef4444; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
            .badge-sec { background: #22c55e; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
            .card { background: #1e293b; border-radius: 8px; padding: 18px; margin-bottom: 20px; border-left: 5px solid #38bdf8; }
            .card-vuln { border-left-color: #ef4444; }
            .card-sec { border-left-color: #22c55e; }
            code { background: #334155; padding: 2px 6px; border-radius: 4px; color: #f1f5f9; }
            ul { line-height: 1.6; }
            a { color: #38bdf8; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>🛡️ Prototipo de Microservicios: OWASP & Arquitectura Segura</h1>
        <p>Este sistema implementa un <strong>API Gateway (Proxy)</strong> y dos <strong>Microservicios</strong>:</p>
        <ul>
            <li><strong>Gateway (Proxy):</strong> <code>http://127.0.0.1:8000</code></li>
            <li><strong>Microservicio 1 (User & Auth):</strong> <code>http://127.0.0.1:8001</code></li>
            <li><strong>Microservicio 2 (Cluster & Deployment):</strong> <code>http://127.0.0.1:8002</code></li>
        </ul>
        <p>Documentación Swagger interactiva: <a href="/docs" target="_blank">Abrir Swagger UI (/docs)</a></p>

        <div class="card card-vuln">
            <h3>1. Deserialización Insegura (RCE) vs JSON Schema</h3>
            <p><span class="badge-vuln">VULNERABLE</span> <code>POST /api/profile/insecure</code> - Tránsito ciego por Gateway y <code>pickle.loads()</code> sin verificación en microservicio interno.</p>
            <p><span class="badge-sec">SEGURO</span> <code>POST /api/profile/secure</code> - Rechazo de objetos nativos, uso de JSON puro y validación Pydantic.</p>
        </div>

        <div class="card card-vuln">
            <h3>2. Integridad de Tokens (alg: none / JWT sin firma) vs Validación Criptográfica</h3>
            <p><strong>Autenticación:</strong> <code>POST /api/auth/login</code> - Emite token legítimo con <code>role: user</code>.</p>
            <p><span class="badge-vuln">VULNERABLE</span> <code>GET /api/admin/data/insecure</code> - Acepta tokens manipulados a <code>admin</code> con <code>alg: none</code> o firma omitida.</p>
            <p><span class="badge-sec">SEGURO</span> <code>GET /api/admin/data/secure</code> - Valida criptográficamente la firma con clave secreta centralizada y rechaza 'none'.</p>
        </div>

        <div class="card card-vuln">
            <h3>3. Integridad de Contenedores y Registros (A08) vs Digest & Firma Digital</h3>
            <p><span class="badge-vuln">VULNERABLE</span> <code>POST /api/cluster/deploy/insecure</code> - Despliegue ciego usando tag mutable (:latest) desde registros públicos no verificados.</p>
            <p><span class="badge-sec">SEGURO</span> <code>POST /api/cluster/deploy/secure</code> - Registro privado obligatorio, digest SHA-256 inmutable y firma digital (Cosign).</p>
        </div>
    </body>
    </html>
    """

# -------------------------------------------------------------
# PROXYING: Autenticación
# -------------------------------------------------------------
@app.post("/api/auth/login")
async def proxy_login(request: Request):
    """Enruta inicio de sesión al Microservicio 1 (User Service)."""
    return await forward_request(f"{USER_SERVICE_URL}/auth/login", request, method="POST")

# -------------------------------------------------------------
# PROXYING VULNERABILIDAD 1: Deserialización
# -------------------------------------------------------------
@app.post("/api/profile/insecure")
async def proxy_profile_insecure(request: Request):
    """
    [GATEWAY CIEGO - TRÁNSITO SIN VALIDACIÓN]
    El Gateway reenvía el payload serializado al microservicio interno
    sin inspeccionar ni validar la integridad del contenido.
    """
    return await forward_request(f"{USER_SERVICE_URL}/profile/insecure", request, method="POST")

@app.post("/api/profile/secure")
async def proxy_profile_secure(request: Request):
    """
    [GATEWAY SEGURO]
    Enruta hacia el endpoint con deserialización segura basada en JSON puro y Pydantic.
    """
    return await forward_request(f"{USER_SERVICE_URL}/profile/secure", request, method="POST")

# -------------------------------------------------------------
# PROXYING VULNERABILIDAD 2: Tokens JWT
# -------------------------------------------------------------
@app.get("/api/admin/data/insecure")
async def proxy_admin_data_insecure(request: Request):
    """
    [GATEWAY CIEGO - PROPAGACIÓN EN LA RED]
    El Gateway no fuerza la validación estricta de firma del token JWT y reenvía
    la cabecera Authorization sin modificar directamente al microservicio interno.
    """
    return await forward_request(f"{USER_SERVICE_URL}/admin/data/insecure", request, method="GET")

@app.get("/api/admin/data/secure")
async def proxy_admin_data_secure(request: Request):
    """
    [GATEWAY SEGURO]
    Enruta hacia el endpoint del microservicio que valida estrictamente
    la firma HMAC-SHA256 y rechaza tokens sin firma o alterados.
    """
    return await forward_request(f"{USER_SERVICE_URL}/admin/data/secure", request, method="GET")

# -------------------------------------------------------------
# PROXYING VULNERABILIDAD 3: Despliegue de Contenedores (A08)
# -------------------------------------------------------------
@app.post("/api/cluster/deploy/insecure")
async def proxy_cluster_deploy_insecure(request: Request):
    """
    [GATEWAY CIEGO]
    Enruta solicitudes de despliegue al microservicio orquestador (Cluster Service)
    sin validar procedencia ni firmas.
    """
    return await forward_request(f"{CLUSTER_SERVICE_URL}/deploy/insecure", request, method="POST")

@app.post("/api/cluster/deploy/secure")
async def proxy_cluster_deploy_secure(request: Request):
    """
    [GATEWAY SEGURO]
    Enruta solicitudes de despliegue al microservicio orquestador con verificación
    estricta de digest SHA-256, registro privado y firma digital.
    """
    return await forward_request(f"{CLUSTER_SERVICE_URL}/deploy/secure", request, method="POST")

if __name__ == "__main__":
    import uvicorn
    from common.config import GATEWAY_PORT
    uvicorn.run("gateway.main:app", host="127.0.0.1", port=GATEWAY_PORT, reload=False)
