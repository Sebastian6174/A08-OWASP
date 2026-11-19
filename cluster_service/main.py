"""
Microservicio 2: Cluster & Deployment Service (Puerto 8002)
Implementa:
- Vulnerabilidad 3: Compromiso de Integridad en Registro y Despliegue de Contenedores (OWASP A08)
  - Endpoint Inseguro: Descarga y ejecución de contenedor por tag mutable sin verificar firma ni digest.
  - Endpoint Seguro: Verificación estricta de procedencia (registro privado), digest SHA-256 inmutable y firma criptográfica digital (Cosign).
"""
import hmac
import hashlib
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from common.config import (
    TRUSTED_REGISTRY_PREFIX,
    CONTAINER_SIGNING_KEY,
    AUTHORIZED_CONTAINER_DIGESTS
)

app = FastAPI(title="Cluster Deployment Microservice", version="1.0.0")

# --- MODELOS DE SOLICITUD DE DESPLIEGUE ---
class InsecureDeployRequest(BaseModel):
    image_reference: str  # Ej: "docker.io/public-repo/payment-service:latest"
    replicas: int = 1
    # Simulación del contenido descargado del registro comprometido
    simulated_registry_backdoor: Optional[str] = None

class SecureDeployRequest(BaseModel):
    image_reference: str = Field(..., description="Debe ser una URI a registro privado")
    digest: str = Field(..., description="Hash criptográfico inmutable sha256:...")
    digital_signature: str = Field(..., description="Firma criptográfica generada al compilar la imagen")
    replicas: int = 1

# -------------------------------------------------------------
# VULNERABILIDAD 3: FALLA DE INTEGRIDAD DE CONTENEDORES (OWASP A08)
# -------------------------------------------------------------
@app.post("/deploy/insecure")
def deploy_container_insecure(req: InsecureDeployRequest):
    """
    [VULNERABLE - OWASP Top 10 A08: Software and Data Integrity Failures]
    1. El orquestador confía ciegamente en una etiqueta mutable (como :latest).
    2. No valida la procedencia (permite registros públicos o no autorizados).
    3. No verifica el digest criptográfico ni la firma digital del contenedor.
    
    Impacto: Si el registro fue comprometido o el tag fue sobreescrito con malware,
    el clúster lo ejecuta en su red privada con acceso a variables de entorno y tráfico interno.
    """
    # Verificamos si la imagen usa un tag mutable
    is_latest = req.image_reference.endswith(":latest")
    
    # Simulación de la ejecución del contenedor en el clúster
    executed_payload = req.simulated_registry_backdoor or (
        "MALICIOUS_BACKDOOR_ACTIVE: Interceptando tráfico de red interna, "
        "exfiltrando variables de entorno (DB_PASSWORD, CLUSTER_SECRET) a C2 server."
        if is_latest or "public" in req.image_reference else "Proceso estándar"
    )

    return {
        "status": "Container Deployed (INSECURE)",
        "image_deployed": req.image_reference,
        "integrity_checked": False,
        "signature_verified": False,
        "risk_warning": "El orquestador desplegó la imagen sin verificar firma ni digest.",
        "cluster_execution_result": {
            "node": "k8s-worker-node-01",
            "container_id": "cnt-vuln-99812",
            "executed_entrypoint": executed_payload,
            "impact": "CRÍTICO: El código malicioso inyectado en el registro ahora corre dentro del clúster."
        }
    }

@app.post("/deploy/secure")
def deploy_container_secure(req: SecureDeployRequest):
    """
    [SOLUCIÓN SEGURA]
    1. Registro Privado: Valida que la imagen provenga exclusivamente del registro corporativo autorizado.
    2. Prohibición de Tags Mutables: No permite :latest sin digest inmutable.
    3. Verificación de Digest Criptográfico: Asegura que el contenido exacto coincida con el hash SHA-256.
    4. Verificación de Firma Digital (Cosign/Notary): Comprueba criptográficamente que la imagen fue firmada
       por la pipeline CI/CD autorizada antes de permitir su ejecución (Admission Controller).
    """
    # 1. Validar procedencia (Registro Privado)
    if not req.image_reference.startswith(TRUSTED_REGISTRY_PREFIX):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Admisión Rechazada: El origen '{req.image_reference}' no pertenece al registro privado "
                f"confiable autorizado ('{TRUSTED_REGISTRY_PREFIX}')."
            )
        )

    # 2. Prohibir tags mutables sin anclaje inmutable
    if ":latest" in req.image_reference:
        raise HTTPException(
            status_code=400,
            detail="Admisión Rechazada: El tag mutable ':latest' está prohibido en entornos de producción seguros."
        )

    # 3. Validar formato de digest criptográfico SHA-256
    if not req.digest.startswith("sha256:") or len(req.digest) != 71:
        raise HTTPException(
            status_code=400,
            detail="Admisión Rechazada: El digest no tiene formato criptográfico SHA-256 inmutable válido."
        )

    # 4. Verificar firma criptográfica digital (Simulación Cosign / Admission Controller)
    expected_signature = hmac.new(
        CONTAINER_SIGNING_KEY.encode(),
        req.digest.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(req.digital_signature, expected_signature):
        raise HTTPException(
            status_code=403,
            detail=(
                "Falla de Integridad Criptográfica (A08): La firma digital del contenedor es inválida "
                "o el artefacto fue alterado en el registro. Despliegue abortado por el Admission Controller."
            )
        )

    # 5. Comprobar que el artefacto exista en el registro autorizado de versiones auditadas
    known_artifact = AUTHORIZED_CONTAINER_DIGESTS.get(req.image_reference)
    if not known_artifact or known_artifact["digest"] != req.digest:
        raise HTTPException(
            status_code=403,
            detail="Admisión Rechazada: El digest no coincide con ninguna versión aprobada y firmada en el catálogo."
        )

    return {
        "status": "Container Deployed (SECURE)",
        "image_deployed": req.image_reference,
        "digest": req.digest,
        "integrity_checked": True,
        "signature_verified": True,
        "registry": "Private Enterprise Registry (Trusted)",
        "admission_controller": "Paso todas las políticas de integridad y firma digital.",
        "cluster_execution_result": {
            "node": "k8s-worker-node-secure",
            "container_id": "cnt-sec-44012",
            "executed_entrypoint": known_artifact["entrypoint_payload"],
            "impact": "SEGURO: Contenedor verificado, garantizando integridad de origen y ejecución limpia."
        }
    }

if __name__ == "__main__":
    import uvicorn
    from common.config import CLUSTER_SERVICE_PORT
    uvicorn.run("cluster_service.main:app", host="127.0.0.1", port=CLUSTER_SERVICE_PORT, reload=False)

