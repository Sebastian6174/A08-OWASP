"""
Configuración compartida para el prototipo de microservicios y proxy.
"""
import hmac
import hashlib

# Puertos para cada componente
GATEWAY_PORT = 8000
USER_SERVICE_PORT = 8001
CLUSTER_SERVICE_PORT = 8002

GATEWAY_URL = f"http://127.0.0.1:{GATEWAY_PORT}"
USER_SERVICE_URL = f"http://127.0.0.1:{USER_SERVICE_PORT}"
CLUSTER_SERVICE_URL = f"http://127.0.0.1:{CLUSTER_SERVICE_PORT}"

# Clave secreta centralizada para JWT (HMAC-SHA256)
JWT_SECRET_KEY = "SUPER_SECRET_CENTRALIZED_ENTERPRISE_KEY_2026"
JWT_ALGORITHM = "HS256"

# Clave y registros autorizados para integridad de Contenedores (A08)
TRUSTED_REGISTRY_PREFIX = "private.registry.internal/"
CONTAINER_SIGNING_KEY = "COSIGN_ENTERPRISE_ROOT_KEY_SECURE_99"

# Catálogo simulado de imágenes oficiales conocidas y sus digests inmutables firmados
AUTHORIZED_CONTAINER_DIGESTS = {
    # imagen legítima firmada:
    "private.registry.internal/microservices/payment:v1.2.0": {
        "digest": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        "signature": hmac.new(
            CONTAINER_SIGNING_KEY.encode(),
            "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069".encode(),
            hashlib.sha256
        ).hexdigest(),
        "is_clean": True,
        "entrypoint_payload": "payment_service_binary --listen 8080"
    }
}

