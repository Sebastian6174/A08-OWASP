"""
Microservicio 1: Auth & User Service (Puerto 8001)
Implementa:
- Vulnerabilidad 1: Deserialización Insegura (pickle) vs Deserialización Segura (Pydantic / JSON puro)
- Vulnerabilidad 2: Token JWT sin validación de firma ("alg": "none") vs Validación estricta centralizada
"""
import base64
import pickle
import time
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field
import jwt

from common.config import JWT_SECRET_KEY, JWT_ALGORITHM

app = FastAPI(title="User & Auth Microservice", version="1.0.0")

# --- MODELOS PYDANTIC PARA VALIDACIÓN SEGURA ---
class LoginRequest(BaseModel):
    username: str
    password: str

class ProfileUpdateSecure(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    bio: str = Field(..., max_length=200)

class InsecurePayloadRequest(BaseModel):
    serialized_payload_b64: str

# -------------------------------------------------------------
# AUTENTICACIÓN: Emisión de Token Legítimo
# -------------------------------------------------------------
@app.post("/auth/login")
def login(creds: LoginRequest):
    """
    Simula inicio de sesión.
    Emite un token JWT legítimo con rol de usuario estándar: role='user'.
    """
    payload = {
        "sub": creds.username,
        "role": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return {
        "message": "Login exitoso",
        "token": token,
        "token_type": "Bearer",
        "assigned_role": "user"
    }

# -------------------------------------------------------------
# VULNERABILIDAD 1: INYECCIÓN DE PAYLOAD / DESERIALIZACIÓN INSEGURA
# -------------------------------------------------------------
@app.post("/profile/insecure")
def update_profile_insecure(body: InsecurePayloadRequest):
    """
    [VULNERABLE - A08 / CWE-502 Deserialización Insegura]
    Recibe un objeto serializado en Python Pickle (codificado en Base64).
    El microservicio asume confianza ciega y deserializa el objeto nativo
    directamente con pickle.loads().
    Si el atacante construyó el payload con __reduce__, se ejecutará código
    remoto arbitrario (RCE) dentro del contenedor/proceso.
    """
    try:
        raw_bytes = base64.b64decode(body.serialized_payload_b64)
        # PELIGRO CRÍTICO: Ejecuta código durante la reconstrucción del objeto
        deserialized_data = pickle.loads(raw_bytes)
        
        return {
            "status": "Vulnerable Profile Processed",
            "received_type": str(type(deserialized_data)),
            "content": str(deserialized_data),
            "warning": "Objeto deserializado sin firma ni verificación de tipos nativos!"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al deserializar: {str(e)}")

@app.post("/profile/secure")
def update_profile_secure(profile: ProfileUpdateSecure):
    """
    [SOLUCIÓN SEGURA]
    1. Uso exclusivo de formato estándar simple (JSON puro).
    2. Prohíbe cualquier transporte de objetos nativos o bytecode ejecutable.
    3. Validación y sanitización estricta de esquema antes del procesamiento
       mediante Pydantic (tipos, longitudes máximas, formato de email).
    """
    return {
        "status": "Secure Profile Processed",
        "profile": {
            "username": profile.username,
            "email": profile.email,
            "bio": profile.bio
        },
        "guarantee": "Validado estrictamente mediante esquema JSON. Ningún objeto ejecutable fue procesado."
    }

# -------------------------------------------------------------
# VULNERABILIDAD 2: VALIDACIÓN INSEGURA DE TOKENS (alg: none / sin firma)
# -------------------------------------------------------------
@app.get("/admin/data/insecure")
def get_admin_data_insecure(authorization: Optional[str] = Header(None)):
    """
    [VULNERABLE - CWE-347 / CWE-287 Verificación de Firma Inadecuada]
    El microservicio confía ciegamente en las claims del JWT sin validar
    criptográficamente la firma con el servidor de claves (verify_signature=False).
    Acepta tokens modificados por el atacante donde cambiaron 'role: user' por 'role: admin'
    o fijaron 'alg: none'.
    Permite escalamiento de privilegios directo.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Header de autorización faltante o inválido")

    token = authorization.split(" ")[1]
    try:
        # FALLA DE SEGURIDAD: Decodificación sin verificar firma ni algoritmo
        untrusted_payload = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token ilegible: {str(e)}")

    user_role = untrusted_payload.get("role")
    username = untrusted_payload.get("sub", "unknown")

    if user_role == "admin":
        return {
            "status": "Vulnerable Access Granted!",
            "message": f"Bienvenido administrador {username}. Datos altamente confidenciales expuestos.",
            "secret_company_data": {
                "treasury_balance": "$12,450,000 USD",
                "internal_master_keys": ["KEY-PROD-9912", "DB-ADMIN-SECRET-PASS"],
                "notice": "El microservicio confió en el claim 'role: admin' sin validar firma criptográfica."
            }
        }
    else:
        raise HTTPException(
            status_code=403,
            detail=f"Acceso denegado. Rol '{user_role}' insuficiente. Se requiere 'admin'."
        )

@app.get("/admin/data/secure")
def get_admin_data_secure(authorization: Optional[str] = Header(None)):
    """
    [SOLUCIÓN SEGURA]
    1. Rechazo categórico de tokens no firmados ('alg: none').
    2. Validación criptográfica de la firma usando clave secreta centralizada (HS256).
    3. Verificación de expiración y claims en cada petición.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Header de autorización faltante o inválido")

    token = authorization.split(" ")[1]
    try:
        # VALIDACIÓN ESTRICTA:
        # Se fija explícitamente el algoritmo permitido (HS256) y se valida la firma
        verified_payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": True}
        )
    except jwt.InvalidAlgorithmError:
        raise HTTPException(status_code=401, detail="Algoritmo no permitido (ej. 'none'). Token rechazado.")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado.")
    except jwt.InvalidSignatureError:
        raise HTTPException(status_code=401, detail="Firma de token inválida. El token fue alterado en tránsito.")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Error en validación de token: {str(e)}")

    user_role = verified_payload.get("role")
    username = verified_payload.get("sub", "unknown")

    if user_role != "admin":
        raise HTTPException(
            status_code=403,
            detail=f"Acceso denegado: El usuario legítimo '{username}' tiene rol '{user_role}' y no es 'admin'."
        )

    return {
        "status": "Secure Access Granted",
        "message": f"Autenticación verificada criptográficamente para admin legítimo '{username}'.",
        "data": "Acceso seguro a datos administrativos."
    }

if __name__ == "__main__":
    import uvicorn
    from common.config import USER_SERVICE_PORT
    uvicorn.run("user_service.main:app", host="127.0.0.1", port=USER_SERVICE_PORT, reload=False)
