# 🛡️ Prototipo de Seguridad en Microservicios y API Gateway (FastAPI)

Este prototipo demuestra vulnerabilidades críticas en arquitecturas basadas en microservicios, centrándose en **fallas de integridad de datos y software (OWASP Top 10 A08)**, así como sus correspondientes soluciones y mejores prácticas.

---

## 🏛️ Arquitectura del Sistema

```
                  ┌────────────────────────────────────────┐
                  │          Cliente / Atacante            │
                  └───────────────────┬────────────────────┘
                                      │ HTTP :8000
                                      ▼
                  ┌────────────────────────────────────────┐
                  │       API Gateway / Proxy (FastAPI)     │
                  │              (Puerto 8000)             │
                  └─────────────┬────────────────────┬─────┘
                                │                    │
             Proxying HTTP      │                    │  Proxying HTTP
             (Puerto 8001)      ▼                    ▼  (Puerto 8002)
   ┌───────────────────────────────────┐      ┌───────────────────────────────────┐
   │         Microservicio 1           │      │         Microservicio 2           │
   │       (User & Auth Service)       │      │   (Cluster & Deployment Runner)   │
   ├───────────────────────────────────┤      ├───────────────────────────────────┤
   │ • POST /auth/login                │      │ • POST /deploy/insecure           │
   │ • POST /profile/insecure (Pickle) │      │ • POST /deploy/secure (Cosign)    │
   │ • POST /profile/secure   (JSON)   │      │                                   │
   │ • GET  /admin/data/insecure       │      │                                   │
   │ • GET  /admin/data/secure         │      │                                   │
   └───────────────────────────────────┘      └───────────────────────────────────┘
```

1. **API Gateway (Proxy) - Puerto 8000**: Punto único de entrada. Reenvía peticiones hacia los microservicios internos. Ilustra el riesgo del *tránsito sin validación* cuando el proxy confía ciegamente en el tráfico de entrada.
2. **Microservicio 1 (Auth & User Service) - Puerto 8001**: Emite tokens JWT, maneja perfiles de usuario y datos administrativos sensibles.
3. **Microservicio 2 (Cluster & Deployment Runner) - Puerto 8002**: Simula un orquestador (ej. Kubernetes) que gestiona el despliegue y ejecución de artefactos/contenedores en el clúster.

---

## 📋 Matriz de Endpoints: Inseguros vs. Seguros

| # | Vulnerabilidad / Riesgo | Endpoint Inseguro (Vulnerable) | Endpoint Seguro (Mitigado) | Solución Aplicada |
|---|-------------------------|--------------------------------|----------------------------|-------------------|
| **1** | **Deserialización Insegura (RCE)** | `POST /api/profile/insecure` | `POST /api/profile/secure` | Formato JSON puro, validación de esquema con Pydantic, prohibición de objetos ejecutables nativos (`pickle`). |
| **2** | **Integridad de JWT (`alg: none`)** | `GET /api/admin/data/insecure` | `GET /api/admin/data/secure` | Rechazo forzado de `alg: none`, validación criptográfica de firma con clave secreta centralizada (HS256). |
| **3** | **Compromiso de Registro (A08)** | `POST /api/cluster/deploy/insecure` | `POST /api/cluster/deploy/secure` | Exigencia de registro privado, digests SHA-256 inmutables y verificación de firma digital de contenedores (Cosign). |

---

## 🔍 Análisis Detallado de las Vulnerabilidades y Soluciones

### 1. Inyección de Payload y Deserialización Insegura (RCE)
* **Flujo del Ataque**:
  1. El atacante serializa un objeto Python nativo (`pickle`) con el método mágico `__reduce__` inyectando comandos de sistema (`whoami`, `cat /etc/passwd`).
  2. El API Gateway recibe el payload codificado en Base64 y lo reenvía al microservicio de usuarios sin inspeccionar su contenido.
  3. El microservicio interno asume confianza implícita y ejecuta `pickle.loads(payload)`.
  4. Durante la deserialización se ejecutan los métodos del objeto malicioso, provocando **Ejecución Remota de Código (RCE)**.
* **Solución Segura**:
  - Se prohíbe el uso de serializadores nativos (`pickle`, `yaml.unsafe_load`).
  - Se utiliza exclusivamente **JSON puro**.
  - Se valida el esquema antes del procesamiento mediante modelos Pydantic (`ProfileUpdateSecure`), verificando tipos de datos, formato de email y longitudes máximas.

---

### 2. Manipulación de Tokens JWT (`alg: none` y Omisión de Firma)
* **Flujo del Ataque**:
  1. El usuario se autentica en `/api/auth/login` y recibe un token legítimo con `role: "user"`.
  2. El atacante decodifica el token, cambia el payload a `role: "admin"` y altera el encabezado fijando `"alg": "none"` (eliminando la firma).
  3. El API Gateway reenvía la cabecera `Authorization` al microservicio sin forzar verificación de firma en el borde.
  4. El microservicio vulnerable lee el token usando `jwt.decode(..., options={"verify_signature": False})` y confía ciegamente en el rol `admin`.
  5. **Impacto**: Escalamiento de privilegios directo y acceso a datos bancarios y claves internas maestras.
* **Solución Segura**:
  - El microservicio seguro restringe explícitamente los algoritmos aceptados: `algorithms=["HS256"]`.
  - Se rechaza inmediatamente cualquier token con `alg: none` (`jwt.InvalidAlgorithmError`).
  - Se verifica la firma criptográfica con la clave centralizada `JWT_SECRET_KEY` antes de leer los claims. Si el token fue alterado, se retorna `HTTP 401 Unauthorized`.

---

### 3. Falla de Integridad en Contenedores y Registros (OWASP A08)
* **Flujo del Ataque**:
  1. El atacante inyecta una imagen alterada con malware o puertas traseras en un registro público bajo una etiqueta estándar mutable (`:latest`).
  2. El orquestador recibe la orden de despliegue en `/api/cluster/deploy/insecure`.
  3. El clúster descarga y ejecuta la imagen confiando ciegamente en la etiqueta `:latest`, sin verificar el hash SHA-256 ni firma criptográfica.
  4. **Impacto**: El contenedor malicioso corre en la red interna del clúster con acceso a variables de entorno confidenciales (`DB_PASSWORD`, `CLUSTER_SECRET`).
* **Solución Segura**:
  - **Registro Privado Obligatorio**: Se rechazan imágenes de registros no autorizados (solo se permite `private.registry.internal/`).
  - **Prohibición de Etiquetas Mutables**: Se rechaza la etiqueta `:latest`.
  - **Digest Criptográfico Inmutable**: Se exige el hash exacto `image@sha256:...`.
  - **Verificación de Firma Digital (Cosign/Admission Controller)**: Se comprueba la firma HMAC/PKI de la imagen antes de admitirla. Si no coincide, el Admission Controller aborta el despliegue con `HTTP 403 Forbidden`.

---

## 🚀 Guía de Puesta en Marcha y Pruebas

### 1. Requisitos Previos
Tener el entorno virtual configurado con las dependencias:
```powershell
.\.venv\Scripts\activate
```

### 2. Ejecución de la Suite Completa de Pruebas Automatizadas
Para ejecutar una demostración paso a paso de los 3 ataques y sus 3 defensas:
```powershell
.\.venv\Scripts\python.exe run_test_suite.py
```

### 3. Ejecución Manual de los Microservicios
Si deseas interactuar con los servicios individualmente o abrir la interfaz Swagger:

```powershell
.\.venv\Scripts\python.exe run_services.py
```
Los servicios quedarán escuchando en:
- **API Gateway (Proxy):** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Documentación Swagger UI del Gateway:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Microservicio 1 (User & Auth):** [http://127.0.0.1:8001/docs](http://127.0.0.1:8001/docs)
- **Microservicio 2 (Cluster Service):** [http://127.0.0.1:8002/docs](http://127.0.0.1:8002/docs)

### 4. Probar los exploits contra los servidores en vivo:
En otra terminal:
```powershell
.\.venv\Scripts\python.exe test_exploits.py
```

