from starlette.testclient import TestClient
from user_service.main import app as user_app

client = TestClient(user_app)
res = client.post("/auth/login", json={"username": "alice", "password": "123"})
print("Status:", res.status_code)
print("Body:", res.json())

