import os
import uuid
from datetime import datetime, timezone
from enum import StrEnum

import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS
from jwt import PyJWKClient
from pymongo import MongoClient

MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
DOMAIN = os.environ.get("AUTH0_DOMAIN", "")
AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "")
ROLES_CLAIM = os.environ.get("AUTH0_ROLES_CLAIM") or "https://proj-soft/roles"


class Status(StrEnum):
    DISPONIVEL = "DISPONIVEL"
    INDISPONIVEL = "INDISPONIVEL"


app = Flask(__name__)
CORS(app)
products = MongoClient(MONGO_URL)["ecommerce_db"]["products"]


def jwt_payload():
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None, (jsonify({"mensagem": "Sem token."}), 401)
    tok = auth.split(None, 1)[1].strip()
    if not DOMAIN or not AUDIENCE:
        return None, (jsonify({"mensagem": "Falta AUTH0_DOMAIN / AUTH0_AUDIENCE."}), 500)
    try:
        key = PyJWKClient(f"https://{DOMAIN}/.well-known/jwks.json").get_signing_key_from_jwt(tok).key
        return jwt.decode(tok, key, algorithms=["RS256"], audience=AUDIENCE, issuer=f"https://{DOMAIN}/"), None
    except jwt.ExpiredSignatureError:
        return None, (jsonify({"mensagem": "Token expirado."}), 401)
    except jwt.InvalidTokenError as e:
        return None, (jsonify({"mensagem": str(e)}), 401)


def roles(p):
    for k in (ROLES_CLAIM, "roles", "permissions"):
        v = p.get(k) if k else None
        if isinstance(v, list):
            return [str(x).upper() for x in v]
        if isinstance(v, str) and v:
            return [v.upper()]
    return []


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/products")
def listar():
    p, err = jwt_payload()
    if err:
        return err
    if not (set(roles(p)) & {"ADMIN", "USER"}):
        return jsonify({"mensagem": "Sem papel USER/ADMIN."}), 403
    return jsonify(list(products.find({}, {"_id": 0})))


@app.post("/products")
def criar():
    p, err = jwt_payload()
    if err:
        return err
    if "ADMIN" not in roles(p):
        return jsonify({"mensagem": "Só ADMIN."}), 403
    d = request.get_json(silent=True) or {}
    if not d.get("codigo") or not d.get("nome") or d.get("preco") is None:
        return jsonify({"mensagem": "codigo, nome, preco obrigatórios."}), 400
    try:
        st = Status(d.get("status", "DISPONIVEL"))
    except ValueError:
        return jsonify({"mensagem": "status: DISPONIVEL ou INDISPONIVEL"}), 400
    try:
        preco = float(d["preco"])
    except (TypeError, ValueError):
        return jsonify({"mensagem": "preco inválido"}), 400
    doc = {
        "id": str(uuid.uuid4()),
        "codigo": str(d["codigo"]),
        "nome": str(d["nome"]),
        "preco": preco,
        "data_cadastro": datetime.now(timezone.utc).isoformat(),
        "status": st.value,
        "email_admin": p.get("email") or p.get("sub") or "?",
    }
    products.insert_one(doc)
    return jsonify(doc), 201


@app.delete("/products/<pid>")
def apagar(pid):
    p, err = jwt_payload()
    if err:
        return err
    if "ADMIN" not in roles(p):
        return jsonify({"mensagem": "Só ADMIN."}), 403
    if products.delete_one({"id": pid}).deleted_count == 0:
        return jsonify({"mensagem": "Não achei."}), 404
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
