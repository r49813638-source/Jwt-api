import json
import base64
import asyncio
import httpx
import logging
from Crypto.Cipher import AES
from flask import Flask, request, jsonify
from google.protobuf import json_format

# ================= Logging =================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ================= Import Proto =================
try:
    from proto import FreeFire_pb2
    logger.info("FreeFire_pb2 imported successfully")
except Exception as e:
    logger.error(f"Proto import failed: {e}")
    raise

# ================= Settings =================
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13)"
RELEASEVERSION = "OB52"

app = Flask(__name__)

# ================= Helpers =================
def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len] * pad_len)

def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data))

async def json_to_proto(json_data: str, proto_message):
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# ================= Token API =================
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"

    payload = (
        f"{account}"
        "&response_type=token"
        "&client_type=2"
        "&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
        "&client_id=100067"
    )

    headers = {
        "User-Agent": USERAGENT,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(uid: str, password: str):
    account = f"uid={uid}&password={password}"
    token_val, open_id = await get_access_token(account)

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })

    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    encrypted_payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = "https://loginbp.ggblueshark.com/MajorLogin"

    headers = {
        "User-Agent": USERAGENT,
        "Content-Type": "application/octet-stream",
        "ReleaseVersion": RELEASEVERSION
    }

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(url, data=encrypted_payload, headers=headers)
        resp.raise_for_status()

        msg = json.loads(
            json_format.MessageToJson(
                FreeFire_pb2.LoginRes.FromString(resp.content)
            )
        )

        return {
            "token": msg.get("token", "0"),
            "region": msg.get("lockRegion", "0"),
            "server_url": msg.get("serverUrl", "0")
        }

# ================= Routes =================
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "API running",
        "version": RELEASEVERSION
    })

@app.route("/api/token", methods=["GET"])
def token():
    uid = request.args.get("uid")
    password = request.args.get("password")

    if not uid or not password:
        return jsonify({"error": "uid and password required"}), 400

    try:
        result = asyncio.run(create_jwt(uid, password))
        return jsonify(result)
    except Exception as e:
        logger.error(f"JWT error: {e}")
        return jsonify({"error": "JWT generation failed"}), 500

# ================= Vercel Handler =================
handler = app