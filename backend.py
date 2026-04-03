import os
import logging
import secrets
import string
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from dotenv import load_dotenv

load_dotenv()

# ==================== CONFIG ====================
BOT_TOKEN  = os.getenv('BOT_TOKEN')
CHANNEL_ID = os.getenv('CHANNEL_ID', '0')
API_KEY    = os.getenv('API_KEY')

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
log = logging.getLogger("xotiic-backend")

if not BOT_TOKEN:
    log.error("BOT_TOKEN not set in environment!")
    raise ValueError("BOT_TOKEN is required")

log.info(f"Bot token loaded: {BOT_TOKEN[:12]}...")
log.info(f"Channel ID: {CHANNEL_ID}")

# ==================== APP ====================
app = FastAPI(title="xotiic CyberScan API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ==================== MODELS ====================
class LoginRequest(BaseModel):
    user_id: str

class LoginResponse(BaseModel):
    success: bool
    scan_id: Optional[str] = None
    message: str

class BotTokenResponse(BaseModel):
    bot_token: str
    channel_id: int
    message: str

class ScanCompleteRequest(BaseModel):
    scan_id: str
    user_id: str
    files_scanned: int
    suspicious_count: int
    duration: float
    logitech: Optional[Dict[str, Any]] = None

class GenerateKeyRequest(BaseModel):
    user_id: str
    duration_days: Optional[int] = 30

class GenerateKeyResponse(BaseModel):
    key: str
    user_id: str
    expires_at: str
    message: str

# ==================== KEY MANAGER ====================
class KeyManager:
    def __init__(self):
        self.keys: Dict = {}
        self.user_keys: Dict = {}
        self._file = os.path.join(os.path.dirname(__file__), 'keys.json')
        self._load()

    def _load(self):
        if os.path.exists(self._file):
            try:
                with open(self._file) as f:
                    d = json.load(f)
                    self.keys      = d.get('keys', {})
                    self.user_keys = d.get('user_keys', {})
                log.info(f"Loaded {len(self.keys)} keys")
            except Exception as e:
                log.error(f"Key load error: {e}")

    def _save(self):
        try:
            with open(self._file, 'w') as f:
                json.dump({'keys': self.keys, 'user_keys': self.user_keys}, f, indent=2)
        except Exception as e:
            log.error(f"Key save error: {e}")

    def generate(self, user_id: str, days: int = 30) -> str:
        chars = string.ascii_uppercase + string.digits
        parts = [''.join(secrets.choice(chars) for _ in range(5)) for _ in range(3)]
        key = f"X-{'—'.join(parts)}"
        expires = (datetime.now() + timedelta(days=days)).timestamp()
        self.keys[key] = {
            'user_id': user_id,
            'expires_at': expires,
            'used': False,
            'created_at': datetime.now().isoformat(),
            'duration_days': days
        }
        self.user_keys.setdefault(user_id, []).append(key)
        self._save()
        log.info(f"Key generated for {user_id}: {key}")
        return key

    def validate(self, user_id: str):
        """Returns (valid, message, key_used)"""
        keys = self.user_keys.get(user_id, [])
        if not keys:
            return False, "No keys found for this Discord ID. Contact xotiic.", None
        now = datetime.now().timestamp()
        for k in keys:
            kd = self.keys.get(k)
            if not kd: continue
            if kd['used']:     continue
            if now > kd['expires_at']: continue
            # Valid — mark used
            self.keys[k]['used']    = True
            self.keys[k]['used_at'] = datetime.now().isoformat()
            self._save()
            return True, "Authorized", k
        return False, "No valid keys found (all used or expired). Contact xotiic.", None

    def stats(self) -> Dict:
        total  = len(self.keys)
        used   = sum(1 for k in self.keys.values() if k.get('used'))
        now    = datetime.now().timestamp()
        valid  = sum(1 for k in self.keys.values() if not k.get('used') and now <= k['expires_at'])
        return {'total': total, 'used': used, 'valid': valid, 'users': len(self.user_keys)}

keys = KeyManager()

# ==================== STATE ====================
active_scans: Dict = {}
scan_history = []
start_time = datetime.now()

# ==================== ROUTES ====================

@app.get("/")
async def root():
    return {
        "service": "xotiic CyberScan API",
        "version": "2.0.0",
        "status": "online",
        "uptime": str(datetime.now() - start_time).split('.')[0],
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "bot_token": bool(BOT_TOKEN),
        "channel_id": CHANNEL_ID,
        "keys": keys.stats(),
        "active_scans": len(active_scans),
        "total_scans": len(scan_history),
        "uptime": str(datetime.now() - start_time).split('.')[0],
    }

@app.get("/api/bot-token", response_model=BotTokenResponse)
async def get_bot_token(x_api_key: Optional[str] = Header(None)):
    """
    Called by the client on startup BEFORE user logs in.
    Returns bot token so the Discord bot can be pre-loaded.
    """
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")
    log.info("Bot token requested (pre-load)")
    return BotTokenResponse(
        bot_token=BOT_TOKEN,
        channel_id=int(CHANNEL_ID),
        message="Bot token retrieved — bot ready to pre-load"
    )

@app.post("/api/login", response_model=LoginResponse)
async def login(req: LoginRequest, x_api_key: Optional[str] = Header(None)):
    """Validates the user's Discord ID against stored keys."""
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")

    uid = req.user_id.strip()
    log.info(f"Login attempt: {uid}")

    valid, msg, used_key = keys.validate(uid)
    if not valid:
        log.warning(f"Login denied for {uid}: {msg}")
        return LoginResponse(success=False, message=msg)

    scan_id = f"XCS-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uid[-6:]}"
    active_scans[scan_id] = {
        'user_id': uid,
        'start': datetime.now().isoformat(),
        'status': 'active',
        'key': used_key,
    }
    log.info(f"Login OK: {uid} | scan_id: {scan_id} | key: {used_key}")
    return LoginResponse(success=True, scan_id=scan_id, message=f"Authorized. Scan ID: {scan_id}")

@app.post("/api/scan/complete")
async def scan_complete(req: ScanCompleteRequest, x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")

    scan = active_scans.get(req.scan_id)
    if not scan:
        raise HTTPException(404, "Scan ID not found")
    if scan['user_id'] != req.user_id:
        raise HTTPException(403, "User mismatch")

    active_scans[req.scan_id]['status'] = 'completed'
    active_scans[req.scan_id]['completed'] = datetime.now().isoformat()

    scan_history.append({
        'scan_id': req.scan_id,
        'user_id': req.user_id,
        'completed': datetime.now().isoformat(),
        'files': req.files_scanned,
        'suspicious': req.suspicious_count,
        'duration': req.duration,
        'key': scan.get('key'),
    })

    log.info(f"Scan complete: {req.scan_id} | files:{req.files_scanned} sus:{req.suspicious_count}")
    return {"status": "ok"}

@app.post("/api/generate-key", response_model=GenerateKeyResponse)
async def generate_key(req: GenerateKeyRequest, x_api_key: Optional[str] = Header(None)):
    """Admin-only: generate a scan key for a Discord user."""
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")

    key = keys.generate(req.user_id, req.duration_days)
    kd  = keys.keys[key]
    exp = datetime.fromtimestamp(kd['expires_at']).strftime('%Y-%m-%d %H:%M:%S')

    return GenerateKeyResponse(
        key=key,
        user_id=req.user_id,
        expires_at=exp,
        message=f"Key valid for {req.duration_days} days. Expires {exp}."
    )

@app.get("/api/stats")
async def stats(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")
    return {
        "keys": keys.stats(),
        "total_scans": len(scan_history),
        "active_scans": len(active_scans),
        "recent": scan_history[-10:],
    }

@app.get("/api/scan/{scan_id}")
async def scan_status(scan_id: str, x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")
    if scan_id in active_scans:
        return active_scans[scan_id]
    for s in scan_history:
        if s['scan_id'] == scan_id:
            return s
    raise HTTPException(404, "Scan not found")

# ==================== MAIN ====================
if __name__ == "__main__":
    port = int(os.getenv('PORT', 5000))
    log.info(f"Starting xotiic CyberScan API on port {port}")
    log.info(f"Keys loaded: {keys.stats()}")
    uvicorn.run(app, host="0.0.0.0", port=port)
