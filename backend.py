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
from supabase import create_client, Client

load_dotenv()

# ==================== CONFIG ====================
BOT_TOKEN  = os.getenv('BOT_TOKEN')
CHANNEL_ID = os.getenv('CHANNEL_ID', '0')
API_KEY    = os.getenv('API_KEY')
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
log = logging.getLogger("xotiic-backend")

if not BOT_TOKEN:
    log.error("BOT_TOKEN not set in environment!")
    raise ValueError("BOT_TOKEN is required")

if not SUPABASE_URL or not SUPABASE_KEY:
    log.warning("SUPABASE_URL or SUPABASE_KEY not set! Keys will not be persisted!")
else:
    log.info("Supabase credentials loaded")

log.info(f"Bot token loaded: {BOT_TOKEN[:12]}...")
log.info(f"Channel ID: {CHANNEL_ID}")

# ==================== SUPABASE INIT ====================
supabase: Optional[Client] = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        log.info("✓ Supabase client initialized")
    except Exception as e:
        log.error(f"Failed to initialize Supabase: {e}")

# ==================== APP ====================
app = FastAPI(title="xotiic CyberScan API", version="2.1.0")
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

# ==================== KEY MANAGER (Supabase) ====================
class KeyManager:
    def __init__(self):
        self.supabase = supabase
        self._init_table()
        
    def _init_table(self):
        """Initialize the keys table if using Supabase"""
        if not self.supabase:
            log.warning("Supabase not available, using in-memory storage")
            self.keys = {}
            self.user_keys = {}
            return
            
        try:
            log.info("Using Supabase for key storage")
        except Exception as e:
            log.error(f"Supabase init error: {e}")
            self.supabase = None
            self.keys = {}
            self.user_keys = {}

    async def generate(self, user_id: str, days: int = 30) -> str:
        """Generate a new key and store in Supabase"""
        # Generate a 12-character alphanumeric key
        alphabet = string.ascii_uppercase + string.digits
        scan_key = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        if self.supabase:
            try:
                # Check if key already exists
                existing = self.supabase.table('scan_keys').select('scan_key').eq('scan_key', scan_key).execute()
                if existing.data:
                    return await self.generate(user_id, days)
                
                # Insert new key
                now = datetime.now()
                expires_at = now + timedelta(days=days)
                
                data = {
                    'scan_key': scan_key,
                    'user_id': user_id,
                    'generated_by': 'admin',
                    'created_at': now.isoformat(),
                    'expires_at': expires_at.isoformat(),
                    'used': False,
                    'duration_days': days
                }
                
                result = self.supabase.table('scan_keys').insert(data).execute()
                if result.data:
                    log.info(f"✓ Key generated for {user_id}: {scan_key} (expires in {days} days)")
                    return scan_key
                else:
                    log.error("Failed to insert key into Supabase")
                    return None
                    
            except Exception as e:
                log.error(f"Error generating key in Supabase: {e}")
                return None
        else:
            # Fallback to in-memory storage
            self.keys[scan_key] = {
                'user_id': user_id,
                'expires_at': (datetime.now() + timedelta(days=days)).timestamp(),
                'used': False,
                'created_at': datetime.now().isoformat(),
                'duration_days': days
            }
            self.user_keys.setdefault(user_id, []).append(scan_key)
            log.info(f"Key generated in memory for {user_id}: {scan_key}")
            return scan_key

    async def validate(self, user_id: str):
        """Returns (valid, message, key_used)"""
        if self.supabase:
            try:
                # Query for valid keys for this user
                now = datetime.now().isoformat()
                result = self.supabase.table('scan_keys')\
                    .select('*')\
                    .eq('user_id', user_id)\
                    .eq('used', False)\
                    .gt('expires_at', now)\
                    .execute()
                
                if not result.data:
                    return False, "No valid keys found for this Discord ID. Contact xotiic.", None
                
                # Use the first valid key
                key_data = result.data[0]
                scan_key = key_data['scan_key']
                
                # Mark as used
                update_result = self.supabase.table('scan_keys')\
                    .update({'used': True, 'used_at': datetime.now().isoformat()})\
                    .eq('scan_key', scan_key)\
                    .execute()
                
                if update_result.data:
                    log.info(f"Key validated for {user_id}: {scan_key}")
                    return True, "Authorized", scan_key
                else:
                    return False, "Failed to validate key", None
                    
            except Exception as e:
                log.error(f"Error validating key in Supabase: {e}")
                return False, f"Database error: {e}", None
        else:
            # Fallback to in-memory storage
            keys = self.user_keys.get(user_id, [])
            if not keys:
                return False, "No keys found for this Discord ID. Contact xotiic.", None
                
            now = datetime.now().timestamp()
            for k in keys:
                kd = self.keys.get(k)
                if not kd:
                    continue
                if kd['used']:
                    continue
                if now > kd['expires_at']:
                    continue
                    
                self.keys[k]['used'] = True
                self.keys[k]['used_at'] = datetime.now().isoformat()
                log.info(f"Key validated in memory for {user_id}: {k}")
                return True, "Authorized", k
                
            return False, "No valid keys found (all used or expired). Contact xotiic.", None

    async def stats(self) -> Dict:
        """Get key statistics"""
        if self.supabase:
            try:
                now = datetime.now().isoformat()
                
                # Get total keys
                total = self.supabase.table('scan_keys').select('count', count='exact').execute()
                
                # Get active keys
                active = self.supabase.table('scan_keys').select('count', count='exact')\
                    .eq('used', False).gt('expires_at', now).execute()
                
                # Get used keys
                used = self.supabase.table('scan_keys').select('count', count='exact')\
                    .eq('used', True).execute()
                
                # Get distinct users
                distinct_users = self.supabase.table('scan_keys').select('user_id')\
                    .execute()
                unique_users = len(set([u['user_id'] for u in distinct_users.data])) if distinct_users.data else 0
                
                return {
                    'total': total.count if hasattr(total, 'count') else 0,
                    'used': used.count if hasattr(used, 'count') else 0,
                    'valid': active.count if hasattr(active, 'count') else 0,
                    'users': unique_users,
                    'storage': 'Supabase'
                }
                
            except Exception as e:
                log.error(f"Error getting stats from Supabase: {e}")
                return {'total': 0, 'used': 0, 'valid': 0, 'users': 0, 'storage': 'Error'}
        else:
            total = len(self.keys)
            used = sum(1 for k in self.keys.values() if k.get('used'))
            now = datetime.now().timestamp()
            valid = sum(1 for k in self.keys.values() if not k.get('used') and now <= k['expires_at'])
            users = len(self.user_keys)
            return {'total': total, 'used': used, 'valid': valid, 'users': users, 'storage': 'Memory'}

keys = KeyManager()

# ==================== STATE ====================
active_scans: Dict = {}
scan_history = []
start_time = datetime.now()

# ==================== ROUTES ====================

# Add this to backend.py after the other routes

class VerifyKeyRequest(BaseModel):
    scan_key: str
    user_id: str

class VerifyKeyResponse(BaseModel):
    valid: bool
    message: str

@app.post("/api/verify-key", response_model=VerifyKeyResponse)
async def verify_key(req: VerifyKeyRequest, x_api_key: Optional[str] = Header(None)):
    """Verify a specific scan key for a user"""
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")
    
    if supabase:
        try:
            now = datetime.now().isoformat()
            result = supabase.table('scan_keys')\
                .select('*')\
                .eq('scan_key', req.scan_key)\
                .eq('user_id', req.user_id)\
                .eq('used', False)\
                .gt('expires_at', now)\
                .execute()
            
            if result.data:
                return VerifyKeyResponse(valid=True, message="Key is valid")
            else:
                return VerifyKeyResponse(valid=False, message="Invalid or expired key")
        except Exception as e:
            return VerifyKeyResponse(valid=False, message=f"Error: {e}")
    else:
        # Memory fallback
        key_data = keys.keys.get(req.scan_key)
        if not key_data:
            return VerifyKeyResponse(valid=False, message="Key not found")
        if key_data.get('used'):
            return VerifyKeyResponse(valid=False, message="Key already used")
        if datetime.now().timestamp() > key_data['expires_at']:
            return VerifyKeyResponse(valid=False, message="Key expired")
        if key_data['user_id'] != req.user_id:
            return VerifyKeyResponse(valid=False, message="Key not assigned to this user")
        
        return VerifyKeyResponse(valid=True, message="Key is valid")

@app.get("/")
async def root():
    return {
        "service": "xotiic CyberScan API",
        "version": "2.1.0",
        "status": "online",
        "uptime": str(datetime.now() - start_time).split('.')[0],
        "storage": "Supabase" if supabase else "Memory"
    }

@app.get("/health")
async def health():
    stats = await keys.stats()
    return {
        "status": "healthy",
        "bot_token": bool(BOT_TOKEN),
        "channel_id": CHANNEL_ID,
        "supabase": bool(supabase),
        "keys": stats,
        "active_scans": len(active_scans),
        "total_scans": len(scan_history),
        "uptime": str(datetime.now() - start_time).split('.')[0],
    }

@app.get("/api/bot-token", response_model=BotTokenResponse)
async def get_bot_token(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")
    log.info("Bot token requested")
    return BotTokenResponse(
        bot_token=BOT_TOKEN,
        channel_id=int(CHANNEL_ID),
        message="Bot token retrieved"
    )

@app.post("/api/login", response_model=LoginResponse)
async def login(req: LoginRequest, x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")

    uid = req.user_id.strip()
    log.info(f"Login attempt: {uid}")

    valid, msg, used_key = await keys.validate(uid)
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

    # Store scan results in Supabase if available
    if supabase:
        try:
            scan_data = {
                'scan_id': req.scan_id,
                'user_id': req.user_id,
                'completed_at': datetime.now().isoformat(),
                'files_scanned': req.files_scanned,
                'suspicious_count': req.suspicious_count,
                'duration': req.duration,
                'key_used': scan.get('key'),
                'scan_results': req.logitech if req.logitech else {}
            }
            supabase.table('scan_history').insert(scan_data).execute()
        except Exception as e:
            log.error(f"Failed to store scan history: {e}")

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
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")

    scan_key = await keys.generate(req.user_id, req.duration_days)
    if not scan_key:
        raise HTTPException(500, "Failed to generate key")

    exp = (datetime.now() + timedelta(days=req.duration_days)).strftime('%Y-%m-%d %H:%M:%S')

    return GenerateKeyResponse(
        key=scan_key,
        user_id=req.user_id,
        expires_at=exp,
        message=f"Key valid for {req.duration_days} days. Expires {exp}."
    )

@app.get("/api/stats")
async def stats(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")
    
    key_stats = await keys.stats()
    return {
        "keys": key_stats,
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

@app.get("/api/user/{user_id}/keys")
async def get_user_keys(user_id: str, x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")
    
    if supabase:
        try:
            result = supabase.table('scan_keys')\
                .select('*')\
                .eq('user_id', user_id)\
                .order('created_at', desc=True)\
                .execute()
            return {"keys": result.data}
        except Exception as e:
            raise HTTPException(500, f"Database error: {e}")
    else:
        keys_list = keys.user_keys.get(user_id, [])
        return {"keys": [{"scan_key": k, **keys.keys[k]} for k in keys_list]}

if __name__ == "__main__":
    port = int(os.getenv('PORT', 5000))
    log.info(f"Starting xotiic CyberScan API on port {port}")
    log.info(f"Supabase: {'Connected' if supabase else 'Not connected (using memory)'}")
    
    import asyncio
    async def startup():
        stats = await keys.stats()
        log.info(f"Initial key stats: {stats}")
    
    asyncio.run(startup())
    uvicorn.run(app, host="0.0.0.0", port=port)
