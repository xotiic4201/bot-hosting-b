import os
import logging
import secrets
import string
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

# ==================== CONFIG ====================
BOT_TOKEN = os.getenv('BOT_TOKEN')
CHANNEL_ID = os.getenv('CHANNEL_ID', '0')
API_KEY = os.getenv('API_KEY')
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
log = logging.getLogger("r6x-backend")

if not BOT_TOKEN:
    log.warning("BOT_TOKEN not set! Bot commands will not work.")

if not SUPABASE_URL or not SUPABASE_KEY:
    log.warning("SUPABASE_URL or SUPABASE_KEY not set! Using in-memory storage.")
else:
    log.info("Supabase credentials loaded")

# ==================== SUPABASE INIT ====================
supabase: Optional[Client] = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        log.info("✓ Supabase client initialized")
    except Exception as e:
        log.error(f"Failed to initialize Supabase: {e}")

# ==================== APP ====================
app = FastAPI(title="R6X Scanner API", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ==================== MODELS ====================
class LoginRequest(BaseModel):
    user_id: str
    scan_key: Optional[str] = None

class LoginResponse(BaseModel):
    success: bool
    scan_id: Optional[str] = None
    message: str

class BotTokenResponse(BaseModel):
    bot_token: str
    channel_id: str
    message: str

class ScanCompleteRequest(BaseModel):
    scan_id: str
    user_id: str
    files_scanned: int
    suspicious_count: int
    duration: float
    registry_traces: Optional[int] = 0
    prefetch_entries: Optional[int] = 0
    ghub_scripts: Optional[int] = 0
    r6_accounts: Optional[int] = 0
    steam_accounts: Optional[int] = 0
    logitech: Optional[Dict[str, Any]] = None

class GenerateKeyRequest(BaseModel):
    user_id: str
    duration_days: Optional[int] = 30

class GenerateKeyResponse(BaseModel):
    key: str
    user_id: str
    expires_at: str
    message: str

class VerifyKeyRequest(BaseModel):
    scan_key: str
    user_id: str

class VerifyKeyResponse(BaseModel):
    valid: bool
    message: str

class DownloadEvent(BaseModel):
    user_id: Optional[str] = None

# ==================== STORAGE MANAGER ====================
class StorageManager:
    def __init__(self):
        self.supabase = supabase
        self._init_tables()
        
        # In-memory fallback storage
        self.keys = {}
        self.user_keys = {}
        self.scan_history = []
        self.download_logs = []
        self.total_scans = 0
        self.total_downloads = 0
        self.total_files_scanned = 0
        
    def _init_tables(self):
        """Initialize tables if using Supabase"""
        if not self.supabase:
            log.warning("Supabase not available, using in-memory storage")
            return
        log.info("Using Supabase for storage")

    async def generate_key(self, user_id: str, days: int = 30) -> Optional[str]:
        """Generate a new scan key"""
        alphabet = string.ascii_uppercase + string.digits
        scan_key = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        if self.supabase:
            try:
                existing = self.supabase.table('scan_keys').select('scan_key').eq('scan_key', scan_key).execute()
                if existing.data:
                    return await self.generate_key(user_id, days)
                
                now = datetime.now()
                expires_at = now + timedelta(days=days)
                
                data = {
                    'scan_key': scan_key,
                    'user_id': user_id,
                    'created_at': now.isoformat(),
                    'expires_at': expires_at.isoformat(),
                    'used': False,
                    'duration_days': days
                }
                
                result = self.supabase.table('scan_keys').insert(data).execute()
                if result.data:
                    log.info(f"Key generated for {user_id}: {scan_key}")
                    return scan_key
            except Exception as e:
                log.error(f"Supabase generate error: {e}")
        
        # Fallback to memory
        self.keys[scan_key] = {
            'user_id': user_id,
            'expires_at': (datetime.now() + timedelta(days=days)).timestamp(),
            'used': False,
            'created_at': datetime.now().isoformat(),
            'duration_days': days
        }
        self.user_keys.setdefault(user_id, []).append(scan_key)
        return scan_key

    async def validate_key(self, user_id: str, specific_key: str = None):
        """Validate a user has a valid key. Returns (valid, message, key_used)"""
        if self.supabase:
            try:
                now = datetime.now().isoformat()
                query = self.supabase.table('scan_keys')\
                    .select('*')\
                    .eq('used', False)\
                    .gt('expires_at', now)
                
                if specific_key:
                    query = query.eq('scan_key', specific_key).eq('user_id', user_id)
                else:
                    query = query.eq('user_id', user_id)
                
                result = query.execute()
                
                if not result.data:
                    if specific_key:
                        return False, "Invalid or expired scan key", None
                    return False, "No valid keys found. Use /gen in Discord to get a key.", None
                
                key_data = result.data[0]
                scan_key = key_data['scan_key']
                
                # Mark as used
                self.supabase.table('scan_keys')\
                    .update({'used': True, 'used_at': datetime.now().isoformat()})\
                    .eq('scan_key', scan_key)\
                    .execute()
                
                log.info(f"Key validated for {user_id}: {scan_key}")
                return True, "Authorized", scan_key
                
            except Exception as e:
                log.error(f"Supabase validate error: {e}")
                return False, f"Database error", None
        
        # Fallback to memory
        keys_list = self.user_keys.get(user_id, [])
        if specific_key:
            if specific_key not in keys_list:
                return False, "Key not found for this user", None
            keys_list = [specific_key]
        
        if not keys_list:
            return False, "No keys found. Contact xotiic.", None
        
        now = datetime.now().timestamp()
        for k in keys_list:
            kd = self.keys.get(k)
            if not kd or kd.get('used'):
                continue
            if now > kd['expires_at']:
                continue
            
            self.keys[k]['used'] = True
            self.keys[k]['used_at'] = datetime.now().isoformat()
            return True, "Authorized", k
        
        return False, "No valid keys found (all used or expired)", None

    async def record_scan(self, scan_data: dict):
        """Record a completed scan"""
        self.total_scans += 1
        self.total_files_scanned += scan_data.get('files_scanned', 0)
        
        scan_record = {
            **scan_data,
            'timestamp': datetime.now().isoformat()
        }
        self.scan_history.append(scan_record)
        
        # Keep last 100
        if len(self.scan_history) > 100:
            self.scan_history = self.scan_history[-100:]
        
        if self.supabase:
            try:
                self.supabase.table('scan_history').insert(scan_record).execute()
            except Exception as e:
                log.error(f"Failed to save scan to Supabase: {e}")
        
        return self.total_scans

    async def record_download(self, user_id: str = None):
        """Record a download event"""
        self.total_downloads += 1
        
        log_entry = {
            'user_id': user_id or 'anonymous',
            'timestamp': datetime.now().isoformat()
        }
        self.download_logs.append(log_entry)
        
        # Keep last 50
        if len(self.download_logs) > 50:
            self.download_logs = self.download_logs[-50:]
        
        if self.supabase:
            try:
                self.supabase.table('download_logs').insert(log_entry).execute()
            except Exception as e:
                log.error(f"Failed to save download to Supabase: {e}")
        
        return self.total_downloads

    async def get_stats(self):
        """Get current statistics for frontend"""
        return {
            'total_scans': self.total_scans,
            'total_downloads': self.total_downloads,
            'total_files_scanned': self.total_files_scanned,
            'active_scans': len([s for s in self.scan_history if s.get('status') == 'active']),
            'recent_scans': self.scan_history[-10:],
            'recent_downloads': self.download_logs[-10:]
        }

    async def get_key_stats(self):
        """Get key statistics"""
        if self.supabase:
            try:
                now = datetime.now().isoformat()
                total = self.supabase.table('scan_keys').select('count', count='exact').execute()
                used = self.supabase.table('scan_keys').select('count', count='exact').eq('used', True).execute()
                valid = self.supabase.table('scan_keys').select('count', count='exact').eq('used', False).gt('expires_at', now).execute()
                return {
                    'total': total.count if hasattr(total, 'count') else 0,
                    'used': used.count if hasattr(used, 'count') else 0,
                    'valid': valid.count if hasattr(valid, 'count') else 0
                }
            except:
                pass
        
        total = len(self.keys)
        used = sum(1 for k in self.keys.values() if k.get('used'))
        now = datetime.now().timestamp()
        valid = sum(1 for k in self.keys.values() if not k.get('used') and now <= k['expires_at'])
        return {'total': total, 'used': used, 'valid': valid}

storage = StorageManager()
active_scans = {}
start_time = datetime.now()

# ==================== API ROUTES ====================

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Invalid API key")
    return True

@app.get("/")
async def root():
    return {
        "service": "R6X Scanner API",
        "version": "2.1.0",
        "status": "online",
        "uptime": str(datetime.now() - start_time).split('.')[0]
    }

@app.get("/health")
async def health():
    stats = await storage.get_stats()
    return {
        "status": "healthy",
        "supabase": bool(supabase),
        "total_scans": stats['total_scans'],
        "total_downloads": stats['total_downloads'],
        "uptime": str(datetime.now() - start_time).split('.')[0]
    }

@app.get("/api/bot-token", response_model=BotTokenResponse)
async def get_bot_token(verified: bool = Depends(verify_api_key)):
    """Return Discord bot token and channel ID for the scanner app"""
    return BotTokenResponse(
        bot_token=BOT_TOKEN or "MOCK_TOKEN_FOR_TESTING",
        channel_id=str(CHANNEL_ID),
        message="Bot token retrieved. Set DISCORD_BOT_TOKEN env var for real bot."
    )

@app.post("/api/login", response_model=LoginResponse)
async def login(req: LoginRequest, verified: bool = Depends(verify_api_key)):
    """Authenticate a user with Discord ID and optional scan key"""
    uid = req.user_id.strip()
    log.info(f"Login attempt: {uid}")
    
    valid, msg, used_key = await storage.validate_key(uid, req.scan_key if req.scan_key else None)
    
    if not valid:
        log.warning(f"Login denied for {uid}: {msg}")
        return LoginResponse(success=False, message=msg)
    
    scan_id = f"R6X-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uid[-6:]}"
    active_scans[scan_id] = {
        'user_id': uid,
        'start': datetime.now().isoformat(),
        'status': 'active',
        'key': used_key
    }
    
    log.info(f"Login OK: {uid} | scan_id: {scan_id}")
    return LoginResponse(success=True, scan_id=scan_id, message=f"Authorized! Scan ID: {scan_id}")

@app.post("/api/verify-key", response_model=VerifyKeyResponse)
async def verify_key(req: VerifyKeyRequest, verified: bool = Depends(verify_api_key)):
    """Verify a scan key without marking it as used"""
    valid, msg, _ = await storage.validate_key(req.user_id, req.scan_key)
    return VerifyKeyResponse(valid=valid, message=msg)

@app.post("/api/scan/complete")
async def scan_complete(req: ScanCompleteRequest, verified: bool = Depends(verify_api_key)):
    """Record a completed scan"""
    scan = active_scans.get(req.scan_id)
    if not scan:
        raise HTTPException(404, "Scan ID not found")
    if scan['user_id'] != req.user_id:
        raise HTTPException(403, "User mismatch")
    
    # Calculate suspicious score
    suspicious_score = req.suspicious_count + (req.ghub_scripts or 0) * 2 + (req.registry_traces or 0) // 10
    
    scan_record = {
        'scan_id': req.scan_id,
        'user_id': req.user_id,
        'files_scanned': req.files_scanned,
        'suspicious_count': req.suspicious_count,
        'suspicious_score': suspicious_score,
        'registry_traces': req.registry_traces or 0,
        'prefetch_entries': req.prefetch_entries or 0,
        'ghub_scripts': req.ghub_scripts or 0,
        'r6_accounts': req.r6_accounts or 0,
        'steam_accounts': req.steam_accounts or 0,
        'duration': req.duration,
        'status': 'completed'
    }
    
    await storage.record_scan(scan_record)
    
    # Clean up active scan
    del active_scans[req.scan_id]
    
    log.info(f"Scan complete: {req.scan_id} | files:{req.files_scanned} suspicious:{req.suspicious_count}")
    return {"status": "ok", "scan_id": req.scan_id}

@app.post("/api/download")
async def record_download(event: DownloadEvent = None, verified: bool = Depends(verify_api_key)):
    """Record a download event for stats"""
    total = await storage.record_download(event.user_id if event else None)
    log.info(f"Download recorded. Total downloads: {total}")
    return {"success": True, "total_downloads": total}

@app.get("/api/stats")
async def get_stats(verified: bool = Depends(verify_api_key)):
    """Get all statistics for frontend display"""
    stats = await storage.get_stats()
    key_stats = await storage.get_key_stats()
    
    return {
        "total_scans": stats['total_scans'],
        "total_downloads": stats['total_downloads'],
        "total_files_scanned": stats['total_files_scanned'],
        "keys": key_stats,
        "active_scans": stats['active_scans'],
        "recent_scans": stats['recent_scans'],
        "recent_downloads": stats['recent_downloads']
    }

@app.get("/api/live-logs")
async def get_live_logs(limit: int = 20, verified: bool = Depends(verify_api_key)):
    """Get recent activity logs for the frontend live log panel"""
    stats = await storage.get_stats()
    
    logs = []
    
    # Add scan logs
    for scan in stats['recent_scans'][-limit:]:
        logs.append({
            "type": "scan",
            "user_id": scan.get('user_id', 'unknown'),
            "files_scanned": scan.get('files_scanned', 0),
            "suspicious_flags": scan.get('suspicious_count', 0),
            "timestamp": scan.get('timestamp', ''),
            "message": f"🔍 Scan by {scan.get('user_id', 'unknown')[:12]}... - {scan.get('files_scanned', 0)} files, {scan.get('suspicious_count', 0)} flags"
        })
    
    # Add download logs
    for dl in stats['recent_downloads'][-limit:]:
        logs.append({
            "type": "download",
            "user_id": dl.get('user_id', 'anonymous'),
            "timestamp": dl.get('timestamp', ''),
            "message": f"📥 Download from {dl.get('user_id', 'anonymous')}"
        })
    
    # Sort by timestamp (newest first)
    logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return {
        "logs": logs[:limit],
        "total_scans": stats['total_scans'],
        "total_downloads": stats['total_downloads'],
        "total_files": stats['total_files_scanned']
    }

@app.post("/api/generate-key", response_model=GenerateKeyResponse)
async def generate_key(req: GenerateKeyRequest, verified: bool = Depends(verify_api_key)):
    """Generate a new scan key for a user"""
    scan_key = await storage.generate_key(req.user_id, req.duration_days or 30)
    if not scan_key:
        raise HTTPException(500, "Failed to generate key")
    
    exp = (datetime.now() + timedelta(days=req.duration_days or 30)).strftime('%Y-%m-%d %H:%M:%S')
    
    return GenerateKeyResponse(
        key=scan_key,
        user_id=req.user_id,
        expires_at=exp,
        message=f"Key valid for {req.duration_days or 30} days"
    )

@app.get("/api/scan/{scan_id}")
async def scan_status(scan_id: str, verified: bool = Depends(verify_api_key)):
    """Get status of a specific scan"""
    if scan_id in active_scans:
        return active_scans[scan_id]
    
    stats = await storage.get_stats()
    for s in stats['recent_scans']:
        if s.get('scan_id') == scan_id:
            return s
    
    raise HTTPException(404, "Scan not found")

@app.get("/api/user/{user_id}/keys")
async def get_user_keys(user_id: str, verified: bool = Depends(verify_api_key)):
    """Get all keys for a specific user"""
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
        keys_list = storage.user_keys.get(user_id, [])
        return {"keys": [{"scan_key": k, **storage.keys[k]} for k in keys_list]}

if __name__ == "__main__":
    port = int(os.getenv('PORT', 5000))
    log.info(f"Starting R6X Scanner API on port {port}")
    log.info(f"Supabase: {'Connected' if supabase else 'Not connected (using memory)'}")
    
    import asyncio
    async def startup():
        stats = await storage.get_stats()
        log.info(f"Initial stats: {stats['total_scans']} scans, {stats['total_downloads']} downloads, {stats['total_files_scanned']} files")
    
    asyncio.run(startup())
    uvicorn.run(app, host="0.0.0.0", port=port)
