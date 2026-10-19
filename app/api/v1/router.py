from fastapi import APIRouter
from .scan import router as scan_router
from .batch import router as batch_router
from .admin import router as admin_router
from .history import router as history_router
from .audit import router as audit_router
from .eval import router as eval_router
from .adversarial import router as adversarial_router
from .brand import router as brand_router
from .sandbox import router as sandbox_router
from .training import router as training_router
from .oauth import router as oauth_router
from .mobile import router as mobile_router
from .threat_intel import router as threat_intel_router
from .vishing import router as vishing_router

api_router = APIRouter()
api_router.include_router(scan_router, prefix="/scan", tags=["Scanning"])
api_router.include_router(batch_router, prefix="/batch", tags=["Batch"])
api_router.include_router(admin_router, prefix="/admin", tags=["Admin"])
api_router.include_router(history_router, prefix="/history", tags=["History"])
api_router.include_router(audit_router, prefix="/audit", tags=["Audit"])
api_router.include_router(eval_router, prefix="/eval", tags=["Red Team Eval"])
api_router.include_router(adversarial_router, prefix="/adversarial", tags=["Adversarial"])
api_router.include_router(brand_router, prefix="/brand", tags=["Brand Protection"])
api_router.include_router(sandbox_router, prefix="/sandbox", tags=["Browser Sandbox"])
api_router.include_router(training_router, prefix="/training", tags=["Training Data"])
api_router.include_router(oauth_router,   prefix="/oauth",    tags=["OAuth Detection"])
api_router.include_router(mobile_router,      prefix="/mobile",       tags=["Mobile Phishing"])
api_router.include_router(threat_intel_router, prefix="/threat-intel", tags=["Threat Intel"])
api_router.include_router(vishing_router,      prefix="/vishing",     tags=["Vishing Analysis"])
