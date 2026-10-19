"""Brand Protection - backward-compatible re-exports from sub-modules."""
from app.services.dns_checkers import brand_dns_check
from app.services.lookalike_generator import generate_lookalikes, scan_lookalikes

__all__ = ["brand_dns_check", "generate_lookalikes", "scan_lookalikes"]
