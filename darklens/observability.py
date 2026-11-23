"""Optional error reporting. Off unless SENTRY_DSN is set and the sentry-sdk package is installed; never required,
and a failure here must never stop the API starting. No request bodies or user text are sent."""
from __future__ import annotations

import logging
import os

log = logging.getLogger("darklens")


def init() -> bool:
    dsn = os.getenv("SENTRY_DSN", "").strip()
    if not dsn:
        return False
    try:
        import sentry_sdk  # type: ignore[import-not-found]
    except ImportError:
        log.warning("SENTRY_DSN is set but sentry-sdk is not installed; error reporting stays off.")
        return False
    try:
        sentry_sdk.init(dsn=dsn, send_default_pii=False, max_request_body_size="never", traces_sample_rate=0.0,
                        release=os.getenv("RENDER_GIT_COMMIT", "")[:12] or None)
    except Exception as e:  # a bad DSN must not take the service down
        log.warning("Error reporting could not start: %s", type(e).__name__)
        return False
    return True
