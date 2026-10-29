"""Security headers (CSP and friends) and the per-request roles cache."""

from django.utils.cache import add_never_cache_headers


class SecurityHeadersMiddleware:
    """Content-Security-Policy and a few extra headers. All assets are local (no CDN).
    Pages of a signed-in user are never stored by the browser or a proxy: after sign-out the Back button
    cannot show project data again (WSTG-ATHN-06)."""

    CSP = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; "
        "object-src 'none'"
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", self.CSP)
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated and not response.has_header("Cache-Control"):
            add_never_cache_headers(response)
        return response


class RequestRolesCacheMiddleware:
    """Gives the signed-in user of this request an empty roles cache (used by rbac.roles_of).
    The cache lives exactly as long as the request: every request loads a fresh user object."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            user._request_roles = {}
        return self.get_response(request)
