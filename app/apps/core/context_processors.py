from django.conf import settings

from .rbac import Perm, has_perm


def nav(request):
    user = getattr(request, "user", None)
    if not getattr(user, "is_authenticated", False):
        return {}
    return {
        "nixfort_version": settings.NIXFORT_VERSION,
        "can_manage_users": has_perm(user, Perm.MANAGE_USERS),
        "can_create_project": has_perm(user, Perm.CREATE_PROJECT),
    }
