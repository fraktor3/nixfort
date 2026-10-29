"""Sign-in, sign-out, failed sign-in and lockout go to the audit journal."""

from axes.signals import user_locked_out
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from apps.core import audit
from apps.core.models import Action, Outcome


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    audit.log(user, Action.LOGIN, request=request)


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    if user is not None:
        audit.log(user, Action.LOGOUT, request=request)


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs):
    username = str((credentials or {}).get("username", ""))[:150]
    audit.log(
        None, Action.LOGIN_FAILED, outcome=Outcome.FAILED, request=request, actor_name=username, username=username
    )


@receiver(user_locked_out)
def on_locked_out(sender, request=None, username=None, ip_address=None, **kwargs):
    audit.log(
        None,
        Action.LOGIN_FAILED,
        outcome=Outcome.DENIED,
        request=request,
        actor_name=str(username or "")[:150],
        reason="locked_out",
    )
