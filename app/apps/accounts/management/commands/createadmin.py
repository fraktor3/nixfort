"""One-time bootstrap of the first administrator (FR-AUTH-01). No default password exists."""

import getpass

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.accounts.models import RoleAssignment
from apps.core import audit
from apps.core.models import Action
from apps.core.rbac import Role


class Command(BaseCommand):
    help = "Создать первого администратора NIXFORT (только если администратора ещё нет)."

    def add_arguments(self, parser):
        parser.add_argument("--username", default=None)

    def handle(self, *args, **opts):
        if RoleAssignment.objects.filter(role=Role.ADMIN, project__isnull=True, user__is_active=True).exists():
            raise CommandError("Администратор уже существует. Новых пользователей создаёт администратор в интерфейсе.")
        User = get_user_model()
        username = opts["username"] or input("Логин администратора: ").strip()
        if not username or User.objects.filter(username=username).exists():
            raise CommandError("Пустой или уже занятый логин.")
        password = getpass.getpass("Пароль (не меньше 12 символов): ")
        if password != getpass.getpass("Пароль ещё раз: "):
            raise CommandError("Пароли не совпадают.")
        user = User(username=username)
        try:
            validate_password(password, user)
        except ValidationError as exc:
            raise CommandError("; ".join(exc.messages)) from None
        with transaction.atomic():
            user.set_password(password)
            user.save()
            RoleAssignment.objects.create(user=user, role=Role.ADMIN, project=None)
            audit.log(None, Action.USER_CREATED, obj=user, actor_name="createadmin", username=username, role=Role.ADMIN)
        self.stdout.write(self.style.SUCCESS(f"Администратор {username} создан."))
