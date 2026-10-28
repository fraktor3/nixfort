"""Pure check logic: no database, no network. Every evaluator gets facts and a context and
returns an Outcome. Missing data never yields PASS (ADR-009, FR-AUD-05)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

PASS, FAIL, UNKNOWN, NA, ERROR = "PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "ERROR"
STATUSES = (PASS, FAIL, UNKNOWN, NA, ERROR)
CATALOG_VERSION = "2026.1"


@dataclass(frozen=True)
class Outcome:
    status: str
    observed: Any = None
    expected: Any = None
    explanation: str = ""


@dataclass(frozen=True)
class Ctx:
    """What a check may know about the node besides collected facts."""

    roles: frozenset[str]
    expected_tcp_ports: frozenset[int] = frozenset()
    ids_interface: str = ""
    controller_ip: str = ""
    active_policy_version: int | None = None


class MissingFact(Exception):
    """A required fact is absent or the agent reported an error for it."""

    def __init__(self, key: str, fact: dict | None):
        self.key = key
        self.fact = fact


def req(result: dict, key: str, fact_key: str):
    """A field that must be present in an agent result; absence -> UNKNOWN, never a default."""
    if not isinstance(result, dict) or key not in result:
        raise MissingFact(f"{fact_key}.{key}", None)
    return result[key]


def need(facts: dict, key: str) -> dict:
    """Return the `result` of fact `key` or raise MissingFact (-> ERROR/UNKNOWN)."""
    f = facts.get(key)
    if not f or f.get("state") != "OK" or not isinstance(f.get("result"), dict):
        raise MissingFact(key, f)
    return f["result"]


@dataclass(frozen=True)
class CheckDef:
    id: str
    domain: str
    title: str
    severity: str
    roles: frozenset[str]  # applicable when the node has ANY of these roles
    facts: tuple[str, ...]
    expected: str
    remediation: str | None  # action id of the agent, or None (recommendation only)
    source_ref: str
    evaluate: Callable[[dict, Ctx], Outcome] = field(repr=False)


MANAGED = frozenset({"gateway", "server", "ids_sensor"})


# ---------------------------------------------------------------- SYS
def sys_01(facts, ctx):
    s = need(facts, "system")
    req(s, "os_supported", "system")
    obs = f"{s.get('os', {}).get('pretty_name')} {s.get('os', {}).get('arch')}"
    if s.get("os_supported") and s.get("os", {}).get("arch") == "x86_64":
        return Outcome(PASS, obs, "Ubuntu 24.04 / Astra 1.8, amd64", "ОС входит в матрицу поддержки.")
    return Outcome(
        FAIL,
        obs,
        "Ubuntu 24.04 / Astra 1.8, amd64",
        "ОС не поддерживается: изменения на этом узле вноситься не будут.",
    )


def sys_02(facts, ctx):
    t = req(need(facts, "system"), "time_sync", "system") or {}
    synced = t.get("synchronized")
    if synced is None:
        return Outcome(UNKNOWN, t, "синхронизировано", "Состояние синхронизации времени не получено.")
    if synced:
        return Outcome(PASS, t, "синхронизировано", "Время синхронизировано, журналы событий сопоставимы.")
    return Outcome(
        FAIL, t, "синхронизировано", "Время не синхронизировано: метки событий в журналах и IDS будут недостоверны."
    )


def sys_03(facts, ctx):
    active = req(need(facts, "system"), "journald_active", "system")
    if active is None:
        return Outcome(UNKNOWN, None, True, "Нет данных о systemd-journald.")
    return Outcome(
        PASS if active else FAIL,
        active,
        True,
        "Системный журнал работает." if active else "Системный журнал не работает: события не фиксируются.",
    )


def sys_04(facts, ctx):
    listeners = req(need(facts, "listeners"), "listeners", "listeners")
    exposed = sorted({int(x["port"]) for x in listeners if not x.get("loopback")})
    unexpected = [p for p in exposed if p not in ctx.expected_tcp_ports]
    expected = sorted(ctx.expected_tcp_ports)
    if unexpected:
        return Outcome(
            FAIL,
            exposed,
            expected,
            f"Слушают порты, не объявленные для узла: {', '.join(map(str, unexpected))}. "
            "Отключите лишние службы или добавьте порт в описание узла, если он нужен.",
        )
    return Outcome(PASS, exposed, expected, "Все прослушиваемые TCP-порты объявлены в описании узла.")


# ---------------------------------------------------------------- SSH
def _ssh(facts) -> dict:
    s = need(facts, "ssh")
    if not req(s, "config_valid", "ssh"):
        raise MissingFact("ssh_invalid", None)
    return s.get("effective") or {}


def _ssh_eq(key: str, want: str, ok_text: str, bad_text: str):
    def ev(facts, ctx):
        val = _ssh(facts).get(key)
        if val is None:
            return Outcome(UNKNOWN, None, want, f"Параметр {key} не найден в выводе sshd -T.")
        return Outcome(PASS if val == want else FAIL, val, want, ok_text if val == want else bad_text)

    return ev


def _ssh_le(key: str, limit: int, ok_text: str, bad_text: str):
    def ev(facts, ctx):
        val = _ssh(facts).get(key)
        try:
            num = int(str(val))
        except (TypeError, ValueError):
            return Outcome(UNKNOWN, val, f"≤ {limit}", f"Параметр {key} не получен или не число.")
        return Outcome(PASS if num <= limit else FAIL, num, f"≤ {limit}", ok_text if num <= limit else bad_text)

    return ev


def ssh_07(facts, ctx):
    s = need(facts, "ssh")
    if req(s, "config_valid", "ssh"):
        return Outcome(PASS, True, True, "sshd -t: конфигурация корректна.")
    return Outcome(
        FAIL,
        s.get("validate_stderr", "")[:300],
        "sshd -t без ошибок",
        "Конфигурация sshd содержит ошибку. Автоматические изменения SSH заблокированы до исправления.",
    )


# ---------------------------------------------------------------- FW (gateway)
def fw_01(facts, ctx):
    s = need(facts, "system")
    n = need(facts, "nft")
    pkg = (req(s, "packages", "system") or {}).get("nftables")
    svc = req(s, "services", "system") or {}
    c = req(n, "conflict", "nft") or {}
    problems = []
    if not pkg:
        problems.append("nftables не установлен")
    if svc.get("ufw") == "active" or c.get("ufw"):
        problems.append("активен UFW")
    if svc.get("firewalld") == "active" or c.get("firewalld"):
        problems.append("активен firewalld")
    if c.get("docker"):
        problems.append("правила Docker")
    if c.get("foreign_base_chains"):
        problems.append("чужие цепочки с policy drop: " + ", ".join(c["foreign_base_chains"]))
    obs = {"nftables": pkg, "ufw": svc.get("ufw"), "firewalld": svc.get("firewalld"), "conflict": c}
    if problems:
        return Outcome(
            FAIL,
            obs,
            "nftables без других менеджеров правил",
            "Изменение правил запрещено: " + "; ".join(problems) + ".",
        )
    return Outcome(PASS, obs, "nftables без других менеджеров правил", "Конфликтующих менеджеров правил нет.")


def fw_02(facts, ctx):
    n = need(facts, "nft")
    req(n, "nixfort_table_present", "nft")
    if ctx.active_policy_version is None:
        return Outcome(
            UNKNOWN, None, "активная политика", "В проекте нет активной политики соединений, сравнивать не с чем."
        )
    meta = n.get("policy_meta") or {}
    present = n.get("nixfort_table_present")
    obs = {"table": present, "policy_version": meta.get("policy_version")}
    want = f"таблица inet nixfort с версией политики v{ctx.active_policy_version}"
    if present and meta.get("policy_version") == ctx.active_policy_version:
        return Outcome(PASS, obs, want, "На шлюзе применена текущая версия политики.")
    why = "управляемая таблица правил отсутствует" if not present else f"применена версия v{meta.get('policy_version')}"
    return Outcome(FAIL, obs, want, f"Политика на шлюзе не соответствует активной: {why}.")


def fw_03(facts, ctx):
    n = need(facts, "nft")
    chain = (req(n, "nixfort_chains", "nft") or {}).get("forward") or {}
    pol = chain.get("policy")
    if pol == "drop":
        return Outcome(PASS, pol, "drop", "Транзитный трафик, не разрешённый политикой, отбрасывается.")
    return Outcome(FAIL, pol, "drop", "Нет запрета по умолчанию для транзитного трафика через шлюз.")


def fw_04(facts, ctx):
    n = need(facts, "nft")
    if not req(n, "nixfort_table_present", "nft"):
        return Outcome(
            NA,
            None,
            ctx.controller_ip,
            "Правила политики не применены: входящий доступ к шлюзу не ограничивается (см. FW-02).",
        )
    sources = n.get("nixfort_input_ssh_sources") or []
    if ctx.controller_ip and ctx.controller_ip in sources:
        return Outcome(PASS, sources, ctx.controller_ip, "SSH-доступ контроллера к шлюзу явно разрешён.")
    return Outcome(
        FAIL, sources, ctx.controller_ip, "Нет явного разрешения SSH с адреса контроллера: есть риск потери управления."
    )


# ---------------------------------------------------------------- HFW (server host firewall)
def hfw_01(facts, ctx):
    n = need(facts, "nft")
    present = req(n, "nixfort_table_present", "nft")
    want = "хостовый экран: input drop, SSH с контроллера, открыты только заявленные порты"
    if not present:
        return Outcome(
            FAIL, None, want, "Хостовый межсетевой экран не настроен: управляемая таблица правил отсутствует."
        )
    chains = n.get("nixfort_chains") or {}
    inp = (chains.get("input") or {}).get("policy")
    ssh_sources = n.get("nixfort_input_ssh_sources") or []
    ports = set(n.get("nixfort_input_ports") or [])
    obs = {"input_policy": inp, "ssh_sources": ssh_sources, "ports": sorted(ports)}
    problems = []
    if inp != "drop":
        problems.append("во входящей цепочке нет запрета по умолчанию")
    if ctx.controller_ip and ctx.controller_ip not in ssh_sources:
        problems.append("нет разрешения SSH с контроллера")
    missing = sorted(set(ctx.expected_tcp_ports) - ports)
    if missing:
        problems.append(f"не открыты заявленные порты: {missing}")
    if problems:
        return Outcome(FAIL, obs, want, "; ".join(problems).capitalize() + ".")
    return Outcome(PASS, obs, want, "Хостовый экран активен: лишние порты закрыты, управление сохранено.")


# ---------------------------------------------------------------- F2B (server)
def f2b_01(facts, ctx):
    s = need(facts, "system")
    pkg = (req(s, "packages", "system") or {}).get("fail2ban")
    svc = (req(s, "services", "system") or {}).get("fail2ban")
    obs = {"package": pkg, "service": svc}
    if pkg and svc == "active":
        return Outcome(PASS, obs, "установлен и работает", "Fail2ban работает.")
    return Outcome(
        FAIL,
        obs,
        "установлен и работает",
        "Fail2ban не установлен." if not pkg else "Fail2ban установлен, но служба не работает.",
    )


def f2b_02(facts, ctx):
    f = need(facts, "fail2ban")
    req(f, "installed", "fail2ban")
    sshd = f.get("sshd") or {}
    obs = {"installed": f.get("installed"), "service": f.get("service"), "jails": f.get("jails")}
    if sshd.get("enabled"):
        return Outcome(PASS, obs, "jail sshd включён", "Защита SSH от перебора паролей включена.")
    return Outcome(FAIL, obs, "jail sshd включён", "Перебор паролей SSH ничем не ограничивается.")


def f2b_03(facts, ctx):
    f = need(facts, "fail2ban")
    req(f, "installed", "fail2ban")
    sshd = f.get("sshd") or {}
    want = "maxretry ≤ 5, bantime ≥ 600 с"
    if not sshd.get("enabled"):
        return Outcome(FAIL, None, want, "Jail sshd не работает, параметры не действуют.")
    mr, bt = sshd.get("maxretry"), sshd.get("bantime")
    if mr is None or bt is None:
        return Outcome(UNKNOWN, {"maxretry": mr, "bantime": bt}, want, "Параметры jail не получены.")
    ok = mr <= 5 and (bt >= 600 or bt < 0)  # bantime -1 = permanent ban
    return Outcome(
        PASS if ok else FAIL,
        {"maxretry": mr, "bantime": bt},
        want,
        "Параметры соответствуют профилю." if ok else "Слишком мягкие параметры блокировки.",
    )


# ---------------------------------------------------------------- IDS (sensor)
def ids_01(facts, ctx):
    s = need(facts, "system")
    pkg = (req(s, "packages", "system") or {}).get("suricata")
    svc = (req(s, "services", "system") or {}).get("suricata")
    obs = {"package": pkg, "service": svc}
    if pkg and svc == "active":
        return Outcome(PASS, obs, "установлена и работает", "Датчик Suricata работает.")
    return Outcome(
        FAIL,
        obs,
        "установлена и работает",
        "Suricata не установлена." if not pkg else "Suricata установлена, но служба не работает.",
    )


def ids_02(facts, ctx):
    r = need(facts, "suricata")
    if not req(r, "installed", "suricata"):
        return Outcome(FAIL, None, "suricata -T без ошибок", "Suricata не установлена.")
    t = r.get("config_test") or {}
    if t.get("ok"):
        return Outcome(PASS, True, "suricata -T без ошибок", "Конфигурация Suricata корректна.")
    return Outcome(
        FAIL,
        (t.get("stderr_tail") or "")[-300:],
        "suricata -T без ошибок",
        "Конфигурация Suricata не проходит проверку.",
    )


def ids_03(facts, ctx):
    r = need(facts, "suricata")
    want = f"интерфейс {ctx.ids_interface}, EVE включён и читается"
    if not req(r, "installed", "suricata"):
        return Outcome(FAIL, None, want, "Suricata не установлена.")
    eve = r.get("eve") or {}
    ifaces = r.get("af_packet_interfaces") or []
    obs = {"interfaces": ifaces, "eve_enabled": eve.get("enabled"), "eve_readable": eve.get("readable")}
    problems = []
    if ctx.ids_interface not in ifaces:
        problems.append(f"датчик не слушает {ctx.ids_interface}")
    if not eve.get("enabled"):
        problems.append("журнал EVE выключен")
    elif not eve.get("readable"):
        problems.append("журнал EVE недоступен")
    if problems:
        return Outcome(FAIL, obs, want, "; ".join(problems).capitalize() + ".")
    return Outcome(
        PASS,
        obs,
        want,
        "Датчик настроен на нужный интерфейс и пишет события. Это не гарантирует, что виден весь трафик.",
    )


S = "CIS Ubuntu 24.04 Benchmark: SSH Server; Рекомендации ФСТЭК (2022): настройка авторизации"
CATALOG: tuple[CheckDef, ...] = (
    CheckDef(
        "SYS-01",
        "SYS",
        "Поддерживаемая ОС",
        "HIGH",
        MANAGED,
        ("system",),
        "Ubuntu 24.04 / Astra 1.8 amd64",
        None,
        "Матрица поддерживаемых ОС",
        sys_01,
    ),
    CheckDef(
        "SYS-02",
        "SYS",
        "Синхронизация времени",
        "MEDIUM",
        MANAGED,
        ("system",),
        "синхронизировано",
        None,
        "CIS: Time Synchronization",
        sys_02,
    ),
    CheckDef(
        "SYS-03",
        "SYS",
        "Системный журнал работает",
        "MEDIUM",
        MANAGED,
        ("system",),
        "journald active",
        None,
        "CIS: Logging; Рекомендации ФСТЭК: регистрация событий",
        sys_03,
    ),
    CheckDef(
        "SYS-04",
        "SYS",
        "Нет неожиданных TCP-служб",
        "HIGH",
        MANAGED,
        ("listeners",),
        "порты ⊆ объявленным",
        None,
        "CIS Controls 4.8: Uninstall/disable unnecessary services",
        sys_04,
    ),
    CheckDef(
        "SSH-01",
        "SSH",
        "Запрет входа root по SSH",
        "HIGH",
        MANAGED,
        ("ssh",),
        "permitrootlogin no",
        "ssh.apply_hardening_profile.v1",
        S,
        _ssh_eq("permitrootlogin", "no", "Вход root по SSH запрещён.", "Root может входить по SSH (хотя бы по ключу)."),
    ),
    CheckDef(
        "SSH-02",
        "SSH",
        "Вход только по ключу",
        "HIGH",
        MANAGED,
        ("ssh",),
        "passwordauthentication no",
        "ssh.apply_hardening_profile.v1",
        S,
        _ssh_eq(
            "passwordauthentication", "no", "Вход по паролю отключён.", "Разрешён вход по паролю: возможен перебор."
        ),
    ),
    CheckDef(
        "SSH-03",
        "SSH",
        "Пустые пароли запрещены",
        "HIGH",
        MANAGED,
        ("ssh",),
        "permitemptypasswords no",
        "ssh.apply_hardening_profile.v1",
        S,
        _ssh_eq("permitemptypasswords", "no", "Пустые пароли запрещены.", "Разрешён вход с пустым паролем."),
    ),
    CheckDef(
        "SSH-04",
        "SSH",
        "Лимит попыток входа",
        "MEDIUM",
        MANAGED,
        ("ssh",),
        "maxauthtries ≤ 4",
        "ssh.apply_hardening_profile.v1",
        S,
        _ssh_le("maxauthtries", 4, "Лимит попыток в норме.", "Слишком много попыток аутентификации за соединение."),
    ),
    CheckDef(
        "SSH-05",
        "SSH",
        "Время на вход",
        "LOW",
        MANAGED,
        ("ssh",),
        "logingracetime ≤ 60",
        "ssh.apply_hardening_profile.v1",
        S,
        _ssh_le("logingracetime", 60, "Время на вход ограничено.", "Слишком долгое ожидание входа."),
    ),
    CheckDef(
        "SSH-06",
        "SSH",
        "X11 forwarding выключен",
        "LOW",
        MANAGED,
        ("ssh",),
        "x11forwarding no",
        "ssh.apply_hardening_profile.v1",
        S,
        _ssh_eq("x11forwarding", "no", "X11 forwarding выключен.", "X11 forwarding включён без необходимости."),
    ),
    CheckDef("SSH-07", "SSH", "Конфигурация sshd корректна", "HIGH", MANAGED, ("ssh",), "sshd -t OK", None, S, ssh_07),
    CheckDef(
        "FW-01",
        "FW",
        "nftables без конфликтов",
        "HIGH",
        frozenset({"gateway"}),
        ("system", "nft"),
        "nftables, без UFW/firewalld/Docker",
        None,
        "Архитектурное решение ADR-011",
        fw_01,
    ),
    CheckDef(
        "FW-02",
        "FW",
        "Политика сегмента применена",
        "HIGH",
        frozenset({"gateway"}),
        ("nft",),
        "текущая версия политики",
        "nft.apply_policy.v1",
        "CIS Controls 4.4/4.5: firewall",
        fw_02,
    ),
    CheckDef(
        "FW-03",
        "FW",
        "Запрет по умолчанию в forward",
        "HIGH",
        frozenset({"gateway"}),
        ("nft",),
        "policy drop",
        "nft.apply_policy.v1",
        "CIS: default deny firewall policy",
        fw_03,
    ),
    CheckDef(
        "FW-04",
        "FW",
        "Управляющий доступ сохранён",
        "CRITICAL",
        frozenset({"gateway"}),
        ("nft",),
        "SSH от контроллера разрешён",
        "nft.apply_policy.v1",
        "Архитектура, раздел 6",
        fw_04,
    ),
    CheckDef(
        "HFW-01",
        "HFW",
        "Хостовый межсетевой экран сервера",
        "HIGH",
        frozenset({"server"}),
        ("system", "nft"),
        "input drop, SSH с контроллера, только заявленные порты",
        "nft.apply_host_firewall.v1",
        "CIS Controls 4: host-based firewall; ФСТЭК: ограничение сетевого доступа",
        hfw_01,
    ),
    CheckDef(
        "F2B-01",
        "F2B",
        "Fail2ban установлен и работает",
        "HIGH",
        frozenset({"server"}),
        ("system",),
        "active",
        "pkg.install_security_tool.v1",
        "CIS Controls 6: access control; ФСТЭК: ограничение попыток входа",
        f2b_01,
    ),
    CheckDef(
        "F2B-02",
        "F2B",
        "Jail sshd включён",
        "HIGH",
        frozenset({"server"}),
        ("fail2ban",),
        "enabled",
        "fail2ban.apply_sshd_profile.v1",
        "Рекомендации ФСТЭК: блокировка после неудачных попыток",
        f2b_02,
    ),
    CheckDef(
        "F2B-03",
        "F2B",
        "Параметры защиты от перебора",
        "MEDIUM",
        frozenset({"server"}),
        ("fail2ban",),
        "maxretry ≤ 5, bantime ≥ 600",
        "fail2ban.apply_sshd_profile.v1",
        "Рекомендации ФСТЭК: блокировка после неудачных попыток",
        f2b_03,
    ),
    CheckDef(
        "IDS-01",
        "IDS",
        "Suricata установлена и работает",
        "HIGH",
        frozenset({"ids_sensor"}),
        ("system",),
        "active",
        "pkg.install_security_tool.v1",
        "CIS Controls 13: network monitoring",
        ids_01,
    ),
    CheckDef(
        "IDS-02",
        "IDS",
        "Конфигурация Suricata корректна",
        "HIGH",
        frozenset({"ids_sensor"}),
        ("suricata",),
        "suricata -T OK",
        "suricata.apply_sensor_profile.v1",
        "CIS Controls 13.3",
        ids_02,
    ),
    CheckDef(
        "IDS-03",
        "IDS",
        "Датчик слушает нужный интерфейс и пишет EVE",
        "HIGH",
        frozenset({"ids_sensor"}),
        ("suricata",),
        "интерфейс + EVE",
        "suricata.apply_sensor_profile.v1",
        "CIS Controls 13.3",
        ids_03,
    ),
)
BY_ID = {c.id: c for c in CATALOG}


def evaluate(check: CheckDef, facts: dict, ctx: Ctx) -> Outcome:
    """Apply one check with all status rules (docs/CHECKS_CATALOG.md «Общие правила»)."""
    if not (ctx.roles & check.roles):
        return Outcome(NA, None, check.expected, "Проверка не относится к роли узла.")
    # Agent / transport failure of any required fact -> ERROR
    for key in check.facts:
        f = facts.get(key)
        if f is None:
            return Outcome(UNKNOWN, None, check.expected, f"Нет данных «{key}»: инвентаризация не собирала их.")
        if f.get("state") != "OK":
            return Outcome(
                ERROR,
                f.get("error_code"),
                check.expected,
                f"Не удалось получить «{key}»: {f.get('state')} {f.get('error_code') or ''}".strip(),
            )
    # Unsupported OS: only SYS-01 is evaluated
    system = (facts.get("system") or {}).get("result") or {}
    if check.id != "SYS-01" and system and not system.get("os_supported", False):
        return Outcome(UNKNOWN, None, check.expected, "ОС не поддерживается, результат проверки недостоверен.")
    try:
        return check.evaluate(facts, ctx)
    except MissingFact as exc:
        if exc.key == "ssh_invalid":
            return Outcome(
                UNKNOWN,
                None,
                check.expected,
                "Конфигурация sshd некорректна (см. SSH-07), эффективное значение не определено.",
            )
        return Outcome(UNKNOWN, None, check.expected, f"Нет данных «{exc.key}».")
    except (KeyError, TypeError, ValueError, AttributeError):
        return Outcome(ERROR, None, check.expected, "Неожиданный формат данных агента.")
