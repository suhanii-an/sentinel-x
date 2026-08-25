"""The synthetic estate the simulators operate against.

Every address here comes from a range IANA reserves for documentation
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or from RFC 1918
private space.  Nothing in this repository can be mistaken for, or routed to,
real infrastructure, and no real organisation's names appear.

Asset criticality is set explicitly rather than defaulted, because it is a real
input to the risk model: the same detection on the domain controller and on a
developer laptop should not produce the same score.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class HostSpec:
    host_id: str
    hostname: str
    ip: str
    os_family: str
    os_version: str
    criticality: int
    environment: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UserSpec:
    user_id: str
    display_name: str
    user_type: str
    department: str
    is_privileged: bool = False
    #: Working hours in UTC, used to generate believable benign history.
    active_hours: tuple[int, int] = (8, 18)
    home_hosts: tuple[str, ...] = ()
    home_ips: tuple[str, ...] = ()


HOSTS: tuple[HostSpec, ...] = (
    HostSpec("LINUX-03", "linux-03.corp.internal", "10.20.4.31", "linux", "Ubuntu 22.04.4 LTS", 4,
             "production", ("web-tier", "internet-facing")),
    HostSpec("LINUX-07", "linux-07.corp.internal", "10.20.4.52", "linux", "Ubuntu 22.04.4 LTS", 4,
             "production", ("app-tier",)),
    HostSpec("LINUX-11", "linux-11.corp.internal", "10.20.4.77", "linux", "Debian 12", 3,
             "production", ("batch",)),
    HostSpec("LINUX-21", "linux-21.corp.internal", "10.20.6.14", "linux", "Ubuntu 22.04.4 LTS", 2,
             "staging", ("staging",)),
    HostSpec("WIN-APP-01", "win-app-01.corp.internal", "10.20.5.21", "windows", "Windows Server 2022", 4,
             "production", ("app-tier",)),
    HostSpec("WIN-DC-01", "win-dc-01.corp.internal", "10.20.5.10", "windows", "Windows Server 2022", 5,
             "production", ("domain-controller", "crown-jewel")),
    HostSpec("LINUX-DB-02", "linux-db-02.corp.internal", "10.20.7.19", "linux", "Rocky Linux 9", 5,
             "production", ("database", "crown-jewel")),
)

USERS: tuple[UserSpec, ...] = (
    UserSpec("admin", "Estate Administrator", "human", "Infrastructure", True, (8, 19),
             ("LINUX-03", "LINUX-07"), ("10.20.4.31", "10.20.9.14")),
    UserSpec("alice", "Alice Nakamura", "human", "Engineering", False, (8, 18),
             ("LINUX-03", "LINUX-21"), ("10.20.9.21",)),
    UserSpec("bob", "Bob Osei", "human", "Engineering", False, (9, 19),
             ("LINUX-07", "LINUX-21"), ("10.20.9.34",)),
    UserSpec("carol", "Carol Whitfield", "human", "Finance", False, (8, 17),
             ("WIN-APP-01",), ("10.20.9.55",)),
    UserSpec("svc-backup", "Backup Service", "service", "Infrastructure", False, (1, 5),
             ("LINUX-11", "LINUX-DB-02"), ("10.20.4.77",)),
    UserSpec("svc-sql", "SQL Service Account", "service", "Infrastructure", False, (0, 23),
             ("WIN-APP-01",), ("10.20.5.21",)),
    UserSpec("dev-admin", "Cloud Platform Admin", "cloud", "Platform", True, (9, 18),
             (), ("198.51.100.10",)),
)

#: Addresses attributed to the simulated adversary (documentation ranges only).
ADVERSARY_IPS: tuple[str, ...] = ("203.0.113.44", "203.0.113.91", "198.51.100.77")
#: Simulated staging infrastructure for tool transfer and egress scenarios.
ADVERSARY_STAGING_IP: str = "198.51.100.200"

CLOUD_ACCOUNT = "123456789012"
CLOUD_REGION = "us-east-1"


@dataclass(slots=True)
class Environment:
    hosts: tuple[HostSpec, ...] = HOSTS
    users: tuple[UserSpec, ...] = USERS
    adversary_ips: tuple[str, ...] = ADVERSARY_IPS
    cloud_account: str = CLOUD_ACCOUNT
    cloud_region: str = CLOUD_REGION
    _host_index: dict[str, HostSpec] = field(default_factory=dict, init=False, repr=False)
    _user_index: dict[str, UserSpec] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self._host_index = {h.host_id: h for h in self.hosts}
        self._user_index = {u.user_id: u for u in self.users}

    def host(self, host_id: str) -> HostSpec:
        return self._host_index[host_id]

    def user(self, user_id: str) -> UserSpec:
        return self._user_index[user_id]

    def host_ip(self, host_id: str) -> str:
        return self._host_index[host_id].ip

    def linux_hosts(self) -> list[HostSpec]:
        return [h for h in self.hosts if h.os_family == "linux"]

    def windows_hosts(self) -> list[HostSpec]:
        return [h for h in self.hosts if h.os_family == "windows"]

    def human_users(self) -> list[UserSpec]:
        return [u for u in self.users if u.user_type == "human"]


DEFAULT_ENVIRONMENT = Environment()
