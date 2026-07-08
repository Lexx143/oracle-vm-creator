"""Файловый стейт пользовательских сессий: data/sessions/<key>/session.json.

Каждому токену доступа соответствует своя изолированная сессия
(свой API-ключ OCI, свой SSH-ключ, своя охота).
"""

import copy
import hashlib
import json
import os
import threading
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
SESSIONS_DIR = DATA_DIR / "sessions"

DEFAULT_STATE = {
    "step": 1,
    # шаг 2: сгенерированный API-ключ и распарсенный сниппет из консоли Oracle
    "api_public_key_pem": None,
    "api_fingerprint": None,
    "oci": None,  # {user, tenancy, region, fingerprint}
    # шаг 3: автонастройка окружения
    "setup": {"status": "idle", "steps": [], "error": None},
    "network": None,  # {vcn_id, subnet_id, image_id, image_name, ads: [...]}
    "ssh_public_key": None,
    # шаги 4-6: охота и результат
    "hunt": {
        "status": "idle",  # idle | running | provisioning | success | error | stopped
        "attempts": 0,
        "started_at": None,
        "last_message": None,
        "error": None,
        "display_name": None,
        "ocpus": None,
        "memory_gb": None,
        "instance_id": None,
        "public_ip": None,
    },
}

_registry = {}
_registry_lock = threading.Lock()


def token_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:16]


class Session:
    def __init__(self, key: str):
        self.key = key
        self.dir = SESSIONS_DIR / key
        self.state_file = self.dir / "session.json"
        self.api_key_file = self.dir / "oci_api_key.pem"
        self.ssh_key_file = self.dir / "vm_ssh_key"
        self.ssh_pub_file = self.dir / "vm_ssh_key.pub"
        self._lock = threading.RLock()
        self._state = None

    def _load_from_disk(self):
        if self.state_file.exists():
            try:
                return json.loads(self.state_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return copy.deepcopy(DEFAULT_STATE)

    def get(self):
        with self._lock:
            if self._state is None:
                self._state = self._load_from_disk()
            return copy.deepcopy(self._state)

    def mutate(self, fn):
        """Атомарно изменить стейт: fn(state) правит dict на месте."""
        with self._lock:
            if self._state is None:
                self._state = self._load_from_disk()
            fn(self._state)
            self.dir.mkdir(parents=True, exist_ok=True)
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._state, ensure_ascii=False, indent=2))
            tmp.replace(self.state_file)
            return copy.deepcopy(self._state)

    def wipe(self):
        """Стереть все данные пользователя: ключи и стейт."""
        with self._lock:
            for f in (self.api_key_file, self.ssh_key_file, self.ssh_pub_file,
                      self.state_file, self.state_file.with_suffix(".tmp")):
                try:
                    f.unlink(missing_ok=True)
                except OSError:
                    pass
            self._state = copy.deepcopy(DEFAULT_STATE)


def for_key(key: str) -> Session:
    with _registry_lock:
        if key not in _registry:
            _registry[key] = Session(key)
        return _registry[key]


def for_token(token: str) -> Session:
    return for_key(token_key(token))


def existing_keys():
    """Ключи сессий, у которых уже есть данные на диске."""
    if not SESSIONS_DIR.exists():
        return []
    return [d.name for d in SESSIONS_DIR.iterdir()
            if d.is_dir() and (d / "session.json").exists()]


def migrate_legacy(token: str):
    """Переложить данные старой однопользовательской раскладки (data/*)
    в сессию первого токена. Безопасно вызывать многократно."""
    legacy_state = DATA_DIR / "session.json"
    if not legacy_state.exists():
        return
    sess = for_token(token)
    sess.dir.mkdir(parents=True, exist_ok=True)
    for name in ("session.json", "oci_api_key.pem", "vm_ssh_key", "vm_ssh_key.pub"):
        src = DATA_DIR / name
        if src.exists():
            src.rename(sess.dir / name)
