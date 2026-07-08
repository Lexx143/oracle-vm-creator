"""Вся работа с Oracle Cloud: ключи, валидация, сеть, образ, цикл охоты за ВМ.

Все функции работают с конкретной сессией (state.Session) — параллельные
пользователи не пересекаются: у каждого свои ключи, стейт и поток охоты.
"""

import configparser
import datetime
import hashlib
import logging
import os
import re
import threading
import time

import oci
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import state

log = logging.getLogger("oracle-vm-creator")

SHAPE = "VM.Standard.A1.Flex"
VCN_NAME = "free-vm-vcn"
SUBNET_NAME = "free-vm-subnet"

# ключ сессии -> поток/стоп-событие
_hunt_threads = {}
_hunt_stops = {}
_setup_threads = {}
_threads_lock = threading.Lock()


# ---------------------------------------------------------------- API-ключ

def ensure_api_keypair(sess):
    """Сгенерировать RSA-2048 ключ для OCI API (один раз), вернуть (public_pem, fingerprint)."""
    st = sess.get()
    if st["api_public_key_pem"] and sess.api_key_file.exists():
        return st["api_public_key_pem"], st["api_fingerprint"]

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.md5(public_der).hexdigest()
    fingerprint = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))

    sess.dir.mkdir(parents=True, exist_ok=True)
    sess.api_key_file.write_bytes(private_pem)
    os.chmod(sess.api_key_file, 0o600)

    def _upd(s):
        s["api_public_key_pem"] = public_pem
        s["api_fingerprint"] = fingerprint
        s["step"] = max(s["step"], 2)
    sess.mutate(_upd)
    return public_pem, fingerprint


def parse_config_snippet(text):
    """Распарсить сниппет конфига, который Oracle показывает после добавления API-ключа."""
    cp = configparser.ConfigParser()
    try:
        cp.read_string(text.strip())
    except configparser.Error:
        raise ValueError(
            "Не удалось разобрать текст. Скопируйте сниппет целиком, начиная со строки [DEFAULT]."
        )
    section = cp["DEFAULT"]
    if not section and cp.sections():
        section = cp[cp.sections()[0]]
    result = {}
    for field in ("user", "fingerprint", "tenancy", "region"):
        value = section.get(field, "").strip()
        if not value:
            raise ValueError(f"В сниппете не хватает поля «{field}». Скопируйте его целиком.")
        result[field] = value
    if not result["user"].startswith("ocid1.user."):
        raise ValueError("Поле user не похоже на OCID пользователя (ocid1.user....).")
    if not result["tenancy"].startswith("ocid1.tenancy."):
        raise ValueError("Поле tenancy не похоже на OCID тенанта (ocid1.tenancy....).")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", result["region"]):
        raise ValueError(f"Регион «{result['region']}» выглядит странно — проверьте сниппет.")
    return result


def _oci_config(sess):
    st = sess.get()
    if not st["oci"]:
        raise RuntimeError("Учётные данные Oracle ещё не настроены (шаг 2).")
    return {
        "user": st["oci"]["user"],
        "tenancy": st["oci"]["tenancy"],
        "region": st["oci"]["region"],
        "fingerprint": st["oci"]["fingerprint"],
        "key_file": str(sess.api_key_file),
    }


def validate_credentials(sess, parsed):
    """Проверить сниппет живым вызовом API. Возвращает список availability domains."""
    st = sess.get()
    if parsed["fingerprint"].lower() != (st["api_fingerprint"] or "").lower():
        raise ValueError(
            "Fingerprint в сниппете не совпадает с ключом, который сгенерировало приложение. "
            "Похоже, в консоль Oracle вставлен другой ключ — добавьте ключ из шага выше."
        )
    cfg = {
        "user": parsed["user"],
        "tenancy": parsed["tenancy"],
        "region": parsed["region"],
        "fingerprint": parsed["fingerprint"],
        "key_file": str(sess.api_key_file),
    }
    identity = oci.identity.IdentityClient(cfg)
    try:
        ads = identity.list_availability_domains(compartment_id=parsed["tenancy"]).data
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            raise ValueError(
                "Oracle не принял ключ (401). Подождите минуту после добавления ключа и "
                "попробуйте ещё раз, либо проверьте, что сниппет скопирован без изменений."
            )
        raise ValueError(f"Ошибка Oracle API: {e.status} {e.code} — {e.message}")
    if not ads:
        raise ValueError("Не удалось получить список availability domains.")

    ad_names = [ad.name for ad in ads]

    def _upd(s):
        s["oci"] = parsed
        s["step"] = max(s["step"], 3)
    sess.mutate(_upd)
    return ad_names


# ---------------------------------------------------------------- Автонастройка

def _setup_step(sess, name, status):
    def _upd(s):
        steps = s["setup"]["steps"]
        for item in steps:
            if item["name"] == name:
                item["status"] = status
                return
        steps.append({"name": name, "status": status})
    sess.mutate(_upd)


def _ensure_network(cfg):
    """Найти или создать VCN + Internet Gateway + маршрут + публичный subnet."""
    vnc = oci.core.VirtualNetworkClient(cfg)
    tenancy = cfg["tenancy"]

    vcns = [v for v in vnc.list_vcns(compartment_id=tenancy).data
            if v.lifecycle_state == "AVAILABLE"]
    vcn = next((v for v in vcns if v.display_name == VCN_NAME), None) or (vcns[0] if vcns else None)

    if vcn is None:
        result = vnc.create_vcn(oci.core.models.CreateVcnDetails(
            compartment_id=tenancy,
            display_name=VCN_NAME,
            cidr_blocks=["10.0.0.0/16"],
            dns_label="freevm",
        ))
        vcn = oci.wait_until(vnc, vnc.get_vcn(result.data.id), "lifecycle_state", "AVAILABLE",
                             max_wait_seconds=120).data

    igws = [g for g in vnc.list_internet_gateways(compartment_id=tenancy, vcn_id=vcn.id).data
            if g.lifecycle_state == "AVAILABLE"]
    if igws:
        igw = igws[0]
    else:
        result = vnc.create_internet_gateway(oci.core.models.CreateInternetGatewayDetails(
            compartment_id=tenancy, vcn_id=vcn.id, display_name="free-vm-igw", is_enabled=True,
        ))
        igw = oci.wait_until(vnc, vnc.get_internet_gateway(result.data.id),
                             "lifecycle_state", "AVAILABLE", max_wait_seconds=120).data

    route_table = vnc.get_route_table(vcn.default_route_table_id).data
    has_default_route = any(r.destination == "0.0.0.0/0" for r in route_table.route_rules)
    if not has_default_route:
        rules = list(route_table.route_rules) + [oci.core.models.RouteRule(
            destination="0.0.0.0/0",
            destination_type="CIDR_BLOCK",
            network_entity_id=igw.id,
        )]
        vnc.update_route_table(route_table.id,
                               oci.core.models.UpdateRouteTableDetails(route_rules=rules))

    subnets = [s for s in vnc.list_subnets(compartment_id=tenancy, vcn_id=vcn.id).data
               if s.lifecycle_state == "AVAILABLE"]
    subnet = next((s for s in subnets if not s.prohibit_public_ip_on_vnic), None)
    if subnet is None:
        result = vnc.create_subnet(oci.core.models.CreateSubnetDetails(
            compartment_id=tenancy,
            vcn_id=vcn.id,
            display_name=SUBNET_NAME,
            cidr_block="10.0.0.0/24",
            dns_label="freevmsub",
            prohibit_public_ip_on_vnic=False,
        ))
        subnet = oci.wait_until(vnc, vnc.get_subnet(result.data.id), "lifecycle_state",
                                "AVAILABLE", max_wait_seconds=120).data
    return vcn, subnet


def _find_image(cfg):
    """Свежий образ Ubuntu (aarch64), совместимый с A1.Flex."""
    compute = oci.core.ComputeClient(cfg)
    images = oci.pagination.list_call_get_all_results(
        compute.list_images,
        compartment_id=cfg["tenancy"],
        operating_system="Canonical Ubuntu",
        shape=SHAPE,
        sort_by="TIMECREATED",
        sort_order="DESC",
    ).data
    if not images:
        raise RuntimeError("Не нашли ни одного образа Ubuntu для VM.Standard.A1.Flex в регионе.")
    full = [i for i in images if "Minimal" not in (i.display_name or "")]
    candidates = full or images
    lts = [i for i in candidates if i.operating_system_version in ("24.04", "22.04")]
    image = (lts or candidates)[0]
    return image


def _ensure_ssh_keypair(sess):
    st = sess.get()
    if st["ssh_public_key"] and sess.ssh_key_file.exists():
        return st["ssh_public_key"]
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    public_str = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode() + " oracle-free-vm"
    sess.dir.mkdir(parents=True, exist_ok=True)
    sess.ssh_key_file.write_bytes(private_bytes)
    os.chmod(sess.ssh_key_file, 0o600)
    sess.ssh_pub_file.write_text(public_str + "\n")
    sess.mutate(lambda s: s.update(ssh_public_key=public_str))
    return public_str


def run_setup_async(sess):
    """Запустить автонастройку в фоне (сеть, образ, SSH-ключ)."""
    with _threads_lock:
        t = _setup_threads.get(sess.key)
        if t and t.is_alive():
            return

    def _upd(s):
        s["setup"] = {"status": "running", "steps": [], "error": None}
    sess.mutate(_upd)

    def worker():
        try:
            cfg = _oci_config(sess)
            identity = oci.identity.IdentityClient(cfg)

            _setup_step(sess, "Список availability domains", "running")
            ads = [ad.name for ad in
                   identity.list_availability_domains(compartment_id=cfg["tenancy"]).data]
            _setup_step(sess, "Список availability domains", "done")

            _setup_step(sess, "Сеть (VCN, интернет-шлюз, подсеть)", "running")
            vcn, subnet = _ensure_network(cfg)
            _setup_step(sess, "Сеть (VCN, интернет-шлюз, подсеть)", "done")

            _setup_step(sess, "Образ Ubuntu ARM", "running")
            image = _find_image(cfg)
            _setup_step(sess, "Образ Ubuntu ARM", "done")

            _setup_step(sess, "SSH-ключ для будущего сервера", "running")
            _ensure_ssh_keypair(sess)
            _setup_step(sess, "SSH-ключ для будущего сервера", "done")

            def _done(s):
                s["network"] = {
                    "vcn_id": vcn.id,
                    "subnet_id": subnet.id,
                    "image_id": image.id,
                    "image_name": image.display_name,
                    "ads": ads,
                }
                s["setup"]["status"] = "done"
                s["step"] = max(s["step"], 4)
            sess.mutate(_done)
        except oci.exceptions.ServiceError as e:
            msg = f"Oracle API: {e.status} {e.code} — {e.message}"
            log.exception("setup failed [%s]", sess.key)
            sess.mutate(lambda s: s["setup"].update(status="error", error=msg))
        except Exception as e:
            log.exception("setup failed [%s]", sess.key)
            sess.mutate(lambda s: s["setup"].update(status="error", error=str(e)))

    with _threads_lock:
        thread = threading.Thread(target=worker, daemon=True)
        _setup_threads[sess.key] = thread
    thread.start()


# ---------------------------------------------------------------- Охота

def _hunt_msg(sess, text):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    sess.mutate(lambda s: s["hunt"].update(last_message=f"[{now}] {text}"))
    log.info("hunt[%s]: %s", sess.key, text)


def start_hunt(sess, display_name, ocpus, memory_gb, boot_gb):
    st = sess.get()
    if not st["network"]:
        raise RuntimeError("Сначала выполните автонастройку (шаг 3).")
    with _threads_lock:
        t = _hunt_threads.get(sess.key)
        if t and t.is_alive():
            return

    def _upd(s):
        s["hunt"].update(
            status="running", attempts=0, error=None, instance_id=None, public_ip=None,
            started_at=time.time(), display_name=display_name,
            ocpus=ocpus, memory_gb=memory_gb, boot_gb=boot_gb,
            last_message="Запускаемся...",
        )
        s["step"] = max(s["step"], 5)
    sess.mutate(_upd)
    _spawn_hunt_thread(sess)


def stop_hunt(sess):
    with _threads_lock:
        stop = _hunt_stops.get(sess.key)
    if stop:
        stop.set()
    sess.mutate(lambda s: s["hunt"].update(
        status="stopped", last_message="Остановлено пользователем."))


def _spawn_hunt_thread(sess):
    with _threads_lock:
        t = _hunt_threads.get(sess.key)
        if t and t.is_alive():
            return
        stop = threading.Event()
        _hunt_stops[sess.key] = stop
        thread = threading.Thread(target=_hunt_loop, args=(sess, stop), daemon=True)
        _hunt_threads[sess.key] = thread
    thread.start()


def resume_all():
    """Поднять охоту всех сессий после рестарта контейнера."""
    for key in state.existing_keys():
        sess = state.for_key(key)
        if sess.get()["hunt"]["status"] in ("running", "provisioning"):
            log.info("resuming hunt for session %s", key)
            _spawn_hunt_thread(sess)


def _hunt_loop(sess, stop):
    try:
        cfg = _oci_config(sess)
        st = sess.get()
        hunt = st["hunt"]
        net = st["network"]
        compute = oci.core.ComputeClient(cfg)

        # если контейнер перезапустился на этапе provisioning — сразу к финализации
        if hunt["status"] == "provisioning" and hunt["instance_id"]:
            _finalize_instance(sess, stop, compute, cfg, hunt["instance_id"])
            return

        details = oci.core.models.LaunchInstanceDetails(
            compartment_id=cfg["tenancy"],
            shape=SHAPE,
            shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=hunt["ocpus"], memory_in_gbs=hunt["memory_gb"],
            ),
            display_name=hunt["display_name"],
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                image_id=net["image_id"],
                # None у сессий, запущенных до появления настройки — диск по умолчанию (~47 ГБ)
                boot_volume_size_in_gbs=hunt.get("boot_gb"),
            ),
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=net["subnet_id"], assign_public_ip=True,
            ),
            metadata={"ssh_authorized_keys": st["ssh_public_key"]},
        )

        ads = net["ads"]
        i = 0
        while not stop.is_set():
            ad = ads[i % len(ads)]
            i += 1
            details.availability_domain = ad
            sess.mutate(lambda s: s["hunt"].update(attempts=s["hunt"]["attempts"] + 1))
            try:
                response = compute.launch_instance(
                    details, retry_strategy=oci.retry.NoneRetryStrategy())
                instance_id = response.data.id
                sess.mutate(lambda s: s["hunt"].update(
                    status="provisioning", instance_id=instance_id))
                _hunt_msg(sess, "🎉 Сервер создаётся! Ждём, пока он запустится...")
                _finalize_instance(sess, stop, compute, cfg, instance_id)
                return
            except oci.exceptions.ServiceError as e:
                if e.status == 500 and "Out of host capacity" in (e.message or ""):
                    _hunt_msg(sess, f"Свободных мощностей нет ({ad.split(':')[-1]}). "
                              "Повтор через 60 секунд — это нормально, ждём.")
                    stop.wait(60)
                elif e.status == 429:
                    _hunt_msg(sess, "Oracle просит не частить (429). Пауза 2 минуты.")
                    stop.wait(120)
                elif e.status == 400 and "LimitExceeded" in (e.code or ""):
                    _fail(sess, "Превышен лимит бесплатного аккаунта. Если раньше создавали серверы — "
                          "удалите их вместе с дисками (Boot Volumes) в консоли Oracle и "
                          "запустите охоту заново. Учтите: Always Free даёт суммарно "
                          "4 OCPU и 24 ГБ RAM на все ARM-серверы.")
                    return
                elif e.status in (401, 404):
                    _fail(sess, f"Oracle не принял учётные данные ({e.status} {e.code}). "
                          "Проверьте, что API-ключ на месте, и начните с шага 2.")
                    return
                else:
                    _hunt_msg(sess, f"Неожиданный ответ API ({e.status} {e.code}). "
                              "Повтор через 60 секунд.")
                    stop.wait(60)
            except Exception as e:
                _hunt_msg(sess, f"Сетевая/локальная ошибка: {e}. Повтор через 60 секунд.")
                stop.wait(60)
    except Exception as e:
        log.exception("hunt loop crashed [%s]", sess.key)
        _fail(sess, f"Внутренняя ошибка: {e}")


def _fail(sess, message):
    sess.mutate(lambda s: s["hunt"].update(status="error", error=message))
    log.error("hunt failed [%s]: %s", sess.key, message)


def _finalize_instance(sess, stop, compute, cfg, instance_id):
    """Дождаться RUNNING и вытащить публичный IP."""
    deadline = time.time() + 15 * 60
    while time.time() < deadline and not stop.is_set():
        instance = compute.get_instance(instance_id).data
        if instance.lifecycle_state == "RUNNING":
            break
        if instance.lifecycle_state in ("TERMINATED", "TERMINATING"):
            _fail(sess, "Сервер неожиданно удалён во время создания. Запустите охоту заново.")
            return
        _hunt_msg(sess, f"Сервер в состоянии {instance.lifecycle_state}, ждём RUNNING...")
        stop.wait(10)

    public_ip = None
    vnc = oci.core.VirtualNetworkClient(cfg)
    for _ in range(30):
        attachments = compute.list_vnic_attachments(
            compartment_id=cfg["tenancy"], instance_id=instance_id).data
        active = [a for a in attachments if a.lifecycle_state == "ATTACHED"]
        if active:
            vnic = vnc.get_vnic(active[0].vnic_id).data
            if vnic.public_ip:
                public_ip = vnic.public_ip
                break
        stop.wait(10)

    def _success(s):
        s["hunt"].update(status="success", public_ip=public_ip,
                         last_message="Сервер запущен!")
        s["step"] = 6
    sess.mutate(_success)
    log.info("SUCCESS [%s]: instance %s ip %s", sess.key, instance_id, public_ip)
