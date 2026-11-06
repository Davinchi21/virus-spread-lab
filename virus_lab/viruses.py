"""Модели вредоносных программ (только параметры, никакого вредоносного кода)."""
from __future__ import annotations

import copy

WINDOWS = ["win7", "win10", "win11", "winsrv"]
ALL_OS = WINDOWS + ["linux"]

VIRUSES = {
    "worm_smb": {
        "name": "Сетевой червь (эксплойт SMB)",
        "vector": "Эксплуатирует уязвимость сетевой службы Windows, участие пользователя не нужно",
        "analogs": "Conficker (2008), WannaCry (2017), NotPetya (2017)",
        "targets": WINDOWS,
        "needs_vuln": True,
        "user_action": False,
        "beta": 0.6,
        "contacts": 3,
        "av_block": 0.3,
        "av_detect": 0.15,
        "firewall_bypass": 0.0,
        "sigma": 0.5,
        "p2p_contacts": 0, "p2p_beta": 0.0, "external_rate": 0.0,
    },
    "email_worm": {
        "name": "Почтовый червь (вредоносное вложение)",
        "vector": "Рассылает себя по адресной книге; заражает, если пользователь откроет вложение",
        "analogs": "ILOVEYOU (2000), Mydoom (2004), Emotet (2014–2021)",
        "targets": WINDOWS,
        "needs_vuln": False,
        "user_action": True,
        "beta": 0.5,
        "contacts": 2,
        "av_block": 0.6,
        "av_detect": 0.2,
        "firewall_bypass": 1.0,
        "sigma": 0.3,
        "p2p_contacts": 0, "p2p_beta": 0.0, "external_rate": 0.0,
    },
    "usb_virus": {
        "name": "Вирус на флешках и в общих папках",
        "vector": "Переносится съёмными носителями и сетевыми папками: медленно, но в обход МСЭ",
        "analogs": "Agent.btz (2008), Stuxnet (USB-вектор, 2010)",
        "targets": WINDOWS,
        "needs_vuln": False,
        "user_action": True,
        "beta": 0.35,
        "contacts": 1,
        "av_block": 0.5,
        "av_detect": 0.08,
        "firewall_bypass": 1.0,
        "sigma": 0.2,
        "p2p_contacts": 0, "p2p_beta": 0.0, "external_rate": 0.0,
    },
    "apt_stealth": {
        "name": "Скрытая целевая атака (APT)",
        "vector": "Медленное горизонтальное перемещение по украденным учётным данным, почти не обнаруживается",
        "analogs": "целевые APT-кампании против организаций",
        "targets": ALL_OS,
        "needs_vuln": False,
        "user_action": False,
        "beta": 0.2,
        "contacts": 1,
        "av_block": 0.05,
        "av_detect": 0.01,
        "firewall_bypass": 0.3,
        "sigma": 0.1,
        "p2p_contacts": 0, "p2p_beta": 0.0, "external_rate": 0.0,
    },
    "linux_worm": {
        "name": "Червь для Linux (подбор паролей SSH)",
        "vector": "Перебирает слабые пароли SSH; «патч» здесь означает стойкий пароль или вход по ключу",
        "analogs": "червь Морриса (1988), Mirai (2016)",
        "targets": ["linux"],
        "needs_vuln": True,
        "user_action": False,
        "beta": 0.5,
        "contacts": 4,
        "av_block": 0.0,
        "av_detect": 0.03,
        "firewall_bypass": 0.0,
        "sigma": 0.5,
        "p2p_contacts": 0, "p2p_beta": 0.0, "external_rate": 0.0,
    },
    "torrent_trojan": {
        "name": "Троян в торрент-раздаче",
        "vector": "Прячется во «взломанных» программах и играх. Заражает того, кто скачал и запустил файл, "
                  "и раздаётся дальше другим торрент-пользователям — даже ПК, не подключённым к ЛВС",
        "analogs": "P2P-черви для Kazaa (2002–2004), скрытые майнеры в пиратских раздачах игр",
        "targets": WINDOWS,
        "needs_vuln": False,
        "user_action": True,
        "beta": 0.0,
        "contacts": 0,
        "av_block": 0.5,
        "av_detect": 0.1,
        "firewall_bypass": 1.0,
        "sigma": 0.3,
        "p2p_contacts": 2,
        "p2p_beta": 0.6,
        "external_rate": 0.01,
    },
    "torrent_worm": {
        "name": "Торрент-червь (приходит из торрента, ползёт по ЛВС)",
        "vector": "Попадает в сеть через заражённую раздачу, а затем распространяется по локальной сети "
                  "через уязвимость SMB, как сетевой червь",
        "analogs": "майнеры и шифровальщики в пиратском ПО с модулем распространения по ЛВС",
        "targets": WINDOWS,
        "needs_vuln": True,
        "user_action": False,
        "beta": 0.5,
        "contacts": 3,
        "av_block": 0.3,
        "av_detect": 0.12,
        "firewall_bypass": 0.0,
        "sigma": 0.5,
        "p2p_contacts": 1,
        "p2p_beta": 0.5,
        "external_rate": 0.005,
    },
}

VIRUS_PARAMS = {
    "beta": "ЛВС: вероятность заражения при одном контакте с соседним узлом",
    "contacts": "ЛВС: число попыток заразить соседей по сети за шаг (0 — по ЛВС не распространяется)",
    "p2p_contacts": "торрент: число раздач заражённого файла другим торрент-пользователям за шаг",
    "p2p_beta": "торрент: вероятность, что получатель запустит файл (патч не защищает)",
    "external_rate": "торрент: вероятность за шаг, что торрент-пользователь скачает заражённый файл из интернета",
    "av_block": "доля атак, которые блокирует антивирус узла-цели",
    "av_detect": "вероятность за шаг, что антивирус найдёт и удалит вирус на заражённом узле",
    "firewall_bypass": "ЛВС: вероятность пройти межсегментный МСЭ при включённой сегментации",
    "sigma": "вероятность за шаг перейти из инкубации в активную фазу (только SEIR)",
    "needs_vuln": "ЛВС: заражает только узлы без патча",
    "user_action": "ЛВС: нужно действие пользователя (учитывается осведомлённость персонала)",
    "targets": "список заражаемых ОС",
}


def get_virus(spec) -> dict:
    """Пресет по имени либо словарь (можно указать "base": "<пресет>" и переопределить поля)."""
    if isinstance(spec, str):
        if spec not in VIRUSES:
            raise ValueError(f"Неизвестный вирус: {spec}. Доступны: {', '.join(VIRUSES)}")
        out = copy.deepcopy(VIRUSES[spec])
        out["id"] = spec
        return out
    if isinstance(spec, dict):
        base_id = spec.get("base") or spec.get("id")
        out = get_virus(base_id) if base_id in VIRUSES else get_virus("worm_smb") | {"id": "custom", "name": "Пользовательский вирус"}
        out.update(copy.deepcopy(spec))
        out.pop("base", None)
        return out
    raise TypeError("Вирус задаётся именем пресета или словарём параметров")
