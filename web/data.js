// Файл сгенерирован командой `python -m virus_lab build-web`. Не редактируйте вручную.
window.VIRUS_LAB_DATA = {
 "viruses": {
  "worm_smb": {
   "name": "Сетевой червь (эксплойт SMB)",
   "vector": "Эксплуатирует уязвимость сетевой службы Windows, участие пользователя не нужно",
   "analogs": "Conficker (2008), WannaCry (2017), NotPetya (2017)",
   "targets": [
    "win7",
    "win10",
    "win11",
    "winsrv"
   ],
   "needs_vuln": true,
   "user_action": false,
   "beta": 0.6,
   "contacts": 3,
   "av_block": 0.3,
   "av_detect": 0.15,
   "firewall_bypass": 0.0,
   "sigma": 0.5,
   "p2p_contacts": 0,
   "p2p_beta": 0.0,
   "external_rate": 0.0
  },
  "email_worm": {
   "name": "Почтовый червь (вредоносное вложение)",
   "vector": "Рассылает себя по адресной книге; заражает, если пользователь откроет вложение",
   "analogs": "ILOVEYOU (2000), Mydoom (2004), Emotet (2014–2021)",
   "targets": [
    "win7",
    "win10",
    "win11",
    "winsrv"
   ],
   "needs_vuln": false,
   "user_action": true,
   "beta": 0.5,
   "contacts": 2,
   "av_block": 0.6,
   "av_detect": 0.2,
   "firewall_bypass": 1.0,
   "sigma": 0.3,
   "p2p_contacts": 0,
   "p2p_beta": 0.0,
   "external_rate": 0.0
  },
  "usb_virus": {
   "name": "Вирус на флешках и в общих папках",
   "vector": "Переносится съёмными носителями и сетевыми папками: медленно, но в обход МСЭ",
   "analogs": "Agent.btz (2008), Stuxnet (USB-вектор, 2010)",
   "targets": [
    "win7",
    "win10",
    "win11",
    "winsrv"
   ],
   "needs_vuln": false,
   "user_action": true,
   "beta": 0.35,
   "contacts": 1,
   "av_block": 0.5,
   "av_detect": 0.08,
   "firewall_bypass": 1.0,
   "sigma": 0.2,
   "p2p_contacts": 0,
   "p2p_beta": 0.0,
   "external_rate": 0.0
  },
  "apt_stealth": {
   "name": "Скрытая целевая атака (APT)",
   "vector": "Медленное горизонтальное перемещение по украденным учётным данным, почти не обнаруживается",
   "analogs": "целевые APT-кампании против организаций",
   "targets": [
    "win7",
    "win10",
    "win11",
    "winsrv",
    "linux"
   ],
   "needs_vuln": false,
   "user_action": false,
   "beta": 0.2,
   "contacts": 1,
   "av_block": 0.05,
   "av_detect": 0.01,
   "firewall_bypass": 0.3,
   "sigma": 0.1,
   "p2p_contacts": 0,
   "p2p_beta": 0.0,
   "external_rate": 0.0
  },
  "linux_worm": {
   "name": "Червь для Linux (подбор паролей SSH)",
   "vector": "Перебирает слабые пароли SSH; «патч» здесь означает стойкий пароль или вход по ключу",
   "analogs": "червь Морриса (1988), Mirai (2016)",
   "targets": [
    "linux"
   ],
   "needs_vuln": true,
   "user_action": false,
   "beta": 0.5,
   "contacts": 4,
   "av_block": 0.0,
   "av_detect": 0.03,
   "firewall_bypass": 0.0,
   "sigma": 0.5,
   "p2p_contacts": 0,
   "p2p_beta": 0.0,
   "external_rate": 0.0
  },
  "torrent_trojan": {
   "name": "Троян в торрент-раздаче",
   "vector": "Прячется во «взломанных» программах и играх. Заражает того, кто скачал и запустил файл, и раздаётся дальше другим торрент-пользователям — даже ПК, не подключённым к ЛВС",
   "analogs": "P2P-черви для Kazaa (2002–2004), скрытые майнеры в пиратских раздачах игр",
   "targets": [
    "win7",
    "win10",
    "win11",
    "winsrv"
   ],
   "needs_vuln": false,
   "user_action": true,
   "beta": 0.0,
   "contacts": 0,
   "av_block": 0.5,
   "av_detect": 0.1,
   "firewall_bypass": 1.0,
   "sigma": 0.3,
   "p2p_contacts": 2,
   "p2p_beta": 0.6,
   "external_rate": 0.01
  },
  "torrent_worm": {
   "name": "Торрент-червь (приходит из торрента, ползёт по ЛВС)",
   "vector": "Попадает в сеть через заражённую раздачу, а затем распространяется по локальной сети через уязвимость SMB, как сетевой червь",
   "analogs": "майнеры и шифровальщики в пиратском ПО с модулем распространения по ЛВС",
   "targets": [
    "win7",
    "win10",
    "win11",
    "winsrv"
   ],
   "needs_vuln": true,
   "user_action": false,
   "beta": 0.5,
   "contacts": 3,
   "av_block": 0.3,
   "av_detect": 0.12,
   "firewall_bypass": 0.0,
   "sigma": 0.5,
   "p2p_contacts": 1,
   "p2p_beta": 0.5,
   "external_rate": 0.005
  }
 },
 "virusParams": {
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
  "targets": "список заражаемых ОС"
 },
 "models": {
  "SI": "SI — заражённый узел остаётся заражённым навсегда",
  "SIS": "SIS — вылеченный узел снова может заразиться",
  "SIR": "SIR — вылеченный узел приобретает иммунитет",
  "SEIR": "SEIR — SIR со скрытым (инкубационным) периодом"
 },
 "topologies": {
  "corporate": "Корпоративная сеть: отделы-подсети, общие серверы, межотдельные связи",
  "flat": "Плоская сеть: все ПК в одном сегменте (полный граф)",
  "star": "Звезда: все ПК связаны только с центральным сервером",
  "ring": "Кольцевая решётка",
  "grid": "Решётка (квадратная)",
  "random": "Случайный граф Эрдёша–Реньи",
  "small_world": "«Малый мир» Уоттса–Строгаца",
  "scale_free": "Безмасштабная сеть Барабаши–Альберт"
 },
 "osNames": {
  "win7": "Windows 7 (снята с поддержки, патчи не выходят)",
  "win10": "Windows 10",
  "win11": "Windows 11",
  "winsrv": "Windows Server",
  "linux": "Linux"
 },
 "subnetProfiles": [
  {
   "name": "Администрация",
   "prefix": "adm",
   "os": [
    [
     "win11",
     0.7
    ],
    [
     "win10",
     0.3
    ]
   ]
  },
  {
   "name": "Бухгалтерия",
   "prefix": "buh",
   "os": [
    [
     "win10",
     0.8
    ],
    [
     "win7",
     0.2
    ]
   ]
  },
  {
   "name": "Разработка",
   "prefix": "dev",
   "os": [
    [
     "linux",
     0.5
    ],
    [
     "win11",
     0.3
    ],
    [
     "win10",
     0.2
    ]
   ]
  },
  {
   "name": "Производство",
   "prefix": "prod",
   "os": [
    [
     "win7",
     0.6
    ],
    [
     "win10",
     0.4
    ]
   ]
  }
 ],
 "serverSubnetProfile": {
  "name": "ИТ и серверы",
  "prefix": "it",
  "os": [
   [
    "win11",
    0.5
   ],
   [
    "linux",
    0.5
   ]
  ]
 },
 "serverRoles": [
  {
   "role": "dc",
   "name": "Контроллер домена",
   "os": "winsrv"
  },
  {
   "role": "fs",
   "name": "Файловый сервер",
   "os": "winsrv"
  },
  {
   "role": "mail",
   "name": "Почтовый сервер",
   "os": "linux"
  },
  {
   "role": "web",
   "name": "Веб-сервер",
   "os": "linux"
  },
  {
   "role": "db",
   "name": "Сервер БД",
   "os": "linux"
  }
 ],
 "coreServers": 3,
 "defaultNetwork": {
  "topology": "corporate",
  "hosts": 100,
  "subnets": 5,
  "patch_coverage": 0.5,
  "av_coverage": 0.6,
  "cross_links": 15,
  "avg_degree": 6,
  "rewire_p": 0.1,
  "ba_m": 3,
  "p2p_share": 0.15,
  "offline_share": 0.0
 },
 "defaultParams": {
  "gamma": 0.02,
  "user_awareness": 0.3,
  "segmentation": false,
  "p2p_blocked": false,
  "initial_infected": 1,
  "patient_zero": -1,
  "detect_threshold": 0.1,
  "response_delay": 10,
  "response_patch_rate": 0.0,
  "response_segmentation": false,
  "response_p2p_block": false,
  "response_quarantine": 0.0,
  "max_steps": 300
 },
 "scenarios": [
  {
   "name": "01. Сетевой червь: базовый сценарий",
   "description": "Червь эксплуатирует уязвимость SMB. Половина ПК с патчем, 60 % с антивирусом, сегментации нет, реагирования нет.",
   "seed": 42,
   "model": "SIR",
   "virus": "worm_smb",
   "network": {
    "topology": "corporate",
    "patch_coverage": 0.5,
    "av_coverage": 0.6
   },
   "params": {
    "gamma": 0.02,
    "initial_infected": 1,
    "patient_zero": -1,
    "segmentation": false,
    "max_steps": 300
   },
   "file": "01_worm_baseline.json"
  },
  {
   "name": "02. Почтовый червь (модель SEIR)",
   "description": "Червь во вложении: патчи не помогают, решают антивирус и осведомлённость пользователей. Инкубация — время, пока письмо не открыто.",
   "seed": 42,
   "model": "SEIR",
   "virus": "email_worm",
   "network": {
    "topology": "corporate",
    "patch_coverage": 0.5,
    "av_coverage": 0.6
   },
   "params": {
    "gamma": 0.02,
    "user_awareness": 0.3,
    "initial_infected": 1,
    "max_steps": 300
   },
   "file": "02_email_worm.json"
  },
  {
   "name": "03. Вирус на флешках (модель SIS)",
   "description": "Вылеченный ПК снова заражается с той же флешки: проверяем, может ли инфекция стать эндемичной.",
   "seed": 42,
   "model": "SIS",
   "virus": "usb_virus",
   "network": {
    "topology": "corporate",
    "patch_coverage": 0.5,
    "av_coverage": 0.4
   },
   "params": {
    "gamma": 0.02,
    "user_awareness": 0.2,
    "initial_infected": 2,
    "max_steps": 400
   },
   "file": "03_usb_virus.json"
  },
  {
   "name": "04. Скрытая целевая атака (APT)",
   "description": "Медленное горизонтальное перемещение по украденным учётным данным. Поражает все ОС, антивирус почти бесполезен.",
   "seed": 42,
   "model": "SEIR",
   "virus": "apt_stealth",
   "network": {
    "topology": "corporate",
    "patch_coverage": 0.5,
    "av_coverage": 0.6
   },
   "params": {
    "gamma": 0.01,
    "initial_infected": 1,
    "patient_zero": "buh-pc03",
    "segmentation": true,
    "max_steps": 500
   },
   "file": "04_apt_stealth.json"
  },
  {
   "name": "05. Червь для Linux (подбор паролей SSH)",
   "description": "Заражает только Linux-узлы со слабым паролем. Почтовый сервер на Linux связан со всеми ПК и работает как мост между отделами.",
   "seed": 42,
   "model": "SIR",
   "virus": "linux_worm",
   "network": {
    "topology": "corporate",
    "patch_coverage": 0.3,
    "av_coverage": 0.6
   },
   "params": {
    "gamma": 0.02,
    "initial_infected": 1,
    "max_steps": 300
   },
   "file": "05_linux_worm.json"
  },
  {
   "name": "06. Сетевой червь и реагирование на инцидент",
   "description": "Инцидент замечают, когда заражено 5 % сети. Через response_delay шагов администраторы ставят патчи, включают межсегментный МСЭ и изолируют заражённые ПК.",
   "seed": 42,
   "model": "SIR",
   "virus": "worm_smb",
   "network": {
    "topology": "corporate",
    "patch_coverage": 0.3,
    "av_coverage": 0.6
   },
   "params": {
    "gamma": 0.02,
    "initial_infected": 1,
    "max_steps": 300,
    "detect_threshold": 0.05,
    "response_delay": 5,
    "response_patch_rate": 0.15,
    "response_segmentation": true,
    "response_quarantine": 0.2
   },
   "file": "06_incident_response.json"
  },
  {
   "name": "07. Сетевой червь в сегментированной сети",
   "description": "Межсегментный МСЭ включён с самого начала и блокирует SMB между отделами. Червь может пройти только через общие серверы, если они уязвимы.",
   "seed": 42,
   "model": "SIR",
   "virus": "worm_smb",
   "network": {
    "topology": "corporate",
    "patch_coverage": 0.3,
    "av_coverage": 0.6
   },
   "params": {
    "gamma": 0.02,
    "initial_infected": 1,
    "segmentation": true,
    "max_steps": 300
   },
   "file": "07_segmented_network.json"
  },
  {
   "name": "08. Троян в торрент-раздаче",
   "description": "Вирус прячется во «взломанном» ПО. Распространяется только между торрент-пользователями (в т.ч. домашними ПК вне ЛВС) и подкачивается из интернета. Патчи и МСЭ бесполезны — решают осведомлённость и антивирус.",
   "seed": 3,
   "model": "SIR",
   "virus": "torrent_trojan",
   "network": {
    "topology": "corporate",
    "p2p_share": 0.35,
    "offline_share": 0.15,
    "av_coverage": 0.6
   },
   "params": {
    "gamma": 0.02,
    "user_awareness": 0.3,
    "initial_infected": 1,
    "max_steps": 400
   },
   "file": "08_torrent_trojan.json"
  },
  {
   "name": "09. Торрент-червь: из P2P в локальную сеть",
   "description": "Вирус попадает в сеть через торрент одного сотрудника, а затем ползёт по ЛВС через уязвимость SMB. Комбинированная угроза: торрент-канал + сетевой червь.",
   "seed": 5,
   "model": "SIR",
   "virus": "torrent_worm",
   "network": {
    "topology": "corporate",
    "p2p_share": 0.2,
    "offline_share": 0.1,
    "patch_coverage": 0.4,
    "av_coverage": 0.6
   },
   "params": {
    "gamma": 0.02,
    "user_awareness": 0.3,
    "initial_infected": 0,
    "patient_zero": -1,
    "max_steps": 400
   },
   "file": "09_torrent_worm.json"
  },
  {
   "name": "10. Малый офис (20 ПК, плоская сеть)",
   "description": "Небольшая сеть без сегментации: 20 ПК в одном коммутаторе, патчей мало. Удобно наблюдать каждый ПК и ручные действия.",
   "seed": 42,
   "model": "SIR",
   "virus": "worm_smb",
   "network": {
    "topology": "flat",
    "hosts": 20,
    "subnets": 1,
    "patch_coverage": 0.3,
    "av_coverage": 0.5
   },
   "params": {
    "gamma": 0.03,
    "initial_infected": 1,
    "max_steps": 200
   },
   "file": "10_small_office.json"
  },
  {
   "name": "11. Крупное предприятие (300 ПК, 10 отделов)",
   "description": "Масштабная корпоративная сеть: проверка, как размер и сегментация влияют на скорость эпидемии. Включено реагирование на инцидент.",
   "seed": 7,
   "model": "SIR",
   "virus": "worm_smb",
   "network": {
    "topology": "corporate",
    "hosts": 300,
    "subnets": 10,
    "patch_coverage": 0.4,
    "av_coverage": 0.6,
    "cross_links": 40
   },
   "params": {
    "gamma": 0.02,
    "initial_infected": 1,
    "detect_threshold": 0.05,
    "response_delay": 8,
    "response_patch_rate": 0.1,
    "response_segmentation": true,
    "response_quarantine": 0.15,
    "max_steps": 400
   },
   "file": "11_large_enterprise.json"
  }
 ]
};
