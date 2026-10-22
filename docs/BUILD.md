# Збірка єдиного runtime

Працювати з кореня `D:\source\MyProjects\durak-mod-switch`.
План і поточний gate: `IMPLEMENTATION_PLAN.md`.

Windows: WSL Ubuntu, Docker та Python з `pyelftools`.
```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_nro.ps1
```
Linux/WSL: Docker та Python з `pyelftools`.
```bash
bash scripts/build_nro.sh
```

Image береться тільки з `toolchain.lock`. Обидва wrapper scripts викликають
`scripts/container_build_verify.sh`: clean build root Makefile → native target
verification → native active loader/linker/audit tests. Потім запускається
`tests.test_step2_loader_harness`. Native executables живуть у `/tmp` контейнера.
Цільові бібліотеки очікуються в локальному `extracted_durak/`.

Результат компіляції: root `durak_nx.nro`, проміжні файли — `build-obj/`.
Windows wrapper також викликає `scripts/package_release.ps1` і створює
повний комплект `build/switch/durak_nx/`. Linux wrapper компілює NRO;
для пакування потрібен PowerShell-скрипт і UnityPy 1.25.3.
Локальні асети й бібліотеки беруться з
`extracted_durak/sdmc/switch/durak_nx/game/`; Python-кеш — `tools/cache/python/`.

Скопіювати `build/switch/` у корінь SD, об'єднавши папки та замінивши файли.
Комплект не містить користувацьких баз або `save`; наявну папку гри не видаляти.
Бібліотеки комплекту розташовані у `game/lib/`, асети — в обох підтримуваних
шляхах `assets/` і `game/assets/`, щоб оновити також попередні інсталяції.
`build/manifest.json` фіксує commit та SHA256 кожного файла.
Запуск: title override, `sdmc:/switch/durak_nx/durak_nx.nro`;
лог: `sdmc:/switch/durak_nx/durak_nx.log`.
Роботу гри та звуку підтверджено користувачем на Switch; журнали збірки
підтверджують лише збірку та host-перевірки.

## Preparing a fresh checkout

Run from the root of your checkout. Game packages are not included in Git.
Provide your own exact supported Durak 25.0 package (versionCode 250).
The extractor verifies the archive, library and metadata hashes:

```powershell
python -m pip install pyelftools UnityPy==1.25.3
python tools/extract_game.py --apks Durak_25.0.apks --out extracted_durak
```

The local package and extracted files are ignored by Git. Locally generated
SD packages include your game data and should not be redistributed.
