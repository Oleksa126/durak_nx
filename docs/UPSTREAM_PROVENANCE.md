> Історичний технічний звіт, не план робіт. Поточні кроки та стан — лише `IMPLEMENTATION_PLAN.md` у корені. Твердження PASS автора звіту не замінює review або hardware test.

# Upstream Provenance & Donor Inventory — Durak NX Feasibility Spike

Цей документ фіксує походження, зафіксовані знімки (pinned snapshots), умови ліцензування, перелік імпортованих файлів та межі ізоляції зовнішніх кодових баз відповідно до вимог Кроку 1 (`IMPLEMENTATION_PLAN.md`).

---

## 1. Зафіксовані зовнішні репозиторії (Pinned Snapshots)

| Компонент / Репозиторій | Pinned Commit | Ліцензія | Роль у проєкті | Розташування у корені |
| :--- | :--- | :--- | :--- | :--- |
| [NaGaa95/laytonbmr_nx](https://github.com/NaGaa95/laytonbmr_nx) | `5763d239f03e57447832bcb1450a3ac1099846c7` (Release 1.0.1, 2026-07-15) | MIT License | **Основний runtime donor:** цілісна система завантаження ELF (`so_util`), емуляція Bionic libc/pthreads (`libc_shim`, `imports`), fake JavaVM/JNI (`jni_fake`, `unity_jni`), ANativeWindow/EGL glue (`android_native_unity`) | `third_party/laytonbmr_nx/` |
| [ChanseyIsTheBest/cloverpit_nx](https://github.com/ChanseyIsTheBest/cloverpit_nx) | `1785b26bc28680063dbcbb15199d090c276b89ef` (2026) | MIT License | **Додатковий архітектурний donor:** Unity 6000.2.6f2 reference techniques, multi-instruction fingerprint matching methodology, crash handler (`nx_crash_handler.c`), TimeManager update hook (`cloverpit_time.c`) | `third_party/cloverpit_nx/` |
| **Базова контрольна точка Durak NX** | `9db8020a65e354827d82de3a492bd674c43bdfa9` (`9db8020`) | Proprietary / Isolated | Контрольна точка E06a: M0/M1 SHA-256 та Build-ID verification, діагностичний W^X CodeMemory state machine, Wave 1–2 bionic shims, fail-closed target evidence | `source/`, `include/` |

---

## 2. Перелік імпортованих файлів донорів

### 2.1. `laytonbmr_nx` (`third_party/laytonbmr_nx/`)
Всі файли імпортовано без історії `.git` та без ігрових ресурсів:
- `LICENSE` — оригінальний текст ліцензії MIT (Copyright (c) 2021 Andy Nguyen, fgsfds, NaGaa95).
- `Makefile` — збірка під Nintendo Switch (`switch-rules`, `libnx`, `mesa`, `SDL2`).
- `README.md` — оригінальний опис порту.
- `source/so_util.c`, `source/so_util.h` — ELF64/AArch64 dynamic loader, mapping CodeMemory, relocation resolver.
- `source/imports.c`, `source/imports.h`, `source/imports_audio.inc` — таблиця зовнішніх символів Android Bionic libc/libm/EGL.
- `source/libc_shim.c`, `source/libc_shim.h` — реалізація Bionic pthread, FILE (`__sF`), errno, locale, mmap/munmap, dlopen/dlsym.
- `source/jni_fake.c`, `source/jni_fake.h`, `source/jni_trace.h`, `source/jni_unimpl.h` — емулятор JNIEnv та JavaVM.
- `source/android_native_unity.c`, `source/android_native_unity.h`, `source/android_native.h` — ANativeWindow, android_native_app_glue.
- `source/unity_jni.c`, `source/unity_jni.h`, `source/unity_jni_surface.h` — Unity-специфічний JNI dispatch, Surface, Activity.
- `source/unity_glue.c`, `source/unity_imports.c`, `source/unity_imports.h`, `source/unity_entrypoints.h` — запуск Unity lifecycle.
- `source/unity_input_hook.c`, `source/unity_input_hook.h` — touch/gamepad input hook.
- `source/diag.c`, `source/diag.h` — діагностика очікування потоків, crash dump.
- `source/fakefd.c` — емуляція дескрипторів файлів procfs/pipe.
- `source/opensles.c`, `source/opensles.h` — OpenSL ES аудіо мікшер поверх SDL2/audout.
- `source/firebase_stub.c`, `source/ndk_stubs.c`, `source/cr3_stubs.c` — допоміжні заглушки SDK.
- `source/region_patch.h` — патчі конфігурації аллокатора 256MB->64MB для Unity 6000.0.58f2.
- `source/main.c` — референсний життєвий цикл запуску.

### 2.2. `cloverpit_nx` (`third_party/cloverpit_nx/`)
Всі файли імпортовано без історії `.git` та без ігрових ресурсів:
- `LICENSE` — оригінальний текст ліцензії MIT (Copyright (c) 2026 ChanseyIsTheBest).
- `source/cloverpit_offsets.h` — опис структурних зміщень та fingerprint matching для Unity 6000.2.6f2.
- `source/cloverpit_patches.c`, `source/cloverpit_region_patch.h` — техніка патчингу пам'яті.
- `source/cloverpit_time.c`, `source/cloverpit_time.h` — хук монотонного годинника `TimeManager::Update(double)`.
- `source/nx_crash_handler.c` — обробник виключень Horizon OS з дампом регістрів і стек-трейсом.
- `source/cloverpit_touch.c`, `source/cloverpit_touchhook.c` — обробка touch введення.

---

## 3. Ліцензійна чистота та правила розділення

1. **Жодного чужого коду гри (Zero Game Code):**
   - Усі імпортовані файли містять виключно код wrapper/compatibility layer та відкриті референсні заголовки.
   - Ігрові дані гри Layton Brothers Mystery Room або Cloverpit відсутні.
   - Дані гри «Дурак» (`Durak_25.0.apks`, розпаковані `.so`, `global-metadata.dat`) знаходяться виключно в `extracted_durak/`, додані до `.gitignore` і ніколи не потрапляють у git-репозиторій.

2. **Збереження ліцензій та авторських прав:**
   - Оригінальні файли `LICENSE` збережено в `third_party/laytonbmr_nx/LICENSE` та `third_party/cloverpit_nx/LICENSE`.
   - Авторські заголовки у файлах вихідного коду (Andy Nguyen, fgsfds, NaGaa95, ChanseyIsTheBest) не модифікуються.

3. **Єдина активна реалізація:**
   - Адаптований runtime знаходиться у root `source/` і `include/`.
   - `third_party/` зберігає незмінені донорські знімки й ліцензії.
   - Попередній backend збережено поза репозиторієм; поточний план — `IMPLEMENTATION_PLAN.md`.

---

## 4. Верифікація середовища збірки (Toolchain Overlay)

Згідно з `toolchain.lock`:
- Docker-образ: `devkitpro/devkita64@sha256:1fc388c3a0d34bd2045a6dadcb1020e069d5f876a187fd705de14b4440c00282`
- Цільовий компілятор: `aarch64-none-elf-gcc 15.2.0`
- Встановлені системні бібліотеки перевірено безпосередньо в контейнері:
  - `switch-mesa 20.1.0-5` (GLES2, GLES3, EGL, glapi) — **наявна**;
  - `switch-libdrm_nouveau 1.0.1-2` — **наявна**;
  - `switch-sdl2 2.28.5-4` — **наявна**;
  - `switch-zlib 1.3.1-1` — **наявна**;
  - `libnx 4.12.0-1` — **наявна**.
- Висновок: Pinned toolchain повністю містить усі бібліотеки, необхідні для збірки цілісного runtime-шару Layton. Жодних мережевих завантажень чи модифікацій root `toolchain.lock` не потрібно.
