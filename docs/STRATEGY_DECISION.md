> Історичний технічний звіт, не план робіт. Поточні кроки та стан — лише `IMPLEMENTATION_PLAN.md` у корені. Твердження PASS автора звіту не замінює review або hardware test.

# Стратегічне рішення та матриця повторного використання (Reuse Matrix)

Дата: 2026-10-01 (Оновлено за результатами рев'ю Codex)  
Робоча область: корінь репозиторію  
Статус: Завершено доопрацювання Кроку 1 (`IMPLEMENTATION_PLAN.md`)  
Цільовий артефакт: Durak 25.0 (`ru.appscraft.durak`, versionCode `250`, Unity `6000.4.0b6`, IL2CPP metadata v39, ARM64)

---

## 1. Обране стратегічне рішення

**Рішення:** **ПРИЙНЯТИ RUNTIME-ОСНОВУ `laytonbmr_nx` ЯК БАЗУ ДЛЯ АДАПТАЦІЇ В РОЛІ ЄДИНОГО BACKEND ДЛЯ DURAK NX.**

Попередня діагностична контрольна точка (`source/`, `include/` зі знімка `9db8020`) зберігається в ізоляції як референс для target hash verification (SHA-256, GNU Build-ID) та перевірки прав CodeMemory W^X, але **НЕ розвивається паралельно як другий конкуруючий runtime backend**.

### Обґрунтування вибору бази донора та межі її придатності:

1. **Технічна узгодженість підсистем (Cohesion vs Fragmentation):**
   У референсному проєкті `laytonbmr_nx` завантажувач (`so_util.c`), резолвер символів (`imports.c`), Bionic shims (`libc_shim.c`), fake JavaVM/JNIEnv (`jni_fake.c`), ANativeWindow glue (`android_native_unity.c`) та підсистема файлових дескрипторів (`fakefd.c`) спроєктовані для спільної роботи:
   - `so_lookup_export` та `dynlib_find_export` інтегровані з `dlsym_fake` та `dlopen_fake`;
   - fake JNIEnv прив'язаний до життєвого циклу потоків і Bionic TLS (`tpidr_el0 + 0x28`);
   - ANativeWindow транслює події вікна безпосередньо в EGL-контекст Mesa.
   Спроба перенести окремо лише JNI або libc на наш старий завантажувач без цілісного субстрату вимагала б складного шару взаємної адаптації.

2. **Покриття назв символів (99.17%) та архітектурний розподіл ролей:**
   Таблиці донора забезпечують **покриття назв (Name Match Coverage)** для 359 із 362 сильних зовнішніх символів (99.17%). Проте перевірка фактів реалізації через інструмент [`audit_symbols.py`](/D:/source/MyProjects/durak-mod-switch/tools/audit_symbols.py) доводить, що **це не означає готовності біндінгів до виконання (guest execution)**:
   - **101 символ (27.90%)** — адаптивні трансляційні шими (`TRANSLATION_SHIM`), де виконується активна конвертація структур, файлових шляхів чи підсистем (`stat_fake`, `readdir_fake`, `fakefd_*`, `__android_log_print`, `mmap`, `pthread_create`, `sysconf_pass` тощо);
   - **165 символів (45.58%)** — прямі неперевірені біндінги та pass-through обгортки (`DIRECT_BINDING`) на toolchain newlib/libm/libnx (`sin`, `malloc`, `memcpy`, `strlen`, `clock_gettime`, `gettimeofday`, `ftruncate_stub` тощо);
   - **93 символи (25.69%)** — заглушки (`STUB_OR_DUMMY`) з фіктивними поверненнями констант (`return 0`, `return -1`, `return NULL`, `(void*)1`), `ENOSYS` або no-op логікою. Сюди входять: `pthread_sigmask` (`(void)how; (void)set; (void)old; return 0;` — не змінює маску сигналів), `fcntl` (ігнорує `F_GETFL`, `F_SETFL`, `F_SETLK`), `truncate` (не обрізає файл), `sigaction`, `signal`, offline-сокети тощо;
   - **3 символи (0.83%)** — повністю відсутні в донорі (`asprintf`, `fchown`, `mremap`, усі для `libsqlite3.so`).
   - **Статус верифікації (окреме поле):** 356 символів (98.34%) мають статус `UNVERIFIED` (не підтверджені для runtime Durak 25.0); 3 символи мають статус `VERIFIED` (`stat`, `fstat`, `lstat` за 128-byte layout proof); 3 символи — `NOT_APPLICABLE` (`MISSING`).
   Поведінка `fchown` як no-op та здатність SQLite продовжити роботу після повернення `ENOSYS` для `mremap` є **неперевіреними гіпотезами/припущеннями**, які вимагають перевірки caller-а під час запуску на залізі.

3. **Сумісність релокацій AArch64:**
   Усі чотири модулі Durak 25.0 використовують виключно 4 типи релокацій (`R_AARCH64_RELATIVE`, `R_AARCH64_ABS64`, `R_AARCH64_GLOB_DAT`, `R_AARCH64_JUMP_SLOT`). Ці типи реалізовані у `so_util.c`. У Durak повністю відсутні релокації TLS (`TLS_DTPMOD64`, `TLS_TPREL64`, `TLSDESC`) та `PT_TLS` сегменти.

4. **Виявлені недоліки донора, що потребують виправлення в Кроці 2:**
   - **Недолік Memory Permissions:** Донорський `so_finalize` призначає `Perm_Rw` для ВСІХ невиконуваних сторінок, залишаючи сегменти `rodata` (`PF_R`) та релоковані таблиці `PT_GNU_RELRO` відкритими для запису. Необхідно додати явний захист `Perm_R`.
   - **Недолік Condvar Timedwait та Clock Domain:** Донорський `pthread_cond_timedwait_fake` штучно обрізає таймаут до 16 мс і повертає передчасний `ETIMEDOUT`. Крім того, він не відстежує призначений атрибутами годинник (`pthread_condattr_setclock` є в інвентарі Durak) і змішує домени `CLOCK_REALTIME` (дефолт POSIX) та `CLOCK_MONOTONIC`. Необхідно зберігати clock attribute, розраховувати таймаут у призначеному домені caller-а, передавати host wait API відносний таймаут і повертати 0 негайно після сигналу або допустимого spurious wakeup.
   - **Недолік `pthread_once`:** Донорський `pthread_once_fake` не містить бар'єру очікування для конкурентних потоків, повертаючи успіх ще до завершення ініціалізації іншим потоком. Потрібна синхронізація очікування.

5. **Готовність інструментарію та бібліотек:**
   Усі необхідні бібліотеки (`switch-mesa`, `switch-libdrm_nouveau`, `switch-sdl2`, `switch-zlib`) уже присутні в зафіксованому контейнері `devkitpro/devkita64`. Жодних змін у root `toolchain.lock` не потрібно.

---

## 2. Матриця повторного використання компонентів (Reuse Matrix)

| Компонент / Підсистема | Донорські файли | Залежності | Класифікація | Технічне обґрунтування та план дій |
| :--- | :--- | :--- | :---: | :--- |
| **1. ELF Loader & Memory Mapping** | `laytonbmr_nx: so_util.c`, `so_util.h` | `switch.h` (`svcMapProcessCodeMemory`, `virtmem`) | **ADAPT** | Завантажувач підтримує 4 типи релокацій Durak. **Обов'язкова адаптація:** 1) додати захист `Perm_R` для `rodata` та пост-релокаційного `PT_GNU_RELRO`; 2) забезпечити 64 KB вирівнювання віртуальної пам'яті для `libsqlite3.so` замість фіксованих 4 KB; 3) читати `DT_INIT_ARRAY` з `PT_DYNAMIC`; 4) інтегрувати target hash validation (SHA-256 + Build-ID). Робота мапінгу на Horizon OS підтверджується hardware логом. |
| **2. Bionic Libc / Libm Imports** | `laytonbmr_nx: imports.c`, `imports.h`, `unity_imports.c` | newlib, `libm` | **ADAPT** | Покриття назв: 359 / 362 (101 translation shims, 165 direct bindings, 93 stubs, 3 missing; 356 UNVERIFIED). **Обов'язкова адаптація:** замінити отруєння вказівників (poison-pointers) на fail-stop thunks; для ризикованих заглушок (`pthread_sigmask`, `fcntl`, `truncate`, `sigaction`) забезпечити контекстне діагностичне логування; додати 3 відсутні символи для `libsqlite3.so` (`asprintf`, `fchown`, `mremap`). |
| **3. Pthreads & TLS Substrate** | `laytonbmr_nx: libc_shim.c`, `util.c/h`, `imports.c` | newlib pthread, `armSetTlsRw` | **ADAPT** | Схема лінивої ініціалізації Bionic м'ютексів є робочою базою. **Обов'язкова адаптація (критичні виправлення донора):** 1) виправити `pthread_cond_timedwait_fake`: враховувати `pthread_condattr_setclock` (default `CLOCK_REALTIME` vs `CLOCK_MONOTONIC`), транслювати дедлайн у відповідному clock domain до host wait API без штучного 16-мс ETIMEDOUT; повертати 0 негайно при сигналі / допустимому spurious wakeup; 2) виправити `pthread_once_fake`: додати бар'єр блокування конкурентних потоків до завершення роботи ініціалізатора; 3) забезпечити per-thread Bionic TLS (`tpidr_el0 + 0x28`). |
| **4. Fake JavaVM & JNIEnv** | `laytonbmr_nx: jni_fake.c/h`, `unity_jni.c/h` | `jni.h` | **ADAPT** | Готова емуляція таблиці JNIEnv. **Обов'язкова адаптація:** 1) змінити сигнатуру `initJni` на 5 аргументів AAPCS64 з передачею валідного `jstring` `""`; 2) змінити сигнатуру `nativeInjectEvent` на 4 аргументи (`deviceId`); 3) реалізувати реєстр нативних методів за повним ключем `class + method + signature`, враховуючи клас `UnityPlayerForActivityOrService`. |
| **5. Android Native Window Glue** | `laytonbmr_nx: android_native_unity.c/h` | `switch.h`, `EGL` | **REUSE** | ANativeWindow емуляція узгоджена з Surface-подіями Unity (`nativeRecreateGfxState`, `nativeSendSurfaceChangedEvent`). |
| **6. EGL / GLES3 Graphics** | `laytonbmr_nx: android_native_unity.c`, `imports.c` | `switch-mesa`, `switch-libdrm_nouveau` | **REUSE** | Unity самостійно створює EGL-контекст поверх ANativeWindow. Використовується нативний драйвер Mesa Nouveau. |
| **7. Filesystem & Assets** | `laytonbmr_nx: fakefd.c`, `libc_shim.c` | newlib POSIX fs | **ADAPT** | **Адаптація:** налаштувати шляхи монтування під SD-структуру `sdmc:/switch/durak_nx/` без конфлікту з основним додатком; маршрутизувати записувані шляхи (`getFilesDir`, `getCacheDir`) у підпапку на SD; перевірити вплив заглушки `truncate`. |
| **8. Crash Diagnostics** | `laytonbmr_nx: diag.c/h`; `cloverpit_nx: nx_crash_handler.c` | `switch.h` (`userAppletWaitForExit`) | **ADAPT** | Поєднати durable pre-call маркери (`CTOR_ENTER`, `JNI_ENTER`, `RENDER_ENTER`) з перехоплювачем апаратних виключень Cloverpit для фіксації PC, LR, SP та RVA у файлі логу `durak_nx.log`. |
| **9. Unity Engine Lifecycle** | `laytonbmr_nx: main.c`, `unity_glue.c` | JNI, RegisterNatives | **ADAPT** | **Адаптація:** видалити всі спеціфічні для Layton патчі (патчі покупок, платних глав, детекції мови); запуск проводити суворо за контрактами Durak DEX. |
| **10. Touch & Gamepad Input** | `laytonbmr_nx: unity_input_hook.c`, `cloverpit_nx` | IL2CPP / JNI | **DEFER** | Відкладено до Кроку 8 (після отримання першого стабільного кадру рендерингу). |
| **11. Audio Subsystem** | `laytonbmr_nx: opensles.c`, FMOD | OpenSL ES / SDL2 | **DEFER** | Відкладено до завершення первинного рендерингу. |

---

## 3. Обов'язкові технічні адаптації для Кроку 2

На основі виправленого аудиту зафіксовано конкретний перелік обов'язкових інженерних змін:

1. **Виправлення захисту прав пам'яті (Memory Protection & RELRO):**
   - У `so_finalize` запровадити диференційоване призначення прав через `svcSetProcessMemoryPermission`:
     - Сегменти коду `PT_LOAD (PF_X)` -> `Perm_Rx`;
     - Сегменти констант `PT_LOAD (PF_R)` без `PF_W` -> `Perm_R`;
     - Область `PT_GNU_RELRO` -> переведення в `Perm_R` **після** завершення релокацій;
     - Сегменти даних `PT_LOAD (PF_W)` -> `Perm_Rw`.
   - Для `libsqlite3.so` забезпечити вирівнювання віртуального діапазону на `0x10000` (64 KB).
   - Підтвердити коректність мапінгу пам'яті через апаратний лог на Switch.

2. **Виправлення синхронізації потоків (Threading Fixes):**
   - **`pthread_cond_timedwait` та узгодження Clock Domain:**
     - **Збереження атрибуту годинника:** У Durak присутній символ `pthread_condattr_setclock`. Структура condvar повинна зберігати прив'язаний `clockid_t` (дефолт POSIX — `CLOCK_REALTIME`, або `CLOCK_MONOTONIC`, якщо задано через атрибути).
     - **Розділення доменів часу:** Дедлайн `abstime` caller-а порівнюється виключно з поточним часом у відповідному clock domain (`clock_gettime(cond->clock, &now)`). Безумовне змішування `CLOCK_REALTIME` (епоха 1970) з монотонним часом Switch (uptime від завантаження) неприпустиме, оскільки призводить або до негайного хибного `ETIMEDOUT`, або до зависання на десятки років.
     - **Узгодження з Host Wait API:** Обчислюється відносний залишок часу `timeout_ns = abstime - now_in_clock`. Отриманий відносний наносекундний таймаут передається системному очікуванню Switch (`condvarWaitTimeout` або `svcWaitSynchronization`). Якщо `timeout_ns <= 0`, повертається `ETIMEDOUT` негайно.
     - **Коректне повернення при сигналі:** При отриманні сигналу (`pthread_cond_signal`/`broadcast`) або допустимому spurious wakeup функція повинна **негайно повернути 0 caller-у** (не очікуючи настання дедлайну). Повертати `ETIMEDOUT` дозволено лише тоді, коли системний wait завершився за таймаутом і дедлайн дійсно вичерпано.
   - **`pthread_once`:** Реалізувати коректну синхронізацію: потік, що перший встановив прапорець, виконує ініціалізатор; усі інші потоки, що викликали `pthread_once` для того самого об'єкта, **блокуються і чекають** завершення виконання ініціалізатора.

3. **JNI Composite Key Registry:**
   - Реєстрація нативних функцій у fake JNI повинна індексуватися за складеним ключем:
     `"com/unity3d/player/UnityPlayerForActivityOrService/nativeRender/()Z"`.

4. **Коректні AAPCS64 Сигнатури JNI:**
   - `initJni`:
     ```c
     typedef void (*fn_durak_initJni)(JNIEnv *env, jobject thiz, jobject context, jint context_type, jstring cmdline);
     ```
     Значення `cmdline` має створюватися через `env->NewStringUTF(env, "")`.
   - `nativeInjectEvent`:
     ```c
     typedef jboolean (*fn_durak_nativeInjectEvent)(JNIEnv *env, jobject thiz, jobject input_event, jint device_id);
     ```

5. **Підтримка `PT_DYNAMIC` для конструкторів:**
   - Оновити `so_execute_init_array` для читання `DT_INIT_ARRAY` та `DT_INIT_ARRAYSZ` з `PT_DYNAMIC`.

6. **Діагностичні Fail-Stop Thunks:**
   - Замінити `*ptr = rels[j].r_offset` (отруєння вказівника) на виклик діагностичного thunk з логуванням символу та адреси виклику.

7. **Інтеграція Canonical M1 Target Verification:**
   - Перевірка SHA-256 та GNU Build-ID перед початком релокацій.

---

## 4. Специфічні Blockers, що потребують Hardware Validation

Наступні аспекти становлять реальні блокери, які **неможливо підтвердити статично**:

1. **Взаємодія Unity 6000.4 з Choreographer / Vsync:**
   - Поведінка рушія за відсутності Android Choreographer (чи зависне він у циклі очікування кадру) з'ясується лише на реальному залізі під час виклику `nativeRender`.
2. **Графічний контекст Mesa / Nouveau GLES3:**
   - Сумісність шейдерного пайплайну Unity 6000.4 з Horizon Nouveau драйвером.
3. **Boehm GC Thread Suspension Bridge:**
   - Обробка сигналів зупинки світу для GC на реальних потоках Switch.
4. **Реакція SQLite на поведінку `fchown` та відмову `mremap`:**
   - Підтвердження робочого стану бази даних при поверненні `ENOSYS` для `mremap`.
