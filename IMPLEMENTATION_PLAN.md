# Durak NX — єдиний план тестового MVP

Оновлено 2026-10-01. Робочий каталог: `D:\source\MyProjects\durak-mod-switch`.
Gemini реалізує; Codex перевіряє. Цей файл замінює попередню послідовність A–E.

## Мета і межі

Якнайшвидше отримати тестову збірку, яка пробує запустити **справжній Unity Durak**
на Switch: перший кадр → завантажувальний екран → меню. Першу спробу виконання
гостьового коду передати на консоль раніше, ніж готова вся графічна частина.
Не обіцяти меню до hardware test. NRO, який лише показує власний splash/консоль,
не є доказом запуску Unity. Constructors/JNI також не доводять, що гра запуститься.

MVP завершений, коли на Switch видно справжнє меню гри й лог підтверджує Unity
frame loop без fatal error. Звук, керування, офлайн-партія, збереження, мережа,
suspend/resume та оптимізація не входять у цей MVP. Якщо якась із цих підсистем
блокує саме старт — зробити лише необхідне для проходження конкретного виклику.

## Що вже виконано — НЕ повторювати

Ціль: Durak 25.0, `ru.appscraft.durak`, versionCode `250`, Unity `6000.4.0b6`,
ARM64 IL2CPP, metadata v39. Є аналіз ELF/DEX/metadata й адаптований runtime Layton.
Код тільки в `source/`, заголовки в `include/`; донорські знімки — `third_party/`.
`feasibility_spike` прибрано. Не створювати її, другий loader або новий план.

**Hardware pre-entry пройдено 2026-10-01.** Лог користувача:
`C:\Users\oleks\AppData\Local\Temp\durak_nx.log`.
Чотири модулі завантажено; 270567 relocations; 762 runtime shim links;
RWX=0, writable RELRO=0, query failures=0, permission mismatches=0,
unresolved strong data=0, fail-stop bindings=0. SQLite address `0x34a10000`
вирівняна до 64 KiB. Guest execution=0; виявлено 506 Unity і 22 IL2CPP constructors.

Codex повторно перевірив alignment/reservation fixes, native harness (7 тестів)
і Switch build. Пройдений pre-entry не треба тестувати ще раз як окрему задачу.
Непідтверджене: виконання guest, JNI, Unity init, графіка, меню.
У hardware log build identity `unknown`; наступна збірка повинна мати однозначний ID.

## Як працювати Gemini без зайвих витрат

- **Одна задача нижче за один робочий цикл.** Не реалізовувати всі чотири одразу.
- Спершу прочитати `GEMINI.md`, цей план, `git status`, relevant diff і потрібні
  функції. Не перечитувати весь репозиторій і не повторювати аналіз усіх символів.
- Використовувати існуючі `so_util`, `jni_fake`, `unity_jni`, `unity_glue`,
  `android_native_unity`, `imports`. Змінювати лише потрібний шлях запуску.
- Після задачі: NRO + build/check result + короткий звіт для Codex.
  Review стосується зміненого шляху. Hardware test потрібен, коли з'являється
  нова виконувана guest boundary; підготовку файлів/контексту можна перевірити разом
  із наступним запуском Unity, без окремого циклу заради самої підготовки.
- Логувати BEGIN/END критичних викликів, модуль, RVA, runtime address і thread.
  Зберігати лог перед guest call. Не додавати власну складну систему тестових режимів.
- Не підміняти невідомі критичні Android/JNI API успішними заглушками.
  Не застосовувати донорські offsets або ARM64 patches без доказу для Durak.
- Не робити commit/push. Не переписувати плани/документацію в кожному циклі;
  оновлювати тільки таблицю фактичного стану внизу.

## Чотири невеликі задачі

### 1. Перший guest test: constructors — ЗРОБИТИ ЗАРАЗ

Продовжити `source/main.c` і `source/so_util.c`. Перевірити необхідну TLS-підготовку
та порядок constructors за наявними цільовими ELF/DT_NEEDED; не просто копіювати
донорський порядок. Увімкнути DT_INIT/DT_INIT_ARRAY з BEGIN/END кожного виклику,
індексом і адресою; використати наявну crash diagnostic, якщо вона придатна.
Завершити діагностичний запуск після constructors. JNI/Unity render поки не викликати.
Build identity додати в цій же задачі, без окремого milestone.

**Результат:** готовий `durak_nx.nro` для негайного тесту на Switch після review.
**Доказ:** guest constructors реально повернулися або лог локалізував перший збій.
Не чекати готовності EGL, меню чи універсальної Bionic compatibility.

### 2. JNI bootstrap — тільки після результату задачі 1

У наявному fake VM підготувати основний thread; викликати потрібні exported
JNI_OnLoad за доказаним порядком і перевірити повернення. Логувати RegisterNatives:
class, method, signature, адреса. Не викликати всі бібліотеки навмання.
Підтвердити Unity native entrypoints за target RegisterNatives, не донорським RVA.
`initJni` і render у цій задачі ще не запускати.

**Результат:** наступна мала NRO для Switch; лог JNI_OnLoad/RegisterNatives або
точний failing call. Перевірити target versionCode `250` на задіяному JNI-шляху.
**Конкретна пастка:** `include/unity_entrypoints.h` містить донорський initJni
contract із 4 аргументами; наявні target DEX докази описують 5 аргументів.
Використати `docs/TARGET_EVIDENCE.md`/`tools/inspect_initjni.py`, а не цей typedef.

### 3. Підготовка першого кадру — тільки мінімальне з наявного runtime

Підключити потрібні target assets/metadata й існуючий Surface/EGL glue.
Визначити точний SD layout із фактичних APK/asset paths. Видати одну команду
або коротку інструкцію копіювання: джерело → SD destination; не змушувати користувача
вгадувати. Перевірити EGL initialization/context/surface і доступність файлів,
логувати їхні фактичні результати. Порожній SDL/EGL екран не називати запуском Unity.

**Результат:** підготовлений код, build/check, точний список SD файлів для задачі 4.
Це вузька задача з assets і graphics setup; constructors/JNI не переписувати.
Окремий hardware цикл лише заради підготовки не потрібний, якщо перевірка потребує
викликів із задачі 4; передати їх в одному наступному тестовому NRO.

### 4. Запуск Unity → перший кадр → спроба меню

Використати entrypoints із задачі 2, resources/context із задачі 3.
Підключити цільовий initJni, необхідний lifecycle і frame loop за підтвердженими
сигнатурами. Логувати вхід/вихід init, lifecycle, render та swap і перший кадр.
Не вводити donor TimeManager/allocator/input patches до доведеної необхідності.
Якщо старт заблокований — виправляти лише перший конкретний blocker цього запуску.

**Результат:** NRO для тесту справжнього Unity кадру, завантаження й меню.
**Доказ MVP:** користувач бачить справжнє меню + відповідний hardware log.
Повернення nativeRender або успішний EGL swap самі по собі не доводять меню.

## Коли продовжувати, а коли зупинити витрати

Після кожного guest test назвати останній завершений виклик і перший failing call.
**Продовжувати:** є нова пройдена runtime boundary або локалізований blocker,
для якого є конкретне обґрунтоване виправлення в наявному wrapper.
**Зупинити наступні зміни й пояснити причину:** той самий blocker повторився після
цільового виправлення без нових доказів, або потрібна нова велика підсистема
замість малої адаптації. У такому разі показати log/address/API і необхідний обсяг;
не витрачати наступні цикли на здогадки чи blanket stubs.
Один невдалий запуск не доводить неможливість порту. Успішний loader не доводить
можливість завершення гри. Рішення приймаємо за реальними guest tests.

## Збірка й передача на Switch

Windows: `powershell -ExecutionPolicy Bypass -File scripts/build_nro.ps1`.
Єдиний output: root `durak_nx.nro`; pinned toolchain із `toolchain.lock`.
На Switch через title override: `/switch/durak_nx/durak_nx.nro`;
чотири `.so` у `/switch/durak_nx/lib/`; log `/switch/durak_nx/durak_nx.log`.
Для першого тесту constructors поточний layout бібліотек уже працює.
Додаткові assets виконавець точно перелічує в задачі 3.

## Єдиний журнал стану

| Задача | Стан | Доказ / наступна дія |
|---|---|---|
| Loader/pre-entry | ПРОЙДЕНО на Switch | Hardware log 2026-10-01; не повторювати |
| 1. Constructors | ПРОЙДЕНО на Switch | Hardware log 2026-10-01; всі 528 constructors виконано без помилок |
| 2. JNI bootstrap | ПРОЙДЕНО на Switch | Hardware log 2026-10-01; 3/3 JNI_OnLoad OK, 13/13 Unity entrypoints підтверджено; FMOD відокремлено як unconfirmed |
| 3. Assets/EGL setup | ПРОЙДЕНО на Switch | Hardware log 2026-10-01; assets 7/7 доступні, 13/13 Unity entrypoints підтверджені, eglInitialize повернув EGL 1.4 |
| 4. Unity/frame/menu | ПРОЙДЕНО на Switch | Лог 19 (2026-10-02) і підтвердження користувача: меню, вибір режиму та gameplay працюють |
| Single Game / SQLite | ПРОЙДЕНО на Switch | durak_nx (19).log: single_stats CREATE rc=101 (рядок 2252); 0 SQLiteException / NullReferenceException; користувач підтвердив роботу гри |
| Приховування зайвих елементів меню | NEEDS_HARDWARE_TEST | Asset patch: 15 UI components + масштаб MainMenu/Background; 22565 об'єктів без змін; docs/main_menu_extras.md; перевірити вигляд, кліки та повернення з Single Game |
| Розблокування режимів Single Game | NEEDS_HARDWARE_TEST | 3 підтверджені level checks у SinglePlayerSelect.Start; build/native/Python PASS; docs/single_game_unlock.md; перевірити вибір і запуск раніше заблокованого режиму |
| Прискорення й очищення запуску | NEEDS_HARDWARE_TEST | Старт без console, без паузи 50 ms, пакетний logger зі збереженням critical flush; level0 camera black; docs/startup_cleanup.md; виміряти час до меню на Switch |
| Екран завантаження / Rate / Our Games | NEEDS_HARDWARE_TEST | level0/1 loading canvases; Our Games приховано; InvokeRateWnd ret з fingerprint/RX verification; build/native/Python PASS; docs/loading_screen_and_rating.md |
| Штатний аудіовихід | ПРОЙДЕНО на Switch | Після 9647093 користувач підтвердив запуск і звук; stack OC не активується, OpenSL -> SDL працює; docs/audio_output.md |
| Startup constructor log sync | ПРОЙДЕНО на Switch | Log 21: constructors/JNI 2.832 s проти 8.358 s, first nativeRender return 4.154 s проти 9.941 s; visible logo timestamp ще не виміряний |
| Free key / crown / top-left label | NEEDS_HARDWARE_TEST | InvokeFreeKeyWnd void entry -> ret з metadata/fingerprint/RX verification; PremiumOfferButton UI та VersionString TMP приховані; bundle зберігає попередні зміни; docs/menu_free_key_cleanup.md |
| Суцільний loading screen | NEEDS_HARDWARE_TEST | Log 22: CPU image 32 ms, disconnect 3606 ms, active MainMenu 14252 ms; overlay bypassed existing Mesa 0×0 extent fix. Виправлено спільний query wrapper + dynamic EGL proc routing; successful loading presents рахуються лише після overlay draw; assets не змінюються; docs/continuous_loading.md |
| Plus → меню поточної партії | NEEDS_HARDWARE_TEST | Прибрано exit render loop; Plus edge викликає штатний uGUI Button.Press зі scripting Input callback; native dispatch/re-entry/exception tests PASS; docs/plus_game_menu.md |
| Іконка та пропозиція Premium | NEEDS_HARDWARE_TEST | icon.jpg з картинки користувача, JPEG 256×256 для NRO; у DRAFT.ShowPremimBannerWnd пропускається тільки index=1 (PremiumOfferWnd), metadata/literal/fingerprint/epilogue перевірені; інші індекси збережені |

Виконано:
1. Задачу 3 пройдено на hardware Switch: assets 7/7, Unity entrypoints 13/13, EGL 1.4 probe OK.
2. Реалізовано задачу 4 (Unity Startup & First Real Frame Gate):
   - Підтверджено `context_type` за Dalvik декомпіляцією enum `com.unity3d.player.a.o`: `b` = `ActivityOrService` = 0, `c` = `GameActivity` = 1. Оскільки `ru.appscraft.durak` наслідує `UnityPlayerActivity` (`UnityPlayerForActivityOrService`), передається значення `context_type = 0`.
   - Виправлено зупинку логера на `consoleExit`: реалізовано режим file-only (`durak_log_set_file_only(1)`), що вимикає `vprintf`/`fflush(stdout)` перед закриттям консолі, але зберігає повний запис, `fflush`, `fsync` та перевірку помилок на SD-картці.
   - Додано маркування `[STEP BEGIN]` / `[STEP END]` для `appletGetOperationMode`, `android_native_update_mode`, `consoleUpdate`, `svcSleepThread` та `consoleExit`.
   - Коректне закриття текстової консолі `consoleExit(NULL)` перед передачею `nwindowGetDefault()` під ексклюзивне володіння Mesa EGL.
   - Виклик життєвого циклу Unity (`nativeRecreateGfxState`, `nativeSendSurfaceChangedEvent`, `nativeResume`, `nativeFocusChanged`, `nativeUnityPlayerSetRunning`).
   - Запуск циклу рендерингу `nativeRender` із детальним логуванням перших кадрів, EGL buffer swap та виходом по натисканню кнопки `+` (START).
3. Усунено MemoryManager / VirtualAllocator OOM blocker:
   - Підтверджено всі 18 цільових сайтів із `durak_recovered_offsets.h` (`DURAK_REGION_PATCH`) для `libunity.so` (Build-ID `bcc661ea2046416d`), які переводять константи та бітові маски алокаторів із 256MB на 64MB.
   - Реалізовано fail-closed патчер `durak_patch_unity_regions` (`source/region_patch.c`), що перевіряє всі 18 інструкцій перед внесенням змін і застосовується ДО запуску будь-якого гостьового коду, поки staging-буфер `mod->load_base` відкритий для запису. Додано post-check `durak_verify_unity_regions_post_map` для верифікації в CodeMemory (RX).
   - Підключено та озброєно stack-region overcommit арену (`oc_find_stack_window` + `oc_arena_init`), що виділяє 1.5 ГБ віртуального адресного простору у stack-регіоні для `PROT_NONE` резервацій із пулом фізичного коміту 384 МБ.
   - Усунено перетворення `PROT_NONE` у фізичну пам'ять у `source/libc_shim.c` (виключено `memset` для `PROT_NONE` в `mmap_fake` та fallback).
   - Додано детальне логування викликів `mmap` (OC / Arena / Fallback), `oc_commit_locked`, `mprotect_fake` та `munmap_fake`.
4. Вирішено блокер доступу до target assets (`unity_app_guid`, `Managed`, `bin/Data/...`):
   - Проведено повний аудит усіх 12 файлів `assets/bin/Data/` в оригінальному `Durak_25.0.apks` (`base.apk`): підтверджено 100% збіг розмірів і SHA-256 хешів із витягнутими файлами (включно зі справжнім 36-байтним текстовим GUID `c9783bb1-b86a-41a4-9351-f079904da435`, без створення синтетичного файлу).
   - Реалізовано структурований резолвер `durak_resolve_path` у `source/libc_shim.c` з пріоритетним пошуком: відносна адресація `assets/...`, `bin/Data/...`, прямі імена файлів/каталогів, Unix-rooted `/switch/durak_nx/...` та `sdmc:/switch/durak_nx/...`, взаємна підтримка канонічного шляху (`assets/`) та каталогу `game/assets/`.
   - Замінено сирий `&opendir` у `source/imports.c` на `opendir_fake` із резолвером шляхів (усуває збій на каталозі `Managed`).
   - Підключено `durak_resolve_path` до `open_fake`, `openat_fake`, `fopen_fake`, `stat_fake`, `lstat_fake`, `opendir_fake`, `access_fake`, `unlink_fake`, `unlinkat_fake`, `rename_fake`, `remove_fake`, `rmdir_fake`, `mkdir_fake`.
   - Додано обов'язкове логування I/O через `durak_log_printf`: `original path`, `resolved path`, результат виконання та `errno` з текстовим описом (`strerror`). `basename_fallback` збережено виключно як last-resort аварійний механізм.
   - Додано автоматичні тести (test 9, test 10 в `test_step2_loader_harness.py`), що перевіряють цілісність усіх 12 файлів та коректність резолвера шляхів.
5. Виправлено Overcommit (OC) commit path для усунення blocker `svcMapMemory FAIL dst=0x11000000 run=4096 rc=0xd401`:
   - `oc_commit_locked` тепер повертає `int` (0 при успіху, -1 при відмові). `mprotect_fake` більше не повертає 0 при невдалому коміті та поширює помилку з `errno` (`ENOMEM` / `EFAULT`).
   - На відмові `oc_commit_locked` логує повні діагностичні дані: `src`, `dst`, розмір у байтах, стан пулу (`pool_bump`, `pool_pages`, залишок), бітмапи `oc_used` та `oc_committed`, а також системні результати `svcQueryMemory` для `source` та `destination` (`base`, `size`, `state/type`, `permissions`, `attributes`, `ipc_refcount`, `device_refcount`).
   - Додано перевірки на повторний коміт, зайнятий destination (`mi_dst.type != MemType_Unmapped`) та придатність source pages (`mi_src.type == MemType_Heap`, `Perm_Rw`, `attr == 0`).
   - Невдалі сторінки гарантовано залишаються непозначеними як committed (`oc_committed == 0`), покажчик пулу `oc_pool_bump` не просувається.
   - Додано host negative test:
     * C native: `test_oc_commit_failure_contract` у `tests/test_loader_linker_native.c` (усі 10 тестів пройдено).
     * Python: `test_11_oc_commit_failure_contract` у `tests/test_step2_loader_harness.py` (усі 11 тестів пройдено).
   - Збірка `durak_nx.nro` успішно перезібрана (6,547,044 байт).
6. Виправлено GC stop-the-world bridge у `source/libc_shim.c` (усунено Data Abort у `pthread_kill_gc` за рядком 2304 / Build ID 6b9690ec3820ecb5a93eaf5823c18c4d11717312):
   - Доведено несумісність донорських Layton offsets (`0x209fd94`, що виходив за межі .bss і викликав Data Abort) та вилучено їх.
   - Відновлено 4 точні офсети для фактичного `libil2cpp.so` гри «Дурак» (31,256,704 байт, Build-ID `d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0`):
     * `GC_START_ACK_OFF`   = `0x1dda480` (GC parallel / restart-ack gate)
     * `GC_SUSPEND_SIG_OFF` = `0x1dda484` (GC suspend signal: за замовчуванням SIGPWR=30)
     * `GC_RESTART_SIG_OFF` = `0x1dda488` (GC restart signal: за замовчуванням SIGXCPU=24)
     * `GC_ACK_SEM_OFF`     = `0x1ff9188` (GC suspend ack semaphore, `sem_t`)
   - Додано 8-сайтовий масив `gc_guards` з верифікацією точних слів ARM64 інструкцій (`ADRP`, `LDR`, `ADD`) у `libil2cpp.so`.
   - Реалізовано перевірку меж модуля (`GC_MAX_OFF <= m->load_size`) та валідацію номерів сигналів (30 / 24).
   - Обґрунтовано архітектурну безпеку кооперативного підтвердження acks без примусового `svcSetThreadActivity`: виключення взаємного блокування (deadlock) на libc/heap locks та природна статичність фонових потоків Unity під час кадру.
7. Дослідження зупинки після кадру 143 (JavaChoreographer wait loop в `libunity.so`):
   - За hardware логом `durak_nx (11).log` перший кадр і логотип Unity успішно відображено на Switch OLED. Після кадру 143 (завершення сплеш-скріну та активація основного рушія) спостерігається зупинка оновлення екрану.
   - Дамп watchdog показав, що головний потік очікує у `pthread_cond_wait_fake`, caller `libunity.so+0xe78b38`, condition object `0x9fe459e0`.
   - За дизасемблюванням Durak `libunity.so` (Build-ID `bcc661ea2046416d`):
     * RVA `0x00e789e8` — конструктор класу `JavaChoreographer` (розмір об'єкта `0xf8`, vtable `0x01431fc8`).
     * `this + 0x0c` — м'ютекс (`pthread_mutex_t`), `this + 0x34` — умовна змінна (`pthread_cond_t`), `this + 0xe8` — покажчик на 16-байтну структуру `wrapper` (`*wrapper = 0`).
     * Умова циклу (`0x00e78b1c` - `0x00e78b28`): цикл очікує `*(uint64_t *)(*(uintptr_t *)(this + 0xe8)) != 0` під м'ютексом `this + 0x0c`.
     * Хто змінює умову: конструктор відправляє повідомлення 0 у Java Handler (`obtainMessage(0).sendToTarget()`). На Android черга Looper UI-потоку викликає `handleMessage` (`0x00e78d20`). При `msg.what == 0` (гілка `0x00e78de0`) метод блокує м'ютекс, викликає `Choreographer.getInstance()`, записує отримане JNI-посилання у `*wrapper` і викликає `pthread_cond_broadcast(this + 0x34)`.
     * Чому виникає зависання на Switch: у нашому середовищі немає Java UI Looper потоку для обробки черги повідомлень, а `Choreographer.getInstance()` у `jni_fake.c` повертає `NULL`. Навіть при спрацьовуванні cap-таймауту 16мс caller перевіряє предикат `*wrapper != 0`, бачить 0 і знову входить у `pthread_cond_wait`.
   - Додано неінвазивну цільову діагностику:
     * `source/imports.c`: виявлення виклику `pthread_cond_wait` з `libunity.so + 0xe78b38` з безпечним логуванням `this`, `cond`, `mtx`, `wrapper`, `*wrapper` та кількості спінів кожні ~3 с.
     * `source/jni_fake.c`: логування запитів `Choreographer.getInstance()` та `Handler`/`Message`.
   - Досліджено архітектурне рішення: `JavaChoreographer` інстанціюється через `ChoreographerBase::Get()` (`0x00e7261c`), обидва виклики якого (`0x00e7258c` та `0x00e72770`) містять перевірку `cbz x0` і коректно підтримують повернення `NULL` (перехід на вільний фреймрейт без Android vsync).
8. Реалізація fail-closed патчу `ChoreographerBase::Get` -> `NULL` fallback (RVA `0x00e7261c`):
   - Досліджено та підтверджено повний набір викликів `ChoreographerBase::Get` (RVA `0x00e7261c`) у `libunity.so` (Build-ID `bcc661ea2046416d`): рівно два місця виклику (`0x00e7258c` та `0x00e72770`), 0 у `libil2cpp.so`.
   - Обидва сайти викликів мають верифіковану перевірку `cbz x0` (`0xb40003c0` та `0xb40000a0`), яка при поверненні `NULL` штатно переходить на епілог і повертає керування без виконання блокуючих операцій.
   - Реалізовано fail-closed патч `DURAK_CHOREOGRAPHER_PATCH` у `include/region_patch.h` та `source/region_patch.c`:
     * RVA `0x00e7261c`: `0xd10143ff` (`sub sp, sp, #0x50`) -> `0xd2800000` (`movz x0, #0`)
     * RVA `0x00e72620`: `0xa90357fe` (`stp x30, x21, [sp, #0x30]`) -> `0xd65f03c0` (`ret`)
   - Патч застосовується у writable staging-буфері `mod->load_base` ДО `so_finalize` та верифікується у CodeMemory (RX) через `durak_verify_unity_choreographer_post_map`.
   - Додано автоматичні тести: `test_durak_unity_choreographer_patching` у `tests/test_loader_linker_native.c` (10/10 тестів PASS) та `test_12_durak_unity_choreographer_patch_contract` у `tests/test_step2_loader_harness.py` (12/12 тестів PASS).
   - NRO перезібрано для перевірки проходження кадру 142 та виходу в меню гри.
9. Дослідження та усунення очікування `libunity+0xe7247c` (Switch 60 Hz Frame Pacing):
   - Досліджено цикл очікування за дампом `durak_nx (15).log`: функція `WaitForVsyncFrame` (`0x00e72440` – `0x00e7249c`), м'ютекс `0x15571c4`, умовна змінна `0x15571ec`, лічильник `0x1557220`. При виклику `pthread_cond_wait` повернення здійснюється на `0x00e7247c` (100% збіг із дампом watchdog).
   - Знайдено всі джерела викликів функції збільшення та broadcast `Unity_OnVsync` (`0x00e724a0`): `0x00e78e90` (`JavaChoreographer::FrameCallback::doFrame`), `0x00e7963c` (`NativeChoreographer::frameCallback`), `0x00e79694` (`NativeChoreographer::frameCallback64`).
   - Встановлено причину зупинки: NULL-патч Choreographer запобіг дедлоку конструктора Java, але через відсутність активного хостового Choreographer виклики `Unity_OnVsync` ніколи не генерувалися. Лічильник залишався 0, і рушій зависав у `WaitForVsyncFrame(target)`.
   - Реалізовано фоновий потік `durak_frame_pacer` (`source/frame_pacer.c`, `include/frame_pacer.h`):
     * Власний Bionic TLS блок (`install_bionic_tls`) для валідності канарки стека під час виконання гостьового коду.
     * Каденс 60.0 Гц (16.666 мс) із точними монотонними мітками `CLOCK_MONOTONIC` та компенсацією дрейфу.
     * Попереднє калібрування (priming) двома імпульсами на старті для валідного `deltaTime = 16.6ms`.
     * Інтеграція в `source/main.c`: старт перед рендером, зупинка при виході, 1ms yield у головному циклі.
     * Діагностичний хук `vsync_diag` у `source/imports.c` для моніторингу очікувань `0xe72460..0xe72480`.
   - Додано native C unit-тест `test_durak_frame_pacer` у `tests/test_loader_linker_native.c` (усі тести PASS).
   - Збірка `durak_nx.nro` успішно перезібрана для hardware validation на Nintendo Switch.
10. Реалізація підтримки тачскріну в меню (Touch & Pointer Input Gate):
   - Досліджено та підтверджено повний набір точних RVA методів `UnityEngine.Input` у `libil2cpp.so` (Build-ID `d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0`):
     * `get_touchCount`: RVA `0x184408c` (`0xa9bf4ffe`, `0xd0002cf3`)
     * `GetTouch`: RVA `0x1843998` (`0xd101c3ff`, `0xa90557fe`)
     * `get_mousePosition`: RVA `0x1843bb4` (`0xd10083ff`, `0xa9014ffe`)
     * `GetMouseButton`: RVA `0x18438e4` (`0xf81e0ffe`, `0xa9014ff4`)
     * `GetMouseButtonDown`: RVA `0x1843920` (`0xf81e0ffe`, `0xa9014ff4`)
     * `GetMouseButtonUp`: RVA `0x184395c` (`0xf81e0ffe`, `0xa9014ff4`)
     * `get_touchSupported`: RVA `0x1844020` (`0xa9bf4ffe`, `0xd0002cf3`)
     * `get_mousePresent`: RVA `0x1843fb4` (`0xa9bf4ffe`, `0xf0002cf3`)
     * Донорські RVA з Layton (наприклад `0x1bf48f4`) повністю відкинуто як недійсні для Durak 25.0.
   - Верифіковано розкладку структури `UnityEngine.Touch` у `global-metadata.dat` v39: рівно 68 байтів (`0x44`), `_Static_assert(sizeof(NxTouch) == 0x44)`.
   - Забезпечено суворе дотримання AAPCS64 ABI:
     * `GetTouch`: структура > 16 байтів повертається через непрямий результатний буфер `x8` (`sret`).
     * `get_mousePosition`: HFA з 3-х float (12 байтів) повертається у регістрах `s0`, `s1`, `s2`.
     * Скалярні методи повертають значення у `w0`.
   - Реалізовано повну машину станів подій дотику: Began (0) -> Moved (1) / Stationary (2) -> Ended (3) -> Idle.
   - Забезпечено критичний контракт відпускання (release frame): при відпусканні пальця подія `TouchPhase.Ended` передається рушію рівно один кадр зі збереженням `touchCount == 1` та `GetMouseButtonUp(0) == 1`, що гарантує генерацію кліку в `TouchInputModule` / `EventSystem` (`IPointerClickHandler.OnPointerClick`).
   - Реалізовано перетворення координат екрана Switch (початок зверху-зліва, 1280x720) у координати простору екрана Unity (початок знизу-зліва): `uy = screen_height - raw_y * (screen_height / 720.0f)`.
   - Реалізовано чисте логування переходів (тільки Began та Ended із тривалістю у кадрах) без покадрового спаму.
   - Усі нерелевантні донорські хуки (Language, PlayerPrefs) видалено.
   - Додано native C unit-тест `test_durak_unity_input_hooks` у `tests/test_loader_linker_native.c` (12/12 тестів PASS).
   - Збірка `durak_nx.nro` успішно скомпільована для тестування дотику в головному меню на реальному Switch.

## Release v0.1.0 — 2026-10-02
- User accepted the current version as the first release; earlier hardware feedback confirms working gameplay and audio.
- Runtime code unchanged. NACP version set to 0.1.0. Build intermediates moved to build-obj; build is the complete SD overlay.
- Packaging regenerates and verifies menu assets, copies four libraries and all assets, records per-file SHA256, and excludes saves/user databases.
- Local Python dependencies moved to tools/cache/python. Git metadata preserved. Removal of .single-game-* scratch entries was rejected by automatic approval policy; these entries remain ignored.
- Release gate passed: pinned clean build, native checks and 12 Python tests. All 29 packaged files passed SHA256/size verification; packaged NRO matches root output, NACP version is 0.1.0, and no save/user database is included. Bundle SHA256: 60c147b892bb207fce747dd7ef4cc0533a7a282456c03c74f7ccc5358c4b05f2.

## Repository layout cleanup — 2026-10-02
- User removed the ignored .single-game-* scratch entries after the automatic deletion rejection.
- Moved seven historical analysis outputs and the original APK investigation notes from root to docs/analysis; updated inventory consumers, tests and generator defaults.
- Moved the release build log to build-obj/logs. Root Makefile, game archive, icon, instructions and compiler outputs retain the paths used by the build and target checks.
- Runtime and accepted v0.1.0 SD package unchanged; release tag remains pinned to its original commit.
- Verification: 81 symbol-inventory, M1 fail-closed and ELF-loader tests passed; staged diff check passed and all eight moves preserve file contents.

## Loading activity animation — 2026-10-02
- User requested visible activity on the existing loading screen. Three gold dots advance every 250 ms, with the same monotonic phase in CPU framebuffer and EGL shader paths; no additional loading screen or invented percentage.
- Before EGL, a libnx thread updates the framebuffer only on phase changes. Framebuffer drawing/disconnection share a mutex; shutdown disconnects, joins the worker and then frees the shared image. Thread creation/start failures report their real Result codes and preserve the static image/EGL fallback.
- EGL animation uses a shader uniform on the existing fullscreen draw, preserving the existing graphics state restoration and MainMenu readiness gate.
- Verification: pinned build/native/Python checks; native coverage checks changing dot pixels, padded stride, no queue after framebuffer disconnect, idempotent shutdown and thread creation/start failure cleanup. Actual animation continuity across the EGL handoff needs Switch validation.

## Local inventory unlock and unlimited gadgets — 2026-10-02
- User authorized unlocking all card covers, avatars and gadgets, including unlimited gadget use.
- Verified the original local catalog and all sprites: 8 covers, 39 avatars, 4 gadgets. Metadata/relocations prove GadgetSelectWindow.useGadget and the quantity field; 12 original instruction words guard the single consumption patch.
- Grants missing items on the existing metrics connection after successful SELECT preparation, before its first step/cache population. Exact filename/schema allowlists, savepoint rollback, real SQLite/errno diagnostics; no table creation, replacement, statistics or selection changes. Existing positive gadget stock retained; depleted stock raised to one.
- First pinned build, existing native checks, 12 Python loader tests, 10 real-SQLite inventory/patch tests and target cosmetics verifier passed. Final build reruns checks after commit. Evidence and hardware acceptance steps: docs/cosmetics_unlock.md. Status: NEEDS_HARDWARE_TEST.

## Case sensitivity temporary files — 2026-10-02
- User requested fixing accumulated CASESENSITIVETEST files. Target metadata/calls prove the .NET DeleteOnClose probe; log (22) shows unlink errno 5 while open.
- Preserve unlink errors/native Result; retry only exact empty probes after successful last tracked close. Before Unity startup remove matching old empty probes after closing the directory. No user database or synthetic platform files touched.
- Native fault injection added to the pinned build gate. Evidence and Switch acceptance: docs/case_probe_cleanup.md. Status: NEEDS_HARDWARE_TEST.

## Cosmetic acquisition hints — 2026-10-02
- User requested removing the three chest/key hints for avatars, shirts and gadgets. Original l10n Generic keys get_new_avatar/get_new_cover/get_new_gadget match the quoted English texts.
- Packaging disables only the Image and TextMeshProUGUI components of SelectAvatar/SelectCover/SelectGadget Content/Image panels. Exact hierarchy, component IDs/classes, original enabled bytes and localization bindings are verified before patching. Controllers and selection references retained.
- Bundle verification compares every serialized object: six additional enabled-byte changes, no additions or unrelated changes. Switch visual acceptance still required.

## Premium offer direct Single Game trigger — 2026-10-02
- User reports the modal still appears. Proved a separate SinglePlayerSelect.OnEnable direct resource path to PremiumOfferWnd, bypassing the earlier DRAFT-only suppression.
- One branch now follows the original non-offer continuation before resource loading/instantiation/Window.Open. Preserve showTab and balanced epilogue; pre-write and post-map fingerprint checks cover both paths.
- Extended native rejection tests and added target metadata/literal/disassembly verification to packaging. Evidence: docs/premium_offer.md. Status: NEEDS_HARDWARE_TEST.

## Remaining cosmetic hint decorations — 2026-10-02
- User reports backgrounds remain after hint text removal. The earlier Image components are info icons; full-width decorations are separate siblings: InfoBack/info-bg in all three selectors and BottomGr/bottom-gr in avatar/cover selectors.
- Disable only those five Image renderers, verifying exact paths, class, enabled byte, sprite PPtr/name, serialized length and position below the item lists. No item, frame around a selectable item, list controller or modal background changed.
- Packaging verifies every object after repacking: five additional enabled-byte changes, zero additions. Hardware visual acceptance required.

## Startup timing baseline — 2026-10-06
- User authorized measurement implementation and explicitly requires all output in durak_nx.log only. No CPU boost, splash, artwork or startup behavior optimization in this gate.
- Added monotonic microsecond phases and in-memory startup counters; one main-thread summary after the existing loading handoff. Separately measure pre-main heap initialization; icon-click/pre-heap time still requires external timing.
- Document nested/overlapping spans, coverage and in-flight exclusions. Evidence/procedure: docs/startup_measurements.md. Native timing/errno/concurrency/freeze tests added to build gate. Status: NEEDS_HARDWARE_TEST.

## Activate immutable asset read-ahead — 2026-10-06
- Hardware baseline 422c06d: MainMenu handoff at 19.33 s, zero cache fills. Static proof: slots initialized to fd=0, attachment requires fd<0. User authorized fixing this cause first.
- Explicit free-slot initialization plus tested cursor/error/EOF/descriptor-reuse semantics; positional and file-map reads share the cache lock and preserve sequential position. Only immutable assets are eligible, bounded to eight 1 MB windows; fallback retains ordinary reads.
- Native real-file/fault-injection/concurrency tests added. Startup diagnostics retained, only in durak_nx.log. Evidence: docs/read_ahead_fix.md. No l10n importer, CPU boost or splash changes. Status: NEEDS_HARDWARE_TEST.

## Combined startup accelerations — 2026-10-06
- User explicitly authorized combining feasible accelerations into one build. Keep full target verification and existing host loading design.
- Hardware SHA256 plus fail-closed self-tests; CPU FastLoad before EGL/normal restore; batched startup log sync with explicit fatal/watchdog durability; disable hidden Unity splash; preserve existing l10n via its proven SimpleSQL overwrite flag while retaining missing-file initialization.
- Packaging verifies byte-exact asset changes and SimpleSQL metadata/call flow. Native SHA and logging tests extended; existing gates retained. Details/limitations: docs/startup_fast_package.md. Status: NEEDS_HARDWARE_TEST.

## Remaining Unity startup I/O — 2026-10-06
- User limits optimization to the 8.860697 s nativeRender interval in log (24); forwarder/launch timing is outside scope. Menu handoff improved from 18.577009 to 10.150068 s in the previous package.
- Cache successful SQLite export lookups, small immutable asset contents across independent opens (16 MiB budget), and positive regular asset metadata. Mutable databases/journals, directory metadata and errors retain native paths; existing SQLite/errno diagnostics preserved.
- Native concurrency, cursor, error/retry, mutable-file and budget-pressure tests added; first startup frame spans and cache metrics stay file-only. Evidence: docs/startup_unity_io.md. Status: NEEDS_HARDWARE_TEST.

## Centered loading logo pulse — 2026-10-06
- User requests the gtasa_nx cover style and explicitly removes Loading text. Flat dark background, original 400x400 centered artwork, two-second cosine pulse at 1.00..1.08 scale. Replace the former text/dots/line within the existing shared CPU/EGL screen.
- Keep existing display ownership, error reporting and MainMenu readiness release. Common layout/timing header, CPU transformed-pixel and failure-cleanup tests; EGL uses a scale uniform and single texture upload. Its motion follows Unity presents and can pause during a blocked startup frame. Evidence: docs/loading_activity.md. Status: NEEDS_HARDWARE_TEST.

## Independent continuous loading layer — 2026-10-06
- User rejects pulse freezing during Unity startup and requests one continuously animated logo until menu. CPU worker now uses a distinct owned VI layer/NWindow above Unity, survives EGL acquisition and releases only after MainMenu readiness/two default-window presents. Unity splash remains disabled in the verified asset package.
- Public libnx lifecycle plus proven AddToLayerStack IPC layout; default producer/override protected. Real pthread test covers animation without main/Unity presents; all setup-stage failures and cleanup/fallback paths tested. Result/stage, heartbeats and final CPU frame count/gap are file-only. Evidence: docs/independent_loading.md. Status: NEEDS_HARDWARE_TEST (VI manager permissions, visible layer ordering, menu reveal and HOME/resume).

## Correct SDK display borrowing — 2026-10-06
- Hardware log (25), 3df3fe8: viOpenDefaultDisplay Result=0x1272, independent=0; CPU framebuffer disconnected at 1629 ms, fallback until 7971 ms menu. Animation thread started; the independent layer never existed.
- Capture the SDK's successful pre-main Default display open via GNU --wrap; borrow the exact returned ID/name and never reopen or close that display. Preserve real SDK results, default window and own-layer cleanup. Native regression rejects duplicate opens and borrowed closes; linked ARM64 test verifies capture is reached by SDK init. Evidence: docs/independent_loading.md. Status: NEEDS_HARDWARE_TEST after this initialization fix.

## Explicit loading layer visibility — 2026-10-06
- Hardware log (26), 03f5ceb: own layer 482/producer 1 created successfully; 146 CPU frames, maximum gap 97 ms, but user sees black. Layer initialization and worker execution now proven; compositor scanout is not.
- Factory omitted per-layer visibility. Require manager 6002 and system 2207 success for the owned ID before publishing its NWindow. SwIPC (b8, u64) wire ABI verified with static assertions and byte-level native tests; both failure paths preserve real Results/cleanup. No display-wide visibility or focus change.
- Regression starts a created layer hidden and requires both visibility gates; all 13 setup failures are checked. Evidence: docs/independent_loading.md. Status: NEEDS_HARDWARE_TEST for actual visible animation/menu handoff; missing visibility is a code omission, not hardware-confirmed sufficiency.
- Verification: regression rejects pre-fix source; updated native layer/async tests and full pinned build, 13 ELF/Python tests, 10 SQLite tests and asset packaging passed. Final committed build/package verification follows.

## Preserve default-window loading when private scanout is unverified — 2026-10-07
- Hardware log (27), 25c4f0a: both visibility Results zero, 139 frames/max gap 65 ms, but black until menu at 7890 ms. Visibility-only sufficiency disproven; private compositor scanout cause not established.
- Restore identical logo on the known default CPU window before private setup, release only its producer before EGL, and actually draw on first MakeCurrent/every startup swap regardless of independent=1. Retain the private pulse; adopt default framebuffer on private failure. Split graphics/CPU locks so blocking GL calls cannot freeze the worker; shutdown joins before freeing art under the graphics lock.
- Private candidate matches libtesla manager-owned ARUID 0; explicitly request owned-layer alpha 1 and verify positive Z via real readback. No global display/focus state change. Preserve Results/value diagnostics exclusively in durak_nx.log. Ownership/opacity as the original scanout cause remains unproven.
- Native tests cover per-window failure/cleanup/producer isolation and actual GLES draw with independent=1 while the driver blocks for 250 ms; CPU worker must advance. Layer wire/readback tests cover all 15 setup stages. Evidence: docs/independent_loading.md. Status: NEEDS_HARDWARE_TEST for visible continuous animation through menu.
- Focused gates passed: real GLES draw/worker concurrency and layer failure/readback tests. Reintroducing the former shared mutex makes the worker-progress assertion fail, confirming the regression test detects that coupling. Full committed NRO/native/Python/SQLite/package gate follows.

## Single Play selector transition latency — 2026-10-07
- User confirms delayed window is the mode selector both on direct Single Play click and after game-to-home return. Existing log (27) has no measured transition, so total cause/magnitude is not established.
- Confirmed post-menu host overhead: every normal diagnostic flush forced log fsync under the logger mutex after startup batching was disabled. Coalesce runtime log syncs at 1000 ms while publishing bytes immediately; retain critical/watchdog/close durability and all error reporting. Game database sync/journal/save behavior unchanged.
- File-only slow nativeRender and default-window EGL-present markers (>=100 ms), with inclusive logger-sync deltas, distinguish blocking engine/presentation work. No managed ABI/RVA or scene animation changes. Evidence: docs/single_play_latency.md.
- Native regression covers boot-to-runtime policy switch, 1000 runtime flush pairs, byte publication, interval/critical/close syncs and fsync failure. Status: NEEDS_HARDWARE_TEST for measured selector improvement.

## Single Play repeated SQLite sidecar probes — 2026-10-07
- Log (28), 5050012: first selector frame 1820 ms/16 ms logger sync; return selector frame 1220 ms/zero logger sync. User sees no acceleration. Logging is not the dominant residual cause; repeated l10n journal/WAL absence probes are directly observed, but their elapsed share is not yet measured.
- Frame-scoped observed-ENOENT cache for the three known databases' journal/WAL/SHM only. Live base/positive/error metadata preserved. Namespace mutations invalidate with an in-flight writer barrier/epoch and alias/ancestor handling; each frame ends with empty state. Sidecar probes bypass the inappropriate asset basename fallback. No database writes/sync/PRAGMA/schema or guest ABI changes.
- Add inclusive per-slow-frame sidecar probe count/time/cache-hit evidence, file-only. Native real-file tests cover 2000 avoided probes, creation/removal/rename, pending/stale-miss races, aliases, errors/Result and concurrent readers. Evidence: docs/single_play_latency.md. Status: NEEDS_HARDWARE_TEST for actual latency reduction; no claim of full root-cause attribution.

## Multiple modal opening diagnostic build — 2026-10-10
- User requests a log build for delays across modals. Reuse native instrumentation for per-render SQLite/I/O/asset/wait/shader measurements, separating main and all threads, with bounded slow-call SQL and caller-RVA samples. File-only reporting after render; preserve saves, errors and game/UI behavior. No new managed hooks or loader patches.
- Existing log (29) does not attribute 1810/1219 ms to logger/sidecar work. Evidence and coverage limits: docs/single_play_latency.md. Status: NEEDS_HARDWARE_TEST; inspect the new log before implementing an acceleration.

## Retain modal resource archive — 2026-10-10
- New hardware log (`2026-10-10T06:32:04Z`): slow first/return selector frames read 69 MiB of assets each; main asset fills take 588/595 ms. This is substantial observed work, not attribution of all 1829/1224 ms. Warm selector frames show no asset fills and take 200–239 ms.
- Extend the existing immutable whole-file cache only for packaged data.unity3d (actual 30.8 MiB), with a separate 32-MiB cap, unchanged cursors/errors/short reads and ordinary fallback. Keep database/save/UI behavior. Add file-only archive counters; previous source fails the new scatter-read regression, updated source passes. Details/limits: docs/single_play_latency.md. Status: NEEDS_HARDWARE_TEST for visible improvement and archive-specific byte confirmation.
- Hardware follow-up `durak_nx (1).log`, build `2026-10-10T06:49:28Z`: archive resident 32,272,398 bytes, zero native archive fills/bytes or evictions across reported slow frames. First selector render 841 ms (previous 1829), automatic selector 320 ms (previous 1224); tabs differ, so these are observations rather than identical-workload benchmarks. ProfileWindowNew context still takes 1081 ms with only 51.5 ms native SQLite steps and 5.3 ms main file reads; residual managed/engine work is not attributed. Archive I/O removal confirmed on Switch; overall latency/visible correctness gate remains open. Evidence-only update, no new runtime changes or rebuild.

## Compile immutable catalogs and remove premium opening work — 2026-10-10
- User authorizes moving non-progress data into code and removing premium checks. Compile 19 original dict/l10n tables (1298 rows), preserving field types/IDs/text/art/scene names; companions commerce/premium flags become zero. Direct localized key lookup removes repeated Generic SQL mapping/reflection. Original typed lists/rows use public IL2CPP APIs and GC handles at three proven managed boundaries; progress and errors tail-enter the original bodies.
- Metadata, method-spec/generic registration and call graph prove boundaries. Eight-word entry fingerprints, pre-write checks for every patch/export and exact post-map checks; assembled AAPCS64 guards restore original arguments/MethodInfo/LR and exact stack prologues. Skip SinglePlayerSelect marketing counter/premium-date work while retaining both redraws/showTab; suppress all DRAFT premium banners. File-only handled/fallback counters and native callback durations added.
- Every original row/column, two languages, GC roots, independent lists/rows after consumer mutation, errno, allocation/error/progress fallback, patch rejection and assembled guard checks passed; full pinned NRO/native/Python/real-SQLite/package gates passed. Evidence and remaining limits: docs/single_play_latency.md. Legacy initialization/files/raw SQL fallback remain for compatibility; this is not a claim that all non-progress SQL storage or scattered premium reads have been removed. Status: NEEDS_HARDWARE_TEST for UI behavior, persistence and actual remaining latency.
- Startup crash follow-up: both supplied Atmosphere reports normalize to GCHandle::Free RVA 0xbe5c04, called by durak_static_table at native LR +0x2554c. Native W0 load truncates a pointer-sized Unity 6 GC slot. User forbids rollback. Replace all root API signatures, locals and translation-cache entries with eight-byte uintptr_t handles; verify target X0 return/block dereferences and exercise handles above 4 GiB. Reintroducing the old list-root truncation makes the regression fail; fixed source passes. Catalog/premium/archive changes retained. NEEDS_HARDWARE_TEST after the corrected build; no runtime success claimed from static/native checks alone.
- Next crash report 01791620508: shared list indexer RVA 0xeb4770 reads array class through X9=0xe0000; _items points into the callback stack. Proved target field_set_value passes dereference=false and stores reference argument directly (STRING/SZARRAY jump table). Replace &array/&str with direct objects, retain scalar byte pointers, read back references before releasing roots/exposing results. Corrected mock rejects non-managed reference pointers; independent array/string mutations reproduce failures, fixed code passes alongside wide-handle tests. Target setter contract joins packaging checks. Changes retained; NEEDS_HARDWARE_TEST for this corrected build.
- Hardware log (3), build 08:23:53Z: reaches MainMenu and frame 4140 of perevodnoy gameplay without recorded abort/reference mismatch. First selector Tab 1: 320.843 ms, 8 SQL steps/7.530 ms, 24/24 compiled rows and 21/21 compiled texts; previous first Tab 1 was 1829 ms/1713 steps. Native archive reads remain zero. Startup/list/gameplay paths exercised successfully; no profile opening or completed-game automatic selector return in this run. Full modes/languages/persistence and those remaining acceptance cases still require hardware testing; legacy initialization/MainMenu premium read remain. Evidence-only update, no rebuild.
- Hardware log (4), same corrected build: first selector 310.205 ms, automatic selector after autoShowSingleSelect=True/isEnded=True 269.556 ms, profile context 342.494 ms (earlier baselines 1829/1224/1961 ms). Both selector opening paths and profile now exercised, plus tabs 1/3 and blocks/home; no recorded abort/reference mismatch through frame 2340. Archive native reads remain zero and static hits replace catalog/localization reads. MainMenu return is separately 680.437 ms (later 752.105 ms); measured scene-to-selector span 1090.799 ms, not click-to-visible time. Hardware stall reduction confirmed on these paths; visible acceptance, full modes/languages/persistence and remaining cleanup still pending. Evidence-only update, no rebuild.
- Continued cleanup authorized: skip MainMenu premium_end/date/log and purchased-companion offer scan while retaining profile/currency/cups refreshes and original hide-offer epilogue; disable eight metadata-proven void automatic-commerce/ad-ID/purchase entries. Existing scene-counter increments/UPDATE are bypassed (log (4) measured one at 60.558 ms), but missing-row/first_run initialization and original daily rewards remain because metadata/call graph proves the calendar dependency. No save database replacement, invented progress, journal/fsync changes or new managed/native callbacks. Four-word fingerprints at every cleanup site, atomic pre-write rejection and post-map checks extended; packaging now proves method tokens/relocations/field offsets/generic arguments/literals, branch targets and epilogues. Details: docs/single_play_latency.md. NEEDS_HARDWARE_TEST for the new build; prior timings do not establish its additional improvement.
- Verification passed: full pinned build/native tests, 13 loader/Python tests, 10 real-SQLite inventory tests, catalog/guard/offline cleanup target proofs and complete SD packaging; deliberately incorrect destinations for all three new branches are rejected. New NRO 2026-10-10T11:23:18Z (5228969-dirty), SHA256 81ce478616deb87a2b243e50917731ac10c22f2c252ca6cc40ab4e59b9889ff9. Hardware gate remains open.
- Hardware log (5), new 11:23:18Z build: no recorded fatal/static reference error through frame 1800; CHECK PREMIUM and SceneOpeningNumber samples absent. MainMenu return 614.106 ms (previous 680.437), native SQLite 2 steps/5.188 ms; prior counter UPDATE absent. First/automatic selector 320.872/276.891 ms and profile 339.818 ms show no additional meaningful window improvement. Measured menu-to-selector span 1023.861 ms, not click timing. Game initialization remains 1048.101 ms; another 39-row UI frame takes 397.468 ms without a SQLite step. Subsequent Variables saves take 54–59 ms but bound keys are not logged, so do not remove them blindly. Correction: the old MainMenu isEnded/isStarted messages describe companion-offer timing, not game completion; automatic home return is exercised, completed-game/results return is not established. Cleanup removal confirmed on hardware; residual managed/UI cost, visible acceptance and full modes/languages/reload remain open. Evidence-only update, no production changes or rebuild; see docs/single_play_latency.md.
- User accepts the log (5) result and explicitly requests diagnostic cleanup/commit. Remove temporary runtime profiler, detailed timing/SQL/caller samples, catalog/archive snapshots and success-only logs; omit periodic render/EGL/pacer/touch/vsync inspections and Android verbosity 2–4. Keep unknown/default and WARN/ERROR/FATAL Android priorities, all failure/patch/reference/SQLite diagnostics, watchdog and critical durability; startup profiling remains. Accepted archive/catalog/premium/commerce/scene-counter fixes and original progress persistence retained. Archive diagnostic counters now native-test-only. No further acceleration claim; remaining modes/languages/reload/completed-game coverage limitations preserved. Quiet release build/native/packaging verification and commit follow.
- Quiet build verification passed: full pinned NRO build, native catalog/root/reference/patch/cache regressions, loader/Python tests, real-SQLite inventory tests and all target/asset/package proofs. Commit the accepted implementation and evidence; final committed build/package identity follows. Quiet-binary hardware smoke test remains unperformed; log (5) is the accepted performance evidence.
