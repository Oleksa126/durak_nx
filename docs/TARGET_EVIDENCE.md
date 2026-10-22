> Історичний технічний звіт, не план робіт. Поточні кроки та стан — лише `IMPLEMENTATION_PLAN.md` у корені. Твердження PASS автора звіту не замінює review або hardware test.

# Target Evidence & JNI Contracts — Durak 25.0

Цей документ містить технічні первинні докази, отримані безпосередньо з офіційних бінарних файлів гри «Дурак» версії 25.0 (`ru.appscraft.durak`, versionCode `250`, APKS SHA-256 `c113... / 292f...`), що обґрунтовують відмінності від донорів, точні сигнатури JNI, типи ELF-релокацій, аналіз прав пам'яті та аудит покриття імпортів.

---

## 1. Канонічна ідентифікація бінарних файлів Durak 25.0

Усі дані вилучені з оригінальних файлів у `extracted_durak/` та верифіковані:

| Файл | Розмір (байтів) | GNU Build-ID | SHA-256 |
| :--- | :---: | :--- | :--- |
| `libsqlite3.so` | 1,797,248 | `99495662cefa74605573c8dc36a53cb1f842764d` | `6df7a75d31c417cae7e877fd7c3d190e0ac47b1f104ae0ae5501d72491b1c32c` |
| `libmain.so` | 6,696 | `c5498ab8c791f1473a54c79a9d3c5b738ff6d941` | `c11373dffa1bab427e8864a40313111de2a70367d052d87f33a9069ce8949d93` |
| `libunity.so` | 21,388,304 | `bcc661ea2046416d` | `292f89210151ba0060f77d137cd6a00a52158dc5da760d4bf106158fc9309cef` |
| `libil2cpp.so` | 31,256,704 | `d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0` | `7bc9c2e7e20c741a511e6645589db16d0fa084d79bcfc12ba1fab78931e2271c` |
| `global-metadata.dat` | 7,639,464 | Metadata v39, Magic `0xfab11baf` | `1e31859eca996941bdf0d9f00dfb3ea70716fa531bfa5ef7592473489e223d72` |

---

## 2. Первинні докази JNI контракту з Durak DEX

Аналіз виконано над `base.apk` з архіву `Durak_25.0.apks`, файл `classes5.dex`. Розпарсено заголовки, пули рядків, типів, прототипів та байткод методів за допомогою точного декодера Dalvik інструкцій ([`inspect_initjni.py`](/D:/source/MyProjects/durak-mod-switch/tools/inspect_initjni.py)).

### 2.1. Відокремлення сигнатури методу від аналізу аргументів у байткоді

#### А. Доказ статичної сигнатури методу (Method Definition)
У пулі методів `classes5.dex` (Method ID `12832`):
- **Клас:** `Lcom/unity3d/player/UnityPlayer;`
- **Назва:** `initJni`
- **Дескриптор:** `(Landroid/content/Context;ILjava/lang/String;)V`

Це підтверджується також таблицею `RegisterNatives` у `libunity.so` (RVA call-site `0xe87080`, метод RVA `0xE85C60`).

Вимога до C-прототипу за специфікацією AAPCS64:
```c
/* 5 аргументів AAPCS64: x0=env, x1=thiz, x2=context, w3=contextType, x4=cmdline */
void Unity_initJni(JNIEnv *env, jobject thiz, jobject context, jint context_type, jstring cmdline);
```

У донорі `laytonbmr_nx` метод був оголошений як 4-аргументний:
```c
/* laytonbmr_nx: помилкове визначення для Durak 25.0 */
typedef void (*fn_initJni)(void *env, void *thiz, void *context, int32_t flags);
```
Виклик донорської сигнатури залишив би вхідний регістр `x4` неініціалізованим зі сміттям стека, що спричинить segmentation fault всередині `libunity.so` при першому доступі до `jstring`.

---

#### Б. Доказ значень аргументів за байткодом виклику (Call-Site Trace)
Виклик `initJni` розташований у 2-аргументному оверлоаді `initialize(FrameLayout, String)`:

Команда верифікації (вузький fail-closed декодер, що суворо перевіряє довжину всіх опкодів і завершується з помилкою при невідомих опкодах, непідтримуваних switch/array payload або виході за межі буфера):
```bash
python tools/inspect_initjni.py
```

Фактичний декомпільований лістинг:

1. **Цільовий метод `UnityPlayer.initialize(FrameLayout, String)`:**
   ```text
   METHOD: Lcom/unity3d/player/UnityPlayer;->initialize(Landroid/widget/FrameLayout;Ljava/lang/String;)V
   CODE OFFSET: 0x22d400, REGISTERS: total=6, in=3 (v3=this, v4=FrameLayout, v5=String), outs=4
   --------------------------------------------------------------------------------
   ...
   [pc 0x0132] iget v4, v3, Lcom/unity3d/player/UnityPlayer;->mContext:Landroid/content/Context;
   [pc 0x0136] iget v0, v3, Lcom/unity3d/player/UnityPlayer;->mContextType:Lcom/unity3d/player/a/o;
   [pc 0x013a] iget v0, v0, Lcom/unity3d/player/a/o;->a:I
   [pc 0x013e] invoke-direct {v3, v4, v0, v5}, Lcom/unity3d/player/UnityPlayer;->initJni(Landroid/content/Context;ILjava/lang/String;)V
   [pc 0x0144] iget v4, v3, Lcom/unity3d/player/UnityPlayer;->mState:Lcom/unity3d/player/a/T;
   ...
   ```
   **Розбір регістрів у точці `0x013e`:**
   - `v3` = `this` (`UnityPlayer`)
   - `v4` = `mContext` (об'єкт `android.content.Context`)
   - `v0` = `mContextType.a` (ціле число `0` для `ActivityOrService`, `1` для `GameActivity`; цільове `0` для `UnityPlayerActivity`)
   - `v5` = вхідний параметр `p2` (`java.lang.String`), переданий у метод `initialize`

2. **Походження значення `v5` (`commandLine`):**
   У класі `UnityPlayerForActivityOrService`:
   ```text
   METHOD: Lcom/unity3d/player/UnityPlayerForActivityOrService;-><init>(Context, LifecycleEvents)V
   CODE OFFSET: 0x22b188, REGISTERS: total=5, in=3 (v2=this, v3=Context, v4=LifecycleEvents), outs=5
   --------------------------------------------------------------------------------
   [pc 0x0000] new-instance v0, Lcom/unity3d/player/a/d;
   [pc 0x0004] invoke-direct {v0}, Lcom/unity3d/player/a/d;-><init>()V
   [pc 0x000a] const-string v1, ""                  <-- ЯВНИЙ ПОРОЖНІЙ РЯДОК ""
   [pc 0x000e] invoke-direct {v2, v3, v4, v1, v0}, UnityPlayerForActivityOrService;-><init>(Context, LifecycleEvents, String, d)V
   [pc 0x0014] return-void
   ```
   У 4-аргументному конструкторі `UnityPlayerForActivityOrService.<init>(Context, LifecycleEvents, String, d)`:
   ```text
   CODE OFFSET: 0x22b1d4, REGISTERS: total=8, in=5 (v3=this, v4=Context, v5=LifecycleEvents, v6=String, v7=d)
   --------------------------------------------------------------------------------
   [pc 0x0060] invoke-virtual {v3, v0, v6}, Lcom/unity3d/player/UnityPlayer;->initialize(FrameLayout, String)V
   ```
   Тут регістр `v6` (`String`) безпосередньо передається як `v5` у `initialize(FrameLayout, String)`.

3. **1-аргументний оверлоад `UnityPlayer.initialize(FrameLayout)`:**
   ```text
   METHOD: Lcom/unity3d/player/UnityPlayer;->initialize(Landroid/widget/FrameLayout;)V
   CODE OFFSET: 0x22d3e4, REGISTERS: total=3, in=2 (v1=this, v2=FrameLayout), outs=3
   --------------------------------------------------------------------------------
   [pc 0x0000] const-string v0, ""                  <-- ТАКОЖ ПЕРЕДАЄТЬСЯ ""
   [pc 0x0004] invoke-virtual {v1, v2, v0}, Lcom/unity3d/player/UnityPlayer;->initialize(FrameLayout, String)V
   [pc 0x000a] return-void
   ```

**Висновок доказу:**
Статична сигнатура методу в таблиці вимагає 5 параметрів C AAPCS64 (`env`, `thiz`, `context`, `contextType`, `cmdline`). Аналіз байткоду доводить, що аргумент `commandLine` не є `NULL`, а за замовчуванням ініціалізується валідним порожнім рядком `""`.

---

### 2.2. Метод `nativeInjectEvent`: сигнатура з `deviceId`

У `classes5.dex`:
- Method ID `12852`:
  ```text
  Class:     Lcom/unity3d/player/UnityPlayer;
  Name:      nativeInjectEvent
  Signature: (Landroid/view/InputEvent;I)Z
  ```
- C AAPCS64 прототип:
  ```c
  jboolean Unity_nativeInjectEvent(JNIEnv *env, jobject thiz, jobject input_event, jint device_id);
  ```
- Вхідні регістри ARM64: `x0` = `env`, `x1` = `thiz`, `x2` = `input_event`, `w3` = `device_id` (`0`). Повертає `w0` (`jboolean`).

---

### 2.3. Розділення класів: `UnityPlayer` проти `UnityPlayerForActivityOrService`

У донорі `laytonbmr_nx` усі нативні методи викликалися як належні класу `UnityPlayer`.
У Durak 25.0 таблиця `RegisterNatives` у `libunity.so` реєструє методи на **різні класи**:

1. **Клас `com/unity3d/player/UnityPlayer`:**
   - `initJni`: `(Landroid/content/Context;ILjava/lang/String;)V` -> RVA `0xE85C60`
   - `nativeInjectEvent`: `(Landroid/view/InputEvent;I)Z` -> RVA `0xE8623C`
   - `nativeApplicationUnload`: `()V` -> RVA `0xE85E88`
   - `nativeGetMainWindowIndex`: `()I` -> RVA `0xE86E74`
   - `nativeIsAutorotationOn`: `()Z` -> RVA `0xE86A18`
   - `nativeMuteMasterAudio`: `(Z)V` -> RVA `0xE86A78`
   - `nativeSetLaunchURL`: `(Ljava/lang/String;)V` -> RVA `0xE86ADC`
   - `nativeUnitySendMessage`: `(Ljava/lang/String;Ljava/lang/String;[B)V` -> RVA `0xE8684C`
   - `nativeCrashNow`: `()V` -> RVA `0xE86ECC`
   - `nativeHidePreservedContent`: `()V` -> RVA `0xE86C98`
   - `nativeViewPaddingChanged`: `(IIIII)V` -> RVA `0xE86CE8`
   - `permissionResponseToNative`: `(JZ)V` -> RVA `0xE86C14`

2. **Клас `com/unity3d/player/UnityPlayerForActivityOrService`:**
   - `nativeRender`: `()Z` -> RVA `0xE861DC`
   - `nativePause`: `()Z` -> RVA `0xE85DC4`
   - `nativeResume`: `()V` -> RVA `0xE85E28`
   - `nativeRecreateGfxState`: `(ILandroid/view/Surface;)V` -> RVA `0xE85F3C`
   - `nativeSendSurfaceChangedEvent`: `()V` -> RVA `0xE85FA4`
   - `nativeFocusChanged`: `(Z)V` -> RVA `0xE85ED8`
   - `nativeDone`: `()Z` -> RVA `0xE85CE4`
   - `nativeConfigurationChanged`: `(Landroid/content/res/Configuration;)V` -> RVA `0xE8614C`
   - `nativeMemoryUsageChanged`: `(I)V` -> RVA `0xE85D70`
   - `nativeOnApplyWindowInsets`: `(Landroid/view/WindowInsets;)V` -> RVA `0xE85FF8`
   - `nativeGetNoWindowMode`: `()Z` -> RVA `0xE86E04`
   - `nativeSetInputArea`: `(IIII)V` -> RVA `0xE864FC`
   - `nativeSetInputSelection`: `(II)V` -> RVA `0xE8668C`
   - `nativeSetInputString`: `(Ljava/lang/String;)V` -> RVA `0xE865E4`
   - `nativeSetKeyboardIsVisible`: `(Z)V` -> RVA `0xE86584`
   - `nativeSoftInputCanceled`: `()V` -> RVA `0xE866FC`
   - `nativeSoftInputClosed`: `()V` -> RVA `0xE867F4`
   - `nativeSoftInputLostFocus`: `()V` -> RVA `0xE86754`
   - `nativeReportKeyboardConfigChanged`: `()V` -> RVA `0xE867AC`

3. **Клас `com/unity3d/player/UnityPlayerForGameActivity`:**
   - `nativeOrientationChanged`: `(II)V` -> RVA `0xE86D50`
   - `nativeUnityPlayerSetRunning`: `(Z)V` -> RVA `0xE86DB0`

**Вимога до JNI Registry:** Реєстрація та dispatch нативних методів мають індексуватися за складеним ключем `ClassName + "/" + MethodName + Signature`.

---

## 3. ELF-структура, сегменти, права пам'яті та релокації

### 3.1. Типи релокацій (Повне сканування 4 модулів)

Сканування секцій `.rela.dyn` та `.rela.plt` підтвердило наявність **виключно 4 типів релокацій**:

| Модуль | `R_AARCH64_RELATIVE` (1027) | `R_AARCH64_ABS64` (257) | `R_AARCH64_GLOB_DAT` (1025) | `R_AARCH64_JUMP_SLOT` (1026) | Всього релокацій |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `libsqlite3.so` | 2,106 | 623 | 79 | 249 | 3,057 |
| `libmain.so` | 9 | 0 | 0 | 12 | 21 |
| `libunity.so` | 33,781 | 6 | 12 | 340 | 34,139 |
| `libil2cpp.so` | 230,788 | 1,813 | 165 | 584 | 233,350 |
| **Разом** | **266,684** | **2,442** | **256** | **1,185** | **270,567** |

- Релокацій `TLS_DTPMOD64`, `TLS_DTPREL64`, `TLS_TPREL64`, `TLSDESC`: **0**.
- Релокацій `COPY`, `IRELATIVE`: **0**.
- Всі 4 типи релокацій формально підтримуються `so_util.c`.

---

### 3.2. Аналіз прав пам'яті: Очікувані проти Фактичних прав донора

У донорі `laytonbmr_nx` функція `so_finalize` ([`so_util.c:83-98`](/D:/source/MyProjects/durak-mod-switch/third_party/laytonbmr_nx/source/so_util.c#L83-L98)) виконує два проходи:
1. Прохід 0: призначає `Perm_Rx` для всіх сторінок, де `(p_flags & PF_X) != 0`.
2. Прохід 1: призначає **`Perm_Rw` для ВСІХ інших сторінок**.

**Порівняння прав для Durak 25.0:**

| Сегмент / Область | Очікувані права за ELF | Фактичні права в донорі `so_util.c` | Статус безпеки | Наслідки та ризики |
| :--- | :---: | :---: | :---: | :--- |
| `PT_LOAD (PF_X \| PF_R)` (Код) | `R-X` (`Perm_Rx`) | `R-X` (`Perm_Rx`) | **Співпадає** | Виконуваний код захищений від запису. |
| `PT_LOAD (PF_R)` (Константи, `rodata`) | `R--` (`Perm_R`) | **`RW-` (`Perm_Rw`)** | **НЕБЕЗПЕЧНО** | Донор робить read-only дані записуваними. Будь-який wild write пошкоджує рядкові константи та RTTI. |
| `PT_LOAD (PF_R \| PF_W)` (Дані, BSS) | `RW-` (`Perm_Rw`) | `RW-` (`Perm_Rw`) | **Співпадає** | Записувані сегменти даних. |
| `PT_GNU_RELRO` (Релоковані дані) | `R--` (`Perm_R` post-reloc) | **`RW-` (`Perm_Rw`)** | **НЕБЕЗПЕЧНО** | **Повний пропуск захисту RELRO!** Таблиці GOT та зміщення залишаються відкритими для модифікації у runtime. |

**Невідповідність вирівнювання (Alignment Discrepancy):**
- `libsqlite3.so` має сегментне вирівнювання `p_align = 0x10000` (64 KB).
- Донорський `so_load` шукає віртуальну пам'ять через `virtmemFindCodeMemory(size, 0x1000)` (4 KB guard/align).
- Якщо `load_virtbase` не буде вирівняно на 64 KB, відносні зміщення сегментів не відповідатимуть сторінковим вимогам MMU на Horizon.

**Вимога адаптації для Кроку 2:**
1. Оновити `so_finalize` для трирівневого мапінгу: `Perm_Rx` для коду, `Perm_R` для `rodata` та пост-релокаційного `PT_GNU_RELRO`, `Perm_Rw` виключно для `data`/`bss`.
2. Враховувати `max(p_align)` при резервуванні `virtmemFindCodeMemory` (64 KB для `libsqlite3.so`).
3. Коректність Horizon mapping обов'язково підтверджувати через hardware log (`durak_nx.log`).

---

### 3.3. Виявлення конструкторів: Dynamic Tags проти Section Headers

| Модуль | `DT_INIT` | `DT_INIT_ARRAY` (RVA) | `DT_INIT_ARRAYSZ` (bytes) | Кількість ctor | Секція `.init_array` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `libsqlite3.so` | Немає | Немає | Немає | 0 | Відсутня |
| `libmain.so` | Немає | Немає | Немає | 0 | Відсутня |
| `libunity.so` | Немає | `0x14500d0` | `0xfd0` | **506** | `sh_addr=0x14500d0, sh_size=0xfd0` |
| `libil2cpp.so` | Немає | `0x1bd9d28` | `0xb0` | **22** | `sh_addr=0x1bd9d28, sh_size=0xb0` |

- Обидва модулі мають збіг між тегами `PT_DYNAMIC` та секціями.
- У Кроці 2 `so_execute_init_array` буде адаптовано для першочергового читання `DT_INIT_ARRAY` з `PT_DYNAMIC`.

---

### 3.4. Підсистема синхронізації та Clock Domain: `pthread_cond_timedwait`

В інвентарі Durak 25.0 присутні такі функції синхронізації (Wave 6):
- `pthread_cond_init`, `pthread_cond_destroy`, `pthread_cond_wait`, `pthread_cond_timedwait`, `pthread_cond_signal`, `pthread_cond_broadcast`
- `pthread_condattr_init`, `pthread_condattr_destroy`, `pthread_condattr_setclock`

**Критичний дефект донора `laytonbmr_nx`:**
1. **Змішування годинників (Clock Domain Confusion):**
   - За специфікацією POSIX, за замовчуванням `pthread_cond_t` прив'язаний до `CLOCK_REALTIME`.
   - Caller може викликати `pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)` для прив'язки condvar до монотонного годинника.
   - Донор безумовно трактує переданий `abstime` як монотонний час або використовує фіксовану 16-мс затримку. Якщо caller передав абсолютний дедлайн за `CLOCK_REALTIME` (епоха 1970, наприклад `1.7e9` секунд), а код порівнює його з `CLOCK_MONOTONIC` (секунди від старту консолі), результат порівняння є фатально некоректним.
2. **Штучне повернення ETIMEDOUT (16 ms Truncation):**
   - Донор обмежує очікування 16 мілісекундами і безумовно повертає `ETIMEDOUT`, навіть коли caller встановив дедлайн через кілька секунд. Це ламає внутрішні таймери та тайм-аути воркерів Unity.
3. **Семантика повернення при сигналі:**
   - Повернення після сигналу (`pthread_cond_signal`/`broadcast`) або допустимого spurious wakeup повинно негайно повертати `0` caller-у, а не чекати до закінчення дедлайну.

---

## 4. Аудит та класифікація біндінгів 362 сильних символів

Звіт згенеровано інструментом [`tools/audit_symbols.py`](/D:/source/MyProjects/durak-mod-switch/tools/audit_symbols.py). Повні структуровані дані зафіксовано в [`docs/symbol_classification_report.json`](/D:/source/MyProjects/durak-mod-switch/docs/symbol_classification_report.json).

### 4.1. Зведення за категоріями

- **Покриття назв символів (Name Match Coverage):** **359 / 362 (99.17%)**. (Назви символів присутні в таблицях донора, але це **не свідчить про готовність чи безпечність біндінгів**).

| Роль біндінгу | Кількість символів | Відсоток | Опис та статус верифікації |
| :--- | :---: | :---: | :--- |
| **TRANSLATION_SHIM** (Адаптивні трансляційні шими) | **101** | **27.90%** | Адаптивні шими донора, що виконують конвертацію бінарних структур або підсистем (`stat_fake`, `readdir_fake`, `fakefd_*`, `__android_log_print`, `mmap`, `pthread_create`, `sysconf_pass` тощо). Більшість мають статус `UNVERIFIED`. |
| **DIRECT_BINDING** (Прямі біндінги та pass-through) | **165** | **45.58%** | Пряма передача функцій toolchain newlib/libm/libnx або прямі pass-through обгортки (`sin`, `malloc`, `memcpy`, `strlen`, `clock_gettime`, `gettimeofday`, `ftruncate_stub`). Статус `UNVERIFIED`. |
| **STUB_OR_DUMMY** (Заглушки та no-op біндінги) | **93** | **25.69%** | Функції-заглушки з фіктивним поверненням константи (`return 0`, `return -1`, `return NULL`, `(void*)1`), `ENOSYS` або no-op логікою. Мають відомі критичні обмеження (див. нижче). |
| **MISSING** (Повністю відсутні в донорі) | **3** | **0.83%** | `asprintf`, `fchown`, `mremap` (усі 3 — виключно для `libsqlite3.so`). Статус `NOT_APPLICABLE`. |
| **РАЗОМ** | **362** | **100.00%** | Повний інвентар Strong Symbols. |

**Розподіл за статусом верифікації (окреме поле):**
- **UNVERIFIED (Неперевірено):** 356 символів (98.34%) — не мають підтвердженого runtime-тесту під Durak 25.0, не можуть вважатися готовими до запуску без верифікації;
- **VERIFIED (Верифіковано):** 3 символи (0.83%) — підтверджено точний 128-byte Bionic AArch64 layout (`stat`, `fstat`, `lstat`);
- **NOT_APPLICABLE (Не застосовується):** 3 символи (0.83%) — відсутні в таблицях символи (`asprintf`, `fchown`, `mremap`).

---

### 4.2. Критичні обмеження донорських заглушок (STUB_OR_DUMMY)

Наступні біндінги донора становлять потенційний ризик і не можуть вважатися готовими без верифікації з боку caller:

1. **`pthread_sigmask` -> `pthread_sigmask_fake`:**
   - Реалізація: `(void)how; (void)set; (void)old; return 0;`.
   - Обмеження: Повністю ігнорує маску сигналів потоку. Для потоків GC або Unity, що очікують блокування сигналів через `sigmask`, маска залишається незмінною.
2. **`fcntl` -> `fcntl_stub`:**
   - Реалізація: `return 0;`.
   - Обмеження: Повністю ігнорує команди `F_GETFL`, `F_SETFL` (неблокуючий режим сокетів/файлів) та `F_SETLK` (блокування файлів SQLite). Якщо caller очікує бітову маску прапорців від `F_GETFL`, він отримує `0`.
3. **`truncate` -> `truncate_stub`:**
   - Реалізація: `return 0;`.
   - Обмеження: Повідомляє про успіх, але не змінює розмір файлу на файловій системі. Це може пошкодити логіку ініціалізації журналів SQLite або збережень Unity.
4. **`sigaction` -> `sigaction_stub` (також `signal`):**
   - Реалізація: `return 0;`.
   - Обмеження: Не реєструє обробник сигналів. Сигнали crash-handler або GC не перехоплюються через POSIX-інтерфейс.
5. **Мережеві сокети (`socket`, `connect`, `send`, `recv` тощо):**
   - Реалізація: оффлайн-заглушки, що повертають `-1`, `0` або `ENETDOWN`. Для першого кадру офлайн-гри це безпечно, але не є повноцінною реалізацією мережевого стека.

---

### 4.3. Відсутні символи (MISSING): Гіпотези та статус перевірки

Усі 3 відсутні символи викликаються виключно з `libsqlite3.so`:

1. **`asprintf` (Wave 2, 1 сайт `0x1c3850`):**
   - Статус: **Підтверджено**. Стандартне форматування через `malloc`. Реалізовано в `9db8020:source/android_shims.c` (попередня реалізація, архівована поза робочим деревом).
2. **`fchown` (Wave 5, 2 сайти `0x1c4910`, `0x1c3788`):**
   - Статус: **Гіпотеза (Assumption)**. Припускається, що `fchown` є no-op на Switch через відсутність POSIX user permissions на FAT32/exFAT. Потребує перевірки, чи SQLite перевіряє код повернення.
3. **`mremap` (Wave 5, 2 сайти `0x1c4970`, `0x1c3788`):**
   - Статус: **Гіпотеза (Assumption)**. Припускається, що при поверненні `MAP_FAILED` та `errno = ENOSYS` SQLite коректно відмовляється від mmap і переходить на звичайний read/write. Ця поведінка є стандартною для SQLite, але потребує підтвердження під час ініціалізації бази даних на залізі.

---

## 5. Докази патчу ChoreographerBase::Get (Усунення блокуючого очікування кадру 142/143)

### 5.1. Канонічна ідентифікація бінарного файлу та сайту
- **Бібліотека:** `libunity.so` (Unity 6000.0.58f2, arm64-v8a)
- **Розмір:** `21,388,304` байт
- **GNU Build-ID:** `bcc661ea2046416d`
- **SHA-256:** `292f89210151ba0060f77d137cd6a00a52158dc5da760d4bf106158fc9309cef`
- **Функція-фабрика:** `ChoreographerBase::Get`
- **RVA:** `0x00e7261c`

### 5.2. Вичерпний аудит викликів (Call-Site Audit)
Автоматичний пошук усіх прямих гілок (`bl`, `b`), релокацій та покажчиків у секціях `.text`, `.rodata`, `.data`, `.data.rel.ro` обох бібліотек `libunity.so` та `libil2cpp.so` показав:
- `libil2cpp.so`: 0 посилань.
- `libunity.so`: Рівно **2** місця виклику в усьому коді, 0 релокацій, 0 покажчиків у таблицях даних.

Обидва місця виклику містять перевірку поверненого значення на `NULL` (`cbz x0`) і штатні гілки fallback:

1. **Caller 1 (RVA `0x00e7258c`):**
   ```armasm
   0x00e7257c: sub   sp, sp, #0x30
   0x00e72580: str   d8, [sp, #0x10]
   0x00e72584: str   x30, [sp, #0x18]
   0x00e72588: stp   x20, x19, [sp, #0x20]
   0x00e7258c: bl    #0xe7261c              ; x0 = ChoreographerBase::Get()
   0x00e72590: cbz   x0, #0xe72608          ; [ОПКОД 0xb40003c0] ЯКЩО x0 == NULL -> перехід до епілогу!
   ... (гілка x0 != NULL: опитування vsync частоти та запис у 0x1557228/230/238) ...
   0x00e72608: ldp   x20, x19, [sp, #0x20]  ; відновлення регістрів
   0x00e7260c: ldr   x30, [sp, #0x18]
   0x00e72610: ldr   d8, [sp, #0x10]
   0x00e72614: add   sp, sp, #0x30
   0x00e72618: ret                          ; чистий вихід без помилок і без витоку ресурсів
   ```

2. **Caller 2 (RVA `0x00e72770`):**
   ```armasm
   0x00e7276c: str   x30, [sp, #-0x10]!
   0x00e72770: bl    #0xe7261c              ; x0 = ChoreographerBase::Get()
   0x00e72774: cbz   x0, #0xe72788          ; [ОПКОД 0xb40000a0] ЯКЩО x0 == NULL -> перехід до епілогу!
   0x00e72778: ldr   x8, [x0]
   0x00e7277c: ldr   x1, [x8, #0x18]
   0x00e72780: ldr   x30, [sp], #0x10
   0x00e72784: br    x1
   0x00e72788: ldr   x30, [sp], #0x10       ; відновлення LR
   0x00e7278c: ret                          ; чистий вихід
   ```

### 5.3. Instruction Fingerprint & Патч
Патч замінює перші 2 інструкції `ChoreographerBase::Get` на повернення `NULL` (`x0 = 0`):

| Зсув (RVA) | Оригінальна інструкція | Оригінальний опкод | Цільова інструкція | Цільовий опкод | Призначення |
| :--- | :--- | :---: | :--- | :---: | :--- |
| `0x00e7261c` | `sub sp, sp, #0x50` | `0xd10143ff` | `movz x0, #0` | `0xd2800000` | Встановлення поверненого покажчика в NULL (x0 = 0) |
| `0x00e72620` | `stp x30, x21, [sp, #0x30]` | `0xa90357fe` | `ret` | `0xd65f03c0` | Негайне повернення з функції (ret до caller LR) |

Контекстні інструкції для перевірки цілісності (RVA `0x00e72624` - `0x00e72630`):
- `0x00e72624`: `0xa9044ff4` (`stp x20, x19, [sp, #0x40]`)
- `0x00e72628`: `0xd53bd054` (`mrs x20, tpidr_el0`)
- `0x00e7262c`: `0xf9401688` (`ldr x8, [x20, #0x28]`)
- `0x00e72630`: `0xf90017e8` (`str x8, [sp, #0x28]`)

### 5.4. Fail-Closed реалізація та верифікація
1. Застосовується в staging-буфері `mod->load_base` ДО виклику `so_finalize` (дозволено запис, відсутній конфлікт із W^X).
2. Двоетапна перевірка: якщо будь-яка інструкція не збігається з `0xd10143ff` або `0xa90357fe`, модуль негайно зупиняється з помилкою без зміни жодного байта.
3. Post-check у CodeMemory (`RX`) після `so_finalize`: перевіряє, що в пам'яті виконання активні `0xd2800000` та `0xd65f03c0`.
4. Тестове покриття:
   - Native C: `test_durak_unity_choreographer_patching` у `tests/test_loader_linker_native.c` (тести 10/10 PASS).
   - Python: `test_12_durak_unity_choreographer_patch_contract` у `tests/test_step2_loader_harness.py` (тести 12/12 PASS).

---

## 6. Первинні докази VSync Wait Loop та Switch 60 Hz Frame Pacing (`libunity.so` Build-ID `bcc661ea2046416d`)

### 6.1. Аналіз циклу очікування (Wait Loop) у `libunity.so`
За даними `durak_nx (15).log`, головний потік зависає на адресі `libunity.so + 0xe7247c`, condition object `0x9fe459e0`.
Дизасемблювання функції `WaitForVsyncFrame` (RVA `0x00e72440` – `0x00e7249c`):
```armasm
0x00e72440: str      x30, [sp, #-0x30]!
0x00e72444: stp      x22, x21, [sp, #0x10]
0x00e72448: stp      x20, x19, [sp, #0x20]
0x00e7244c: adrp     x20, #0x1557000
0x00e72450: add      x20, x20, #0x1c4          ; x20 = 0x15571c4 (&g_vsync_mutex)
0x00e72454: mov      x19, x0                   ; x19 = target_frame
0x00e72458: mov      x0, x20
0x00e7245c: bl       #0x1401b40                ; pthread_mutex_lock(&g_vsync_mutex)
0x00e72460: adrp     x22, #0x1557000
0x00e72464: ldr      x21, [x22, #0x220]         ; x21 = [0x1557220] (g_vsync_frame_counter)
0x00e72468: cmp      x21, x19                   ; перевірка: counter >= target_frame?
0x00e7246c: b.ge     #0xe72480                  ; якщо так -> вихід з циклу
0x00e72470: add      x0, x20, #0x28             ; x0 = 0x15571c4 + 0x28 = 0x15571ec (&g_vsync_cond)
0x00e72474: mov      x1, x20                    ; x1 = &g_vsync_mutex
0x00e72478: bl       #0x1402020                ; pthread_cond_wait(&g_vsync_cond, &g_vsync_mutex)
0x00e7247c: b        #0xe72464                  ; повторна перевірка умови циклу (LR = 0x00e7247c!)
0x00e72480: adrp     x0, #0x1557000
0x00e72484: add      x0, x0, #0x1c4
0x00e72488: bl       #0x1401b50                ; pthread_mutex_unlock(&g_vsync_mutex)
0x00e7248c: mov      x0, x21                    ; повернення поточного лічильника
0x00e72490: ldp      x20, x19, [sp, #0x20]
0x00e72494: ldp      x22, x21, [sp, #0x10]
0x00e72498: ldr      x30, [sp], #0x30
0x00e7249c: ret
```
- **LR після `pthread_cond_wait`:** рівно `0x00e7247c` — 100% збіг із дампом watchdog у `durak_nx (15).log`.
- **Об'єкт умови:** `0x15571ec` (`0x15571c4 + 0x28`), м'ютекс: `0x15571c4`.
- **Лічильник кадрів:** `0x1557220` (`uint64_t g_vsync_frame_counter`).

### 6.2. Call-Site у рушії Unity Frame Pacer (RVA `0x00e57270` – `0x00e57404`)
Unity викликає `WaitForVsyncFrame` у головному циклі рендерингу:
```armasm
0x00e57378: mov      x8, sp
0x00e5737c: bl       #0xe724f8                  ; bl GetFrameStats(sp)
0x00e57380: ldr      x8, [sp, #8]               ; x8 = поточне значення лічильника vsync
0x00e57384: cmp      x8, x20                    ; порівняння з цільовим кадром x20
0x00e57388: b.ge     #0xe573fc                  ; якщо counter >= target -> ПРОПУСТИТИ очікування!
...
0x00e573d4: bl       #0xe72440                  ; інакше: bl WaitForVsyncFrame(target)
```

### 6.3. Функція інкременту та broadcast: `Unity_OnVsync` (RVA `0x00e724a0`)
```armasm
0x00e724a0: str      x30, [sp, #-0x20]!
0x00e724a4: stp      x20, x19, [sp, #0x10]
0x00e724a8: adrp     x20, #0x1557000
0x00e724ac: add      x20, x20, #0x1c4          ; x20 = &g_vsync_mutex (0x15571c4)
0x00e724b0: mov      x19, x0                   ; x19 = timestamp_nanos
0x00e724b4: mov      x0, x20
0x00e724b8: bl       #0x1401b40                ; pthread_mutex_lock(&g_vsync_mutex)
0x00e724bc: adrp     x9, #0x1557000
0x00e724c0: adrp     x8, #0x1557000
0x00e724c4: adrp     x11, #0x1557000
0x00e724c8: ldr      x12, [x9, #0x220]         ; x12 = [0x1557220] (старий counter)
0x00e724cc: ldr      x10, [x8, #0x228]         ; x10 = [0x1557228] (попередній cur_ts)
0x00e724d0: str      x19, [x8, #0x228]         ; [0x1557228] = новий timestamp_nanos
0x00e724d4: mov      x0, x20
0x00e724d8: add      x8, x12, #1               ; x8 = старий counter + 1
0x00e724dc: str      x10, [x11, #0x230]        ; [0x1557230] = попередній timestamp (prev_ts)
0x00e724e0: str      x8, [x9, #0x220]          ; [0x1557220] = counter + 1!
0x00e724e4: bl       #0x1401b50                ; pthread_mutex_unlock(&g_vsync_mutex)
0x00e724e8: add      x0, x20, #0x28             ; x0 = &g_vsync_cond (0x15571ec)
0x00e724ec: ldp      x20, x19, [sp, #0x10]
0x00e724f0: ldr      x30, [sp], #0x20
0x00e724f4: b        #0x1402040                ; pthread_cond_broadcast(&g_vsync_cond)
```

### 6.4. Джерела викликів `Unity_OnVsync` (`0x00e724a0`) в оригінальному Android APK
Вичерпне сканування релокацій та прямого розгалуження в `libunity.so` виявило рівно три джерела викликів:
1. `0x00e78e90`: `JavaChoreographer::FrameCallback::doFrame(long frameTimeNanos)`
2. `0x00e7963c`: `NativeChoreographer::frameCallback(long frameTimeNanos, void *data)`
3. `0x00e79694`: `NativeChoreographer::frameCallback64(int64_t frameTimeNanos, void *data)`

### 6.5. Вплив NULL-патчу Choreographer та необхідність Switch Frame Pacer
- Повернення `NULL` з `ChoreographerBase::Get` запобігло дедлоку конструктора `JavaChoreographer` на старті (успішно пройдено кадри 0-142 та сплеш-логотип).
- Проте через відсутність зареєстрованого Choreographer колбеки ОС Android (`doFrame` / `frameCallback`) взагалі не надходили.
- Внаслідок цього функція `Unity_OnVsync` (`0x00e724a0`) ніколи не викликалася, лічильник `0x1557220` залишався рівним 0, а condvar `0x15571ec` ніколи не пробуджувався.
- Рушій Unity у кадрі 143 викликав `WaitForVsyncFrame(target)`, і головний потік завис у `pthread_cond_wait`.
- **Чому заборонено bypass циклу (`ret`) або підстановку довільного лічильника:**
  Функція `GetFrameStats` (`0x00e724f8`) обчислює:
  $$\Delta t = (t_{\text{cur}} - t_{\text{prev}}) \times 10^{-9}\text{ сек}$$
  Прямий bypass залишив би часові мітки нульовими або неактуальними, що зруйнувало б фізику рушія, внутрішні таймери та анімації Unity.
- **Узгоджене архітектурне рішення:**
  Фоновий потік `durak_frame_pacer` (`source/frame_pacer.c`, `include/frame_pacer.h`), який:
  1. Має власний блок Bionic TLS (`install_bionic_tls`) для захисту стекових канарок AAPCS64.
  2. Запускається перед циклом рендерингу із частотою 60.0 Гц (інтервал 16,666,667 нс).
  3. На кожному такті викликає оригінальну функцію `Unity_OnVsync` (`0x00e724a0`) рушія з монотонними наносекундними мітками `clock_gettime(CLOCK_MONOTONIC)`.
  4. Під час ініціалізації праймує два початкові імпульси (`t0 - 16.6ms`, `t0`), гарантуючи попереднє калібрування `deltaTime = 16.6ms` до першого запиту рушія.
  5. У `source/main.c` замінено жорсткий сон 16.6ms на мінімальний `svcSleepThread(1000000ULL)` (1ms yield), делегуючи точний пейсинг рушію та фоновому VSync потоку.

---

## 7. Вхідні дані (Touch & Pointer Input) для Durak 25.0

### 7.1. Структурні RVA методів `UnityEngine.Input` у Durak 25.0 `libil2cpp.so`
Бінарний файл `extracted_durak/libil2cpp.so` (GNU Build-ID `d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0`, розмір 31,256,704 байти).
Аналіз ELF-сегментів: PT_LOAD 1 має `p_vaddr = 0xb1cd30`, `p_offset = 0xb18d30` ($\Delta = \text{0x4000}$).
Тому файл на диску має зміщення `foff = RVA - 0x4000`.

| Метод `UnityEngine.Input` | Віртуальна адреса (RVA) | Зміщення у файлі ELF | Оригінальні інструкції (insn0, insn1) | Призначення |
| :--- | :---: | :---: | :---: | :--- |
| `get_touchCount` | `0x0184408c` | `0x0184008c` | `0xa9bf4ffe` `0xd0002cf3` | Кількість активних точок дотику (0 або 1) |
| `GetTouch` | `0x01843998` | `0x0183f998` | `0xd101c3ff` `0xa90557fe` | Отримання структури `Touch` за індексом |
| `get_mousePosition` | `0x01843bb4` | `0x0183fbb4` | `0xd10083ff` `0xa9014ffe` | Координати віртуального курсора / дотику (Vector3) |
| `GetMouseButton` | `0x018438e4` | `0x0183f8e4` | `0xf81e0ffe` `0xa9014ff4` | Стан утримання кнопки миші 0 (bool) |
| `GetMouseButtonDown` | `0x01843920` | `0x0183f920` | `0xf81e0ffe` `0xa9014ff4` | 1-кадровий фронт натискання кнопки миші 0 |
| `GetMouseButtonUp` | `0x0184395c` | `0x0183f95c` | `0xf81e0ffe` `0xa9014ff4` | 1-кадровий фронт відпускання кнопки миші 0 |
| `get_touchSupported` | `0x01844020` | `0x01840020` | `0xa9bf4ffe` `0xd0002cf3` | Ознака підтримки тачскріну (завжди 1) |
| `get_mousePresent` | `0x01843fb4` | `0x0183ffb4` | `0xa9bf4ffe` `0xf0002cf3` | Ознака наявності миші/курсора (завжди 1) |

*Примітка щодо донорських зміщень:* У `laytonbmr_nx` використовувалися RVA `0x1bf48f4`, `0x1bf4100` тощо, які належать зовсім іншому випуску Unity 2018 і є категорично несумісними з Unity 6 Durak 25.0.

### 7.2. Розкладка структури `UnityEngine.Touch` у `global-metadata.dat` v39
Повне сканування полів типу `UnityEngine.Touch` у метаданих гри (`global-metadata.dat` v39):
- Загальний розмір структури: рівно 68 байтів (`0x44`).
- Розкладка полів:
  * `+0x00`: `int32_t m_FingerId`
  * `+0x04`: `Vector2 m_Position` (`x` @ `0x04`, `y` @ `0x08`)
  * `+0x0c`: `Vector2 m_RawPosition` (`x` @ `0x0c`, `y` @ `0x10`)
  * `+0x14`: `Vector2 m_PositionDelta` (`dx` @ `0x14`, `dy` @ `0x18`)
  * `+0x1c`: `float m_TimeDelta` (0.016666f)
  * `+0x20`: `int32_t m_TapCount` (1)
  * `+0x24`: `int32_t m_Phase` (0=Began, 1=Moved, 2=Stationary, 3=Ended, 4=Canceled)
  * `+0x28`: `int32_t m_Type` (0=Direct)
  * `+0x2c`: `float m_Pressure` (1.0f)
  * `+0x30`: `float m_maxPressure` (1.0f)
  * `+0x34`: `float m_Radius` (1.0f)
  * `+0x38`: `float m_RadiusVariance` (0.0f)
  * `+0x3c`: `float m_AltitudeAngle` (1.5707963f = $\pi / 2$)
  * `+0x40`: `float m_AzimuthAngle` (0.0f)

### 7.3. Специфікація AAPCS64 ABI для хуків
1. **`GetTouch`**: За стандартом AAPCS64 структури розміром понад 16 байтів, що не є Homogeneous Floating-point Aggregates (HFA), повертаються непрямо: адреса буфера результату передається у спеціальному регістрі `x8` (`sret`). У коді виклику `libil2cpp.so` (`0x01843998`) вхідний `x8` зберігається у `x19`. Повернення значення структури за значенням у C (`return t;`) генерує запис у `*x8` згідно з ABI.
2. **`get_mousePosition`**: Повертає `UnityEngine.Vector3` (3 значення `float` по 4 байти = 12 байтів, HFA). Відповідно до розділу 6.4.2 AAPCS64 повертається безпосередньо у регістрах з плаваючою крапкою `s0`, `s1`, `s2`. Дизасемблювання підтверджує генерацію `ldp s0, s1, [sp]; ldr s2, [sp, #8]; ret`.
3. **Скалярні методи**: `get_touchCount`, `GetMouseButton*`, `get_touchSupported`, `get_mousePresent` повертаються у регістрі `w0`.

### 7.4. Архітектура хуків та контракт відпускання (Release Frame)
- **Fail-closed верифікація:** Усі 8 точок інструкцій перевіряються перед записом через `so_patch_code`. Якщо хоча б одна інструкція не збігається, патчинг негайно переривається.
- **Трампліни ARM64:**
  ```armasm
  ldr x16, #8
  br  x16
  .quad <hook_function_address>
  ```
- **Контракт події відпускання для Unity EventSystem:**
  Unity `TouchInputModule` обробляє `IPointerClickHandler.OnPointerClick` лише тоді, коли подія переходить у стан `TouchPhase.Ended` при `touchCount == 1`. Якщо скинути `touchCount` у 0 одночасно з відпусканням пальця, Unity вважає, що дотик зник (canceled/lost), і клік по кнопці не відбувається. Тому хук `nx_input_hook_update` підтримує `touchCount == 1`, `phase == TouchPhase.Ended` та `GetMouseButtonUp(0) == 1` рівно протягом 1 кадру з координатами точки відпускання, і лише в наступному кадрі переходить у стан `Idle` (`count == 0`).
- **Перетворення простору координат:**
  Сенсорна панель Nintendo Switch повертає координати у просторі 1280x720 з початком координат у верхньому лівому кутку. Unity очікує координати екрана з початком у нижньому лівому кутку. Формула перетворення:
  $$u_x = \text{raw}_x \times \frac{W_{\text{screen}}}{1280.0}$$
  $$u_y = H_{\text{screen}} - \text{raw}_y \times \frac{H_{\text{screen}}}{720.0}$$
  Для портативного режиму (1280x720):
  $$u_x = \text{raw}_x, \quad u_y = 720.0 - \text{raw}_y$$
