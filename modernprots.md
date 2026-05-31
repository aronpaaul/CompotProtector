# Что делает современные протекторы реально безопасными

> Подборка техник из публичных источников: tuts4you, exelab.ru, reverseengineering.se,
> rePacked форумы, технические блоги Oreans/VMProtect, публикации ресёрчеров.

---

## 0. Вводная: почему CompotProtector ломается быстро

Прежде чем говорить о "сильных" техниках — честный список того, **чего не хватает** в типичном самописном протекторе:

| Слабость | Что происходит |
|---|---|
| Один алгоритмический примитив (keygen) | Восстановил раз — дешифруешь всё |
| Детерминированный ключ (env_key) | Один скрипт на Python ломает любую машину |
| CRC в одном месте | 1 байт патч (`je→jmp`) убирает всё |
| Watchdog-треды рядом | 30 байт NOP — нет тредов |
| Строки в открытом виде после расшифровки | Дамп → читаешь пароль |
| IAT резолвится стандартно | GetProcAddress_by_hash реверсится за час |

Современные коммерческие протекторы решили эти проблемы. Вот как.

---

## 1. Виртуализация кода (VM-based obfuscation)

**Используют:** VMProtect, Themida/WinLicense, Code Virtualizer, Obsidium, EXECryptor 2.x

Это самая мощная техника из существующих. Вместо native x86-64 инструкций защищаемый код компилируется в **кастомный байткод** для кастомной виртуальной машины.

### Как это устроено

```
Оригинальный код:
  mov eax, [rsi+8]
  add eax, edx
  cmp eax, 0x1337
  jne .fail

После VM-компиляции:
  PUSH_IMM32  0x1337          ; кастомный опкод 0xA3
  FETCH_MEM   [rsi+8]         ; кастомный опкод 0x7F
  ADD_REG     edx             ; кастомный опкод 0x2C
  CMP_AND_JCC .vm_fail        ; кастомный опкод 0xE1
```

Каждый билд генерирует **уникальный opcode mapping**. Опкод `0xA3` в одной версии = PUSH, в другой = XOR. Статический анализ требует сначала восстановить всю ISA виртуальной машины.

### Что делает это трудным

- **Разные VM на один бинарь**: Themida ставит несколько VM-интерпретаторов с разными ISA, между которыми переключается исполнение
- **VM handlers на стеке или в heap**: код интерпретатора может быть записан в аллоцированную память, что делает breakpoint-ы на нём нестабильными
- **Mutation + VM**: некоторые опкоды VM-кода дополнительно мутируют (junk, dead branches) внутри handler-а

### Конкретно VMProtect 3.x (из публичного анализа)

```
Структура VM:
  vm_context struct {
    virtual_regs[16]   ; виртуальные регистры
    vm_stack[...]      ; VM-стек (отдельный от x86 стека)
    vm_flags           ; виртуальный EFLAGS
    dispatch_key       ; ROL'd ключ для расшифровки следующего handler
  }

dispatch_loop:
  mov al, [esi]        ; читаем VM-опкод
  rol al, cl           ; decrypt through rotating key
  jmp [handler_table + eax*4]
```

Ключ `dispatch_key` меняется на каждом шаге — нельзя поставить просто бряк на handler.

### Как ломают и почему это медленно

Единственный надёжный метод — **trace-based lifting**: запустить под Unicorn/PIN/DynamoRIO, перехватить все VM-шаги, вручную восстановить semantics. На реальный VMProtect-защищённый код это занимает от нескольких дней до нескольких недель.

Проекты типа `vmprotect-devirtualizer` и `unlicense` существуют, но работают только на старых версиях.

---

## 2. Nanomites (Armadillo, некоторые custom)

Классическая техника из середины 2000х, которую до сих пор используют в кастомных протекторах.

### Принцип

Все `je`/`jne`/`jmp` заменяются на `INT 3` (0xCC). Параллельно запускается **process debugger** — отдельный процесс, который обрабатывает каждый breakpoint:

```
Protected.exe (child)          Protector.exe (parent/debugger)
                               WaitForDebugEvent()
INT 3 на адресе X      →       получает EXCEPTION_BREAKPOINT
                               расшифровывает оригинальный jmp
                               вычисляет target
                               SetThreadContext(EIP = target)
                               ContinueDebugEvent()
продолжает с target ←
```

### Почему это сильно

1. **Нельзя подключить свой debugger** — процесс уже отлаживается родителем (один debugger за раз в Win32)
2. **Нельзя поставить обычный bpt** — все `INT 3` уже заняты nanomites
3. **Статический анализ видит только `0xCC 0xCC 0xCC`** — граф управления полностью скрыт
4. **Нельзя простым патчем заменить прыжок** — таргет зашифрован в родительском процессе

### Современный вариант: Exception-based obfuscation

Вместо `INT 3` используют `INT 1` (trap flag), `INVALID OPCODE` (0x0F0B = `ud2`), деление на ноль. SEH-обработчики восстанавливают корректный поток — в IDA/Ghidra выглядит как мёртвый код.

---

## 3. Page-level code encryption (anti-dump)

**Концепция:** код расшифрован только на одной странице памяти в каждый момент времени.

```c
// Псевдокод page encryptor
void on_page_fault(address) {
    page = align_down(address, 0x1000);
    
    // Re-encrypt previous active page
    if (active_page != NULL) {
        xor_encrypt(active_page, 0x1000, derive_key(active_page));
        VirtualProtect(active_page, 0x1000, PAGE_NOACCESS);
    }
    
    // Decrypt requested page
    xor_encrypt(page, 0x1000, derive_key(page));
    VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ);
    active_page = page;
}
```

Реализуется через **VEH (Vectored Exception Handler)** или **driver-level page fault hook**.

### Почему дамп бесполезен

- `CreateToolhelp32Snapshot` / `ReadProcessMemory` получит зашифрованные страницы
- Scylla / ImpREC не увидит настоящий код
- Единственный способ — перехватить каждый page fault (занимает часы на нормальном проекте)

### Кто использует

- Некоторые кастомные Game DRM (не публичные)
- StarForce в своё время
- Современные античиты (EAC, BE) используют похожий принцип для kernel-driver pages

---

## 4. Integrity checks встроенные в поток данных

CompotProtector делает CRC отдельно → патчишь один `je` и готово. Сильные протекторы **встраивают проверки прямо в вычисления**:

### Техника: hash-dependent constants

```c
// Нельзя убрать проверку — результат нужен для вычислений
uint32_t checksum = compute_code_hash(0x400000, 0x10000);
uint32_t key      = checksum ^ HARDCODED_MAGIC;  // key зависит от хэша
decrypt_next_stage(buffer, size, key);           // без правильного key — мусор
```

Если кто-то патчит код → `checksum` меняется → `key` неверный → следующий расшифрованный стейдж — мусор → крэш через 10 секунд, в совершенно другом месте.

### Техника: execution path checksum (Themida-style)

Каждый `call` перед выполнением обновляет скользящий CRC:

```asm
; Вместо обычного call target:
add  [g_path_crc], ebx          ; обновляем CRC текущим EBX
rol  [g_path_crc], 3
xor  [g_path_crc], NEXT_PC_IMM
call target
```

В конце функции — проверка `g_path_crc` против эталона. Патч где угодно → значение уходит в сторону → рано или поздно проверка падает. Нельзя убрать проверку не зная все места обновления.

### Техника: self-referential decryption

```
Сегмент A шифрует ключ для сегмента B.
Сегмент B шифрует ключ для сегмента C.
Сегмент C содержит проверочный хэш сегмента A.
```

Патч в A → C-хэш не совпадает, но ты узнаешь об этом не сразу, а когда выполнение дойдёт до C.

---

## 5. License verification через асимметричную криптографию

**Проблема CompotProtector:** строки (в т.ч. пароль) в расшифрованном `.ygpm`. Патчинг тривиален.

**Правильный способ:** RSA/ECDSA.

### Как это работает в WinLicense / Oreans

```
Генерация (на сервере вендора):
  private_key = ECC_GENERATE()
  license_data = { hardware_id, expiry, features }
  signature = ECC_SIGN(private_key, SHA256(license_data))
  license_file = license_data + signature

Верификация (в защищённом приложении):
  public_key = HARDCODED_IN_APP  (не секрет!)
  ok = ECC_VERIFY(public_key, SHA256(license_data), signature)
```

**Почему нельзя пропатчить:**
- `public_key` открытый — его можно извлечь, но не подделать без `private_key`
- Ты можешь NOP'нуть `jne` после verify, но тогда попадёшь в неициализированный код (features не распакованы)
- Истинный bypass — либо keygen (нужен `private_key`), либо patch VM, либо эмуляция всего пайплайна

Именно это делает современные коммерческие лицензии сложными: **математика сложнее, чем патч одного байта**.

---

## 6. Anti-debug современного уровня

Стандартный `IsDebuggerPresent` патчится за секунду. Вот что используют в реальных протекторах:

### Уровень 1 — PEB поля

```c
// Всё тривиально, но тем не менее проверяют
PEB.BeingDebugged          // = 1 под отладчиком
PEB.NtGlobalFlag           // = 0x70 под отладчиком
PEB.ProcessHeap.Flags      // = 2 vs 0x40000062
PEB.ProcessHeap.ForceFlags // = 0 vs 0x40000060
```

Мифы4You давно публиковали скрипты для x64dbg, которые автоматически патчат эти поля — большинство простых защит обходятся этим.

### Уровень 2 — Kernel-level (требует драйвера или NtQuery)

```c
// Через NtQueryInformationProcess
ULONG_PTR DebugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(),
    ProcessDebugPort,    // = 7
    &DebugPort, sizeof(DebugPort), NULL);
if (DebugPort != 0) { exit(1); }

// Через ProcessDebugObjectHandle
HANDLE DebugObject = NULL;
NtQueryInformationProcess(..., ProcessDebugObjectHandle, // = 30
    &DebugObject, ...);
if (DebugObject != NULL) { exit(1); }
```

`ProcessDebugPort` возвращает `-1` если процесс отлаживается. Многие отладчики не патчат этот kernel-объект.

### Уровень 3 — Hardware breakpoints

```c
CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    // Кто-то поставил hardware BP
    anti_debug_action();
}
```

Защита Denuvo и некоторые античиты периодически сканируют DR-регистры у всех потоков.

### Уровень 4 — Timing (RDTSC)

```asm
rdtsc
mov [t1_hi], edx
mov [t1_lo], eax
; ... проверяемый код (10-20 инструкций) ...
rdtsc
sub eax, [t1_lo]
sbb edx, [t1_hi]
cmp eax, 0x10000    ; > 65536 тактов → возможно single-step или бряк
ja  .detected
```

Под отладчиком с бряками или single-step разница в RDTSC колоссальная (100K+ тактов вместо ~20).

### Уровень 5 — Exception-based detection

```c
// Если отладчик перехватывает все исключения — обнаружен
__try {
    RaiseException(0xDEADBEEF, 0, 0, NULL);
} __except(EXCEPTION_EXECUTE_HANDLER) {
    // Если попали сюда — не под отладчиком
    continue_normally();
}
// Если под отладчиком с "pass exception to debuggee" = false — не попадём в handler
debug_detected();
```

Взаимодействие с SEH очень неочевидно под OllyDbg/x64dbg с настройками по умолчанию.

### Уровень 6 — Anti-patch ntdll (Themida делает это)

```c
// Проверяем что ntdll!NtSetContextThread не запатчен
uint8_t* fn = GetProcAddress(ntdll, "NtSetContextThread");
// Первые 4 байта должны быть: 4C 8B D1 B8  (mov r10, rcx; mov eax, N)
if (fn[0] != 0x4C || fn[1] != 0x8B || fn[2] != 0xD1 || fn[3] != 0xB8) {
    // ntdll пропатчена (inline hook) — значит кто-то перехватывает вызовы
}
```

Это ловит большинство API-хуков от отладчиков и инжекторов.

---

## 7. OLLVM и его форки — обфускация на уровне компилятора

**OLLVM (Obfuscator-LLVM)** — форк LLVM с пассами обфускации. Используют в Android NDK (некоторые мобильные игры), Snapchat, некоторые cryptocurrency wallets.

### Control Flow Flattening (CFF)

```c
// Оригинал:
if (x > 0) { A(); }
else        { B(); }
C();

// После CFF:
int state = initial_state;
while (true) {
    switch (state) {
        case 0x3A7F: A(); state = 0xC91B; break;
        case 0xF204: B(); state = 0xC91B; break;
        case 0xC91B: C(); return;
    }
}
```

Граф управления превращается в плоский switch. IDA строит граф из 3 блоков → после CFF: 50+ блоков, все через один dispatcher.

### Bogus Control Flow (BCF)

Вставляет непрозрачные предикаты — условия, которые всегда true/false, но статически неразрешимы:

```c
// Всегда true, но статически неизвестно (зависит от x²+y² >= 0, всегда так)
if ((x*x + y*y) >= 0) {   // ← опак-предикат
    // настоящий код
} else {
    // мусорный код (никогда не выполняется)
}
```

IDA видит два возможных пути, тратит время на анализ мусорной ветки.

### String Encryption Pass (HikariLLVM / PLUTO-LLVM)

```c
// Оригинал:
const char* pass = "secret";

// После pass:
uint8_t enc[] = {0x34, 0x2A, 0x18, 0x7F, 0x91, 0x45};
const char* pass = decrypt_at_runtime(enc, 6, derived_key());
```

Каждая строка шифруется уникальным ключом, derivation которого зависит от значения других переменных.

### Instruction Substitution (IS)

`a + b` → `a - (-b)` → `(a NAND b) NAND (a NAND b) NAND ...` — цепочки из логических операций вместо арифметических. Семантически эквивалентно, но IDA/Ghidra поднимает мусорный псевдокод.

---

## 8. Anti-VM / Anti-sandbox

Современные протекторы проверяют, что запущены на "настоящей" машине:

### Техники определения виртуалки

```c
// CPUID ECX bit 31 — hypervisor present
uint32_t ecx;
__cpuid(1, ...); // ecx bit 31 = 1 → гипервизор
if (ecx & (1 << 31)) { exit(); }

// CPUID leaf 0x40000000 — hypervisor vendor string
uint32_t regs[4];
__cpuid(0x40000000, regs);
// "VMwareVMware", "KVMKVMKVM", "Microsoft Hv", "XenVMMXenVMM"
if (is_vm_vendor(regs)) { exit(); }

// RDTSC spread — в VM разброс больше
uint64_t t1 = __rdtsc();
cpuid(0);
uint64_t t2 = __rdtsc();
if (t2 - t1 < 10) { exit(); }  // в VM CPUID дороже

// Реестр VMware
HKEY key;
if (RegOpenKey(HKLM, "SOFTWARE\\VMware, Inc.\\VMware Tools", &key) == 0) {
    exit();
}
```

### Environment fingerprint

Современные протекторы (в т.ч. из undergroundа) собирают фингерпринт:

```python
fingerprint_components = [
    cpuid(1),                    # CPU model
    disk_serial(),               # GetVolumeInformationA("C:\\")
    motherboard_uuid(),          # SMBIOS через GetSystemFirmwareTable
    mac_address(),               # GetAdaptersInfo
    os_install_date(),           # HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    screen_resolution(),         # GetSystemMetrics
    installed_ram(),             # GlobalMemoryStatusEx
]
hardware_id = sha256(b"".join(fingerprint_components))
```

Этот HWID потом сравнивается с лицензией. Если хоть одна компонента изменилась (переустановка ОС, замена диска) — нужна повторная активация.

---

## 9. Kernel-mode протекторы (античит-уровень)

**EasyAntiCheat, BattlEye, Vanguard** — это де-факто протекторы для игр. Техники:

### Ring 0 integrity

```
User mode:
  Загружается game.exe
  ↓
Kernel driver (signed):
  Хукает PsSetLoadImageNotifyRoutine (загрузка модулей)
  Хукает ObRegisterCallbacks (открытие хэндлов к процессу)
  Мониторит SSDT (System Service Descriptor Table) на модификации
  Сканирует память на паттерны чит-инжекторов
  ↓
Если нашёл аномалию:
  BSOD / kick из игры / ban аккаунта
```

Против такого уровня защиты нужен либо **signed kernel exploit**, либо **hypervisor bypass** (запускаешь в VM с мониторингом ring -1).

### Проверка integrity Ring 0

```c
// Проверяем что SSDT не пропатчена (любой хук ntdll видно)
for (int i = 0; i < SSDT.NumberOfServices; i++) {
    PVOID routine = SSDT.ServiceTable[i];
    // Адрес должен быть внутри ntoskrnl.exe
    if (!is_in_ntoskrnl(routine)) {
        // Найден хук — инъекция или руткит
        report_violation();
    }
}
```

---

## 10. Современные тренды 2024-2025 (из публичных источников)

### TPM-based binding

Некоторые enterprise-лицензии (Adobe, Autodesk) начали использовать TPM 2.0:

```
Ключ дешифровки зашит в TPM → выходит только через TPM_Unseal
TPM_Unseal работает только если PCR[0..7] совпадают с эталоном
  PCR = хэши BIOS + bootloader + OS + драйверов
Если кто-то патчит OS или ставит другой bootloader → PCR меняется → ключ не выходит
```

Пока TPM не взломан физически (decapping + side-channel) — это по-настоящему сильная защита.

### LLVM MBE (Mixed Boolean-Arithmetic на уровне IR)

В отличие от runtime-MBA (как в CompotProtector) — здесь MBA применяется к **LLVM IR** до кодогенерации. В результате процессор выполняет серии AND/OR/XOR/NOT вместо простых инструкций, и весь поток данных становится нечитаемым.

Пример из proGuard/NFProtect (Android):

```
; Оригинал: a = b + c
; После 3 уровней MBA:
t1 = (b | c) + (b & c) + (b ^ c)     ; эквивалентно b + c но нечитаемо
t2 = ((t1 << 1) | (t1 >> 31)) ^ MAGIC
a  = t2 - (MAGIC_INVERSE ^ t2)       ; но = a в итоге
```

### Code signing с revocation

Современные DRM (Steam, Origin) подписывают каждый билд + отзывают подписи при обнаружении пиратки:

```
binary.exe → signed by Valve cert → Steam servers verify on launch
              ↓
если сервер видит слишком много одинаковых hardware IDs с одной копией → revoke
если бинарь модифицирован → cert verification fail → не запускается offline
```

### AI-based anti-tamper (экспериментально, 2024)

Несколько статей на arxiv.org и выступлений на Black Hat описывают ML-модели, встроенные в runtime защиту. Модель обучена на профиле "нормального" исполнения (timing, memory access patterns) и детектирует аномалии (трассировку, эмуляцию, отладку) с ~95% точностью.

Пока это академично, но через 2-3 года скорее всего попадёт в коммерческие протекторы.

---

## 11. Что невозможно обойти статически

Финальный список техник, против которых нет статического решения:

| Техника | Почему не статика |
|---|---|
| VM с уникальной ISA | ISA неизвестна без запуска |
| Page-level encryption | Расшифровка только при исполнении |
| TPM-sealed keys | Ключ физически в TPM |
| Online license check | Private key на сервере |
| Nanomites | Граф управления в родительском процессе |
| Execution path checksum | Любой патч ломает последующий декрипт |
| Anti-dump + PE header erase | Дамп содержит мусор |

---

## 12. Практические советы для CompotProtector

Конкретно для CompotProtector — что добавить чтобы описанные выше атаки не работали:

### Обязательно

```
1. Перейди на асимметричную проверку пароля
   → SHA-256(input) == stored_hash
   → или лучше: Argon2id(input, salt) == stored_hash
   Тогда пароль нельзя прочитать из памяти даже после расшифровки

2. Встрой integrity check в поток вычислений
   → ck = mba(raw_key ^ crc_of_code_section, magic)
   → если код пропатчен → crc меняется → ck неверный → decrypt даёт мусор

3. Распредели watchdog-запуски по всему коду
   → не 6 вызовов подряд
   → 1 вызов в init, 1 через 500мс в другом потоке, 1 в response на пользовательский ввод

4. Разные keygen для разных слоёв
   → сейчас один keygen на всё: TLS, STRG, CODE
   → добавь второй алгоритм (ChaCha20 или AES-128-CTR) для одного из слоёв
```

### Желательно

```
5. Добавь CFF через OLLVM пасс на крекме-код
   → HikariLLVM: -mllvm -fla -mllvm -bcf
   → бесплатно, часть компиляции

6. Шифруй строки с уникальными ключами per-string
   → см. llvm-string-obfuscator или написать custom pass

7. Добавь TPM bind или HWID в env_key
   → GetVolumeInformationA("C:\\") → SerialNumber
   → вместе с CPUID → HWID = sha256(cpuid || serial || ntdll_hash)
   → bind к конкретной машине реально усиливается
```

### Долгосрочно

```
8. Рассмотри переход на VM-based obfuscation
   → openVM/ProtectionRing0 на github — open-source прообразы
   → или изучить архитектуру VMProtect (публично описана ресёрчерами)

9. Kernel driver для watchdog
   → создай простой signed driver (через EV cert или test-signing)
   → мониторь из ring 0 → пользователю невозможно NOP-нуть вызовы
```
