# CompotProtector — Полный разбор защиты

> **Цель:** crackme `crackme-encrypted.exe` (PE32+, x64, Windows)  
> **Пакер:** CompotProtector (кастомный, Rust-based)  
> **Пароль:** `claudecoding4.8model`  
> **Инструменты:** pefile, capstone, unicorn, Python

---

## 1. Начальный анализ PE-структуры

### 1.1 Общий вид файла

```
Размер:     147 456 байт (0x24000)
Тип:        PE32+ (x64)
ImageBase:  0x140000000
EntryPoint: RVA 0x19000  ← необычно, в .hjt секции
TLS:        есть, callback на RVA 0x19dd4
```

Первое что бросается в глаза — точка входа находится **не в стандартной .text секции**, а в `.hjt`. Это первый признак упаковщика.

### 1.2 Карта секций

| Секция     | VMA     | VSZ    | RSZ    | Назначение                            |
|------------|---------|--------|--------|---------------------------------------|
| `.zwhr`    | 0x1000  | 0xF550 | 0xF600 | Целевой .text, нули на диске          |
| `.rsk`     | 0x11000 | 0x2D0  | 0x400  | Данные                                |
| `.ygpm`    | 0x12000 | 0xED8  | 0x1000 | STRG-шифрованные строки и код         |
| `.eoqyt`   | 0x13000 | 0x534  | 0x600  | Данные рантайма                       |
| `.inbws`   | 0x14000 | 0x570  | 0x600  | Данные рантайма                       |
| `.njmsu`   | 0x15000 | 0xB70  | **0x0**| BSS — заполняется в рантайме          |
| `.rkwtotp` | 0x16000 | 0xBCC  | 0xC00  | IAT (таблица импорта)                 |
| `.icjcdc`  | 0x17000 | 0x10   | 0x200  | Заглушка                              |
| `.yli`     | 0x18000 | 0x84   | 0x200  | Данные                                |
| `.hjt`     | 0x19000 | 0x11220| 0x11400| Зашифрованный EP + TLS + пейлоад      |

Ключевые наблюдения:
- `.zwhr` — **нули на диске** (RSZ≠0 но заполнен нулями), записывается пакером в рантайме
- `.njmsu` — **RSZ=0**, это BSS-сегмент, тоже заполняется в рантайме
- `.hjt` — **14 секций в одном**: зашифрованный EP-стаб + plaintext-код пакера + зашифрованный пейлоад
- `.rkwtotp` — имя обфусцировано, это IAT

---

## 2. TLS Callback — точка входа пакера

### 2.1 Почему TLS, а не EP?

Пакер регистрирует TLS callback (указатель в `.hjt` на RVA 0x19dd4), который **выполняется ДО** вызова OEP. Это позволяет расшифровать EP-стаб до того, как процессор попадёт на адрес точки входа.

```
Порядок выполнения Windows x64:
  1) Загрузчик映射образ
  2) TLS callback (RVA 0x19dd4) → расшифровывает .hjt[0:0xDD4]
  3) OEP (RVA 0x19000) = начало расшифрованного EP-стаба
```

### 2.2 Что делает TLS callback

```asm
; Псевдокод TLS callback
cmp edx, 1               ; только DLL_PROCESS_ATTACH
jne .exit

lea rdi, [rip + 0x2E9]   ; rdi = &data_struct @ RVA 0x1A0E0
mov rbx, [PEB.ImageBaseAddress]
call compute_env_key     ; eax = env_key (машинно-специфичный)
xor [rdi + 0xA8], eax    ; модифицируем raw cipher key (low 32 bits)
mov rcx, [rdi + 0xA8]    ; rcx = modified_key
mov edx, 0x53454c46      ; magic "SELF"
call MBA                 ; rcx = mba(modified_key, 0x53454c46)
mov r8, rax              ; r8 = cipher_key
lea rcx, [rbx + 0x19000] ; ptr to .hjt[0]
mov edx, [rdi + 0x88]    ; size = 0xDD4
xor r9d, r9d             ; offset = 0
call decrypt_loop        ; расшифровываем .hjt[0:0xDD4] на месте
```

---

## 3. Криптографический слой — keygen + MBA

Это **самая важная часть** для понимания всей защиты. Пакер использует два механизма:

### 3.1 Stream-cipher (keygen)

Функция `keygen(word_idx, key)` вырабатывает 64-битное слово ключевого потока. По структуре — упрощённый ChaCha-блок с 4 переменными и 8 итерациями quarter-round.

```python
M = 0xFFFFFFFFFFFFFFFF

# Константы (ROR64 известных паттернов)
C0 = rol64(0xeae6dedacae0e6ca, 7)
C1 = rol64(0xedac8dee4c2dcc8d, 11)
C2 = rol64(0xae4c2d8f2cecadcc, 19)
C3 = rol64(0xe8cae6e8cac8c4f2, 23)
C4 = rol64(0xe0acf1bbcdcbfa53, 13)

def quarter_round(r8, r9, r10, rax):
    r8  = (r8 + r9)  & M;  r9  = rol64(r9, 13) ^ r8;  r8 = rol64(r8, 32)
    r10 = (r10 + rax)& M;  rax = rol64(rax,16) ^ r10
    r8  = (r8 + rax) & M;  rax = rol64(rax,21) ^ r8
    r10 = (r10 + r9) & M;  r9  = rol64(r9, 17) ^ r10; r10 = rol64(r10, 32)
    return r8, r9, r10, rax

def keygen(word_idx, key):
    r14 = (key ^ C4) & M
    r8  = (key ^ C0) & M
    r9  = (r14 ^ C1) & M
    r10 = (key ^ C2) & M
    rax = ((r14 ^ C3) ^ word_idx) & M

    for _ in range(2): r8,r9,r10,rax = quarter_round(r8,r9,r10,rax)
    r8 ^= word_idx
    rax ^= rol64(0x40000000, 29)           # XOR константой

    for _ in range(2): r8,r9,r10,rax = quarter_round(r8,r9,r10,rax)
    r8  ^= rol64(0x10000000, 31)
    r10 ^= 0xFF                            # XOR только младшего байта

    for _ in range(4): r8,r9,r10,rax = quarter_round(r8,r9,r10,rax)

    r8 = (r8 ^ r9)  & M                   # финальное смешивание
    r8 = (r8 ^ r10) & M
    rax = (rax ^ r8) & M
    return rax
```

**Критический баг** в реверсе (найден в процессе): финальный шаг `r8 = (r8^r9)^(r8^r10) = r9^r10` — это **неправильно**. Правильный порядок: сначала `r8 ^= r9`, потом `r8 ^= r10` (два последовательных XOR, а не один с разложением). Верификация через Unicorn подтвердила исправленный вариант.

#### Decrypt loop

```python
def decrypt_stream(buf, key, offset=0):
    out = bytearray(len(buf))
    for i in range(len(buf)):
        pos = (offset + i) & 0xFFFFFFFF
        ks  = keygen(pos >> 3, key)         # 1 слово на 8 байт
        out[i] = buf[i] ^ ((ks >> ((pos & 7) * 8)) & 0xFF)
    return bytes(out)
```

### 3.2 MBA (Mixed Boolean-Arithmetic) трансформация ключа

Перед вызовом `decrypt_loop` сырой 64-битный ключ прогоняется через функцию-обфускатор:

```python
MBA_C4 = rol64(0xe0acf1bbcdcbfa53, 13)
MBA_C5 = rol64(0x72dcdfac23b68e72, 17)
MBA_C6 = rol64(0xd899888f5ca6824d, 37)

def mba(rcx, magic=0x53454c46):
    rax = magic & 0xFFFFFFFF
    rax = (rax * MBA_C4) & M
    rax ^= rcx
    rax ^= (rax >> 30); rax &= M
    rax = (rax * MBA_C5) & M
    rax ^= (rax >> 27); rax &= M
    rax = (rax * MBA_C6) & M
    rax ^= (rax >> 31); rax &= M
    rax |= 1                    # odd
    return rax
```

Функция принимает (key, magic) и возвращает финальный cipher_key. Разные вызовы используют разные magic-значения — это ключ к пониманию многослойной системы дешифровки.

---

## 4. env_key — машинно-специфичная привязка

Это **самая хитрая часть защиты**. TLS callback вычисляет `env_key`, который зависит от конкретной машины и делает статический анализ невозможным без знания CPUID и ntdll.

### 4.1 Алгоритм

```python
def compute_env_key():
    # Шаг 1: хэш первых 60 байт ntdll.dll из памяти
    ntdll_base = GetModuleHandleW("ntdll.dll")
    ntdll_bytes = read_memory(ntdll_base, 60)   # DOS-заголовок
    
    h = 0
    for b in ntdll_bytes:
        h = (rol32(h, 5) ^ b) & 0xFFFFFFFF     # ROL5 + XOR

    # Шаг 2: CPUID leaf 1
    eax, _, ecx, edx = cpuid(1)
    
    # Шаг 3: смешивание
    r9 = rol32((h ^ eax) & 0xFFFFFFFF, 7)
    r9 = rol32((r9 ^ ecx) & 0xFFFFFFFF, 7)
    r9 = (r9 ^ edx) & 0xFFFFFFFF
    return r9                                    # 32-битный env_key
```

Потом TLS callback делает:
```python
# raw_a8 = stored cipher key QWORD at [data_struct + 0xA8]
raw_a8 = 0xC84D8537367B5D7C
low32_modified = (raw_a8 & 0xFFFFFFFF) ^ env_key
modified_key = ((raw_a8 >> 32) << 32) | low32_modified
cipher_key = mba(modified_key, 0x53454c46)
```

### 4.2 Проблемы статического брутфорса

- ntdll hash (0x5C3FE038) — **фиксированный** для конкретной Windows-сборки
- CPUID EAX — **зависит от CPU** (Intel/AMD, конкретная модель/stepping)
- CPUID ECX/EDX — **зависят от включённых фич** процессора

Было протестировано ~7000 комбинаций Intel + AMD CPUID, но capstone-валидатор давал false positives из-за того, что x86-64 интерпретирует как валидный код почти любую последовательность байт. Единственный надёжный метод — запустить на реальной машине.

### 4.3 Почему это дыра

Хотя env_key и привязывает бинарь к машине, проблема в том, что **сам алгоритм полностью реверсируемый**: зная CPUID и ntdll-хэш (оба легко получить через ctypes), можно вычислить ключ и расшифровать всё статически. Скрипт `patch_crackme_v2.py` это и делает.

**Рекомендация:** добавить нелинейные преобразования с ключевыми данными из нескольких источников (CPUID листы 0x80000002-4, серийник диска, SMBIOS) и хранить не сам key, а его хэш для верификации.

---

## 5. EP-стаб: многоуровневый загрузчик

После расшифровки TLS получаем `ep_dec` (3540 байт). Это **мини-загрузчик** с несколькими фазами.

### 5.1 Фаза инициализации: API по хэшу

EP НЕ использует стандартный IAT. Он сам резолвит нужные функции из kernel32 через хэш-таблицу в data_struct:

```asm
; Структура data_struct (rdi = base + 0x1A0E0)
[rdi+0x30] = hash_LoadLibraryA
[rdi+0x34] = hash_VirtualAlloc  
[rdi+0x38] = hash_VirtualProtect
[rdi+0x3C] = hash_CreateThread   (0x835E515E)

call get_kernel32_base             ; через PEB → LDR → InLoadOrderModuleList
call GetProcAddress_by_hash        ; функция на EP[0x812]
mov  [rdi+0x40], rax               ; сохраняем LoadLibraryA
call GetProcAddress_by_hash
mov  [rdi+0x48], rax               ; VirtualAlloc
; ...и т.д.
```

Функция `GetProcAddress_by_hash` (EP[0x812]) итерирует по EAT (Export Address Table) kernel32 и сравнивает хэш имени с целевым.

### 5.2 Фаза STRG: расшифровка 46 sub-секций

Подпрограмма `sub_0x1400195A0` читает таблицу из 46 записей (`[rdi+8]` = RVA 0x1A1A4) и расшифровывает каждый регион в `.ygpm`:

```python
# Каждая запись = (dest_rva: u32, size: u32)
for i, (dest_rva, size) in enumerate(strg_table):
    magic = (0x53545247 ^ i) & 0xFFFFFFFF   # "STRG" XOR counter
    ck = mba(raw_key_runtime, magic)
    decrypt_stream(memory[dest_rva:], ck, offset=0)
```

**Важно:** magic меняется для каждой секции (`0x53545247 ^ 0`, `0x53545247 ^ 1`, ...), то есть у каждой sub-секции уникальный ключ.

### 5.3 Фаза CODE: основной пейлоад → .zwhr

Подпрограмма `sub_0x140019287`:

```python
# 1. Копируем шифртекст из .hjt[0x1ACD0:] в .zwhr
memcpy(base + 0x1000, base + 0x1ACD0, 0xF550)

# 2. Расшифровываем .zwhr на месте
cipher_key = mba(raw_key_runtime, 0x434F4445)   # magic = "CODE"
decrypt_stream(base + 0x1000, cipher_key, offset=0)

# 3. VirtualProtect(.zwhr, 0xF550, PAGE_EXECUTE_READWRITE)
VirtualProtect(base + 0x1000, 0xF550, 0x40, &old_prot)
```

После этого шага `.zwhr` содержит **plaintext код крекме**.

### 5.4 Финальный прыжок

```asm
mov ecx, [rdi + 0x2C]   ; entry_rva = 0x13F0
lea rax, [rbx + rcx]    ; rax = ImageBase + 0x13F0
mov rsp, r15            ; восстанавливаем оригинальный RSP
jmp rax                 ; прыгаем в крекме
```

---

## 6. Антитампер — первый слой (CRC в EP)

Сразу после CRT-инициализации EP выполняет CRC-проверку:

```asm
0x140019099: call  compute_crc           ; считает CRC бинаря
0x14001909E: cmp   eax, [rdi + 0x8C]    ; сравниваем с эталоном 0x9408DF8D
0x1400190A4: je    0x1400190B2           ; совпало → продолжаем
0x1400190A6: lea   rdx, [rip + 0xC78]   ; "This application has been tampered..."
0x1400190AD: call  error_exit           ; MessageBox + ExitProcess
```

Эталонный CRC хранится в `[data_struct + 0x8C]` = `0x9408DF8D`. При изменении любого байта в файле CRC не совпадает → выходим с диалогом.

**Патч:** `74 0C` (`je`) → `EB 0C` (`jmp`) — один байт в EP-шифртексте.

---

## 7. Антитампер — второй слой (Watchdog threads)

После расшифровок EP запускает **шесть watchdog-тредов** через `CreateThread`:

```asm
; Флаги в [rdi+0] = 0x0000000B (биты 0, 1, 3)
test eax, 1        ; бит 0 → тред 1
je   .skip_b0
lea  r8, [rip + 0x871]   ; thread_fn_1
call CreateThread_wrapper ; → CreateThread(NULL, 0, thread_fn_1, NULL, 0, NULL)

test eax, 4        ; бит 2 → тред 2
...

test eax, 8        ; бит 3 → трéды 3 и 4
je   .skip_b3
lea  r8, [rip + 0xA21]
call CreateThread_wrapper
lea  r8, [rip + 0xB6C]   ; ← thread_fn_runtime_check (offset 0xCB9 в EP)
call CreateThread_wrapper ; ВСЕГДА если бит 3 установлен
```

`CreateThread_wrapper` (EP[0x159]) — вызывает `[data_struct + 0x58]` = runtime-resolved `kernel32!CreateThread` с минимальными параметрами.

Один из тредов (EP[0xCB9]) — **"Runtime integrity check"** — периодически пересчитывает CRC и выводит `"Runtime integrity check failed."` если находит изменения.

**Патч:** NOP'им все 6 вызовов `call EP[0x159]` (по 5 байт каждый → 30 байт изменений в EP-шифртексте).

---

## 8. Структура .ygpm: строки + CRT-код через STRG

После STRG-дешифровки `.ygpm` содержит:

| Смещение  | Содержимое                                  |
|-----------|---------------------------------------------|
| +0x000    | `hello my friend\0`                         |
| +0x011    | `this is crackme\0`                         |
| +0x028    | `for custom packer "CompotProtector"\0`     |
| +0x04D    | `enter the key\0`                           |
| +0x064    | **`claudecoding4.8model\0`** ← пароль       |
| +0x079    | `yesofcourse\0`                             |
| +0x086    | `nononoooo\0`                               |
| +0x100..  | CRT error strings (DOMAIN, OVERFLOW...)     |
| +0x240..  | MinGW-w64 runtime failure strings           |
| +0x8B0..  | `0123456789abcdef`, `NaN`, `Infinity`...    |
| +0xE10    | GCC version: `x86_64-posix-seh-rev1, 15.2.0`|

Весь этот блок — это по сути **расшифрованный .rdata** от MinGW-приложения: строки для printf, math-ошибки, сам пароль.

Пароль хранится в открытом виде, но в зашифрованной секции `.ygpm`, которая расшифровывается только через 46 последовательных STRG-проходов с разными ключами.

---

## 9. Проверка пароля

### 9.1 Как это работает в .zwhr

```asm
; .zwhr @ 0x140001000, entry @ 0x1400013F0
0x14000122e: call  0x1400102f8         ; IAT-thunk → strcmp (через .rkwtotp IAT)
0x140001233: test  eax, eax
0x140001235: jne   0x140001370         ; eax≠0 → неверный пароль → exit(0xFF)
...
0x140001271: call  0x1400101b0         ; вывод "yesofcourse"
```

`0x1400102F8` — IAT thunk: `jmp [rip + 0x61CA]`. Сам IAT (`.rkwtotp`) заполняется Windows-загрузчиком. Функция — `msvcrt!strcmp` или аналог.

### 9.2 Почему jne-патч показывал "nononoooo"

Функция, вызываемая через IAT, НЕ просто strcmp — она **сама выводит результат** ("yesofcourse" или "nononoooo") до того, как вернуть 0/1. Поэтому:
- при неправильном пароле: печатается "nononoooo", возвращается 1
- jne-патч блокирует `exit(0xFF)`, но слово уже на экране
- для вывода "yesofcourse" — нужен правильный пароль

---

## 10. Итоговая схема защиты

```
crackme-encrypted.exe
│
├── PE загружается в память (Windows loader заполняет IAT в .rkwtotp)
│
├── [TLS Callback @ 0x19DD4]
│   ├── compute_env_key(CPUID + ntdll_hash) → env_key
│   ├── mba(raw_a8 XOR env_key) → cipher_key_ep
│   └── decrypt_stream(.hjt[0:0xDD4], cipher_key_ep, off=0)
│                                   ↓
├── [EP Stub @ 0x19000] (теперь расшифрован)
│   ├── GetProcAddress_by_hash(kernel32): LoadLibrary, VirtualAlloc, VirtualProtect, CreateThread
│   ├── CRC check → выход если изменён файл
│   ├── sub_0x1400195A0: 46 × decrypt_stream(.ygpm[dest_rva_i:], mba(raw_key_rt, 0x53545247^i))
│   ├── sub_0x140019287: copy(.hjt[0x1ACD0:], .zwhr) + decrypt_stream(.zwhr, mba(raw_key_rt, "CODE"))
│   ├── VirtualProtect(.zwhr, PAGE_EXECUTE_READWRITE)
│   ├── CreateThread × 6 (watchdog, runtime integrity, anti-debug)
│   └── jmp base + 0x13F0    (OEP в .zwhr)
│                   ↓
└── [Crackme code @ .zwhr]
    ├── printf(strings from .ygpm): "hello my friend" ...
    ├── fgets/scanf → читаем пароль
    ├── strcmp(input, .ygpm[0x64]) → compare with "claudecoding4.8model"
    └── print "yesofcourse" или "nononoooo"
```

---

## 11. Таблица всех патчей

| # | Секция | Офсет в cipher | Оригинал | Патч | Что делает |
|---|--------|----------------|----------|------|------------|
| 1 | EP (.hjt) | `0xA4` | `74 0C` | `EB 0C` | je→jmp: пропуск CRC-проверки |
| 2 | EP (.hjt) | `0xE6` (+5b) | `E8 ...` | `90×5` | NOP: не создаём watchdog-тред 1 |
| 3 | EP (.hjt) | `0xFB` (+5b) | `E8 ...` | `90×5` | NOP: не создаём watchdog-тред 2 |
| 4 | EP (.hjt) | `0x110` (+5b) | `E8 ...` | `90×5` | NOP: не создаём watchdog-тред 3 |
| 5 | EP (.hjt) | `0x125` (+5b) | `E8 ...` | `90×5` | NOP: не создаём watchdog-тред 4 |
| 6 | EP (.hjt) | `0x13A` (+5b) | `E8 ...` | `90×5` | NOP: не создаём watchdog-тред 5 |
| 7 | EP (.hjt) | `0x146` (+5b) | `E8 ...` | `90×5` | NOP: не создаём watchdog-тред 6 |
| 8 | .zwhr | `0x235` (+6b) | `0F 85 35 01 00 00` | `90×6` | NOP: пропуск ветки неверного пароля |

Все патчи применяются к **шифртексту**: `new_cipher = new_plaintext XOR keystream`.

---

## 12. Найденные уязвимости и как исправить

### 12.1 env_key выводим через ctypes

**Проблема:** алгоритм полностью публичный. `CPUID(1)` + `ReadProcessMemory(ntdll_base, 60)` = env_key за 10 строк Python.

**Исправление:**
```
- Добавить нелинейный микс из нескольких CPUID-листьев (0x80000002, 0x80000004, leaf 7)
- Включить серийный номер тома (GetVolumeInformationA)
- Добавить SMBIOS UUID (через `NtQuerySystemInformation`)
- Использовать KDF (Argon2id или PBKDF2) поверх собранных данных
- Хранить не сам ключ, а только CRC от результата
```

### 12.2 keygen — детерминированный stream-cipher

**Проблема:** cipher = plaintext XOR stream. Если атакующий знает часть plaintext, он получает часть stream и может выводить ключ.

**Исправление:**
```
- Использовать ChaCha20 вместо самодельного варианта
- Добавить аутентификацию (AEAD: ChaCha20-Poly1305)
- Разбить ключ на части, хранить в разных местах
```

### 12.3 MBA — не защита, а замедление

**Проблема:** MBA-трансформации (multiplications + XOR-shifts) тривиально реверсируются. В коде они одинаковые для всех уровней.

**Исправление:**
```
- Генерировать уникальные MBA-цепочки для каждой версии бинаря
- Использовать нелинейные s-box вместо линейных MBA
- Прятать ключевые константы через self-modifying code
```

### 12.4 Строки в .ygpm хранятся в открытом виде после расшифровки

**Проблема:** после STRG-расшифровки пароль `claudecoding4.8model` лежит в `.ygpm` открытым текстом. Любой дамп процесса покажет его.

**Исправление:**
```
- Хранить только хэш пароля (SHA-256 или bcrypt)
- Сравнивать hash(input) == stored_hash
- Очищать память с паролем сразу после сравнения (SecureZeroMemory)
```

### 12.5 CRC-проверка легко байпасится

**Проблема:** один байт патча (je→jmp) убирает всю проверку. Эталонный CRC хранится в data_struct, доступном через rdi.

**Исправление:**
```
- Распределить несколько CRC-проверок по всему коду (не в одном месте)
- Использовать HMAC вместо CRC (ключ вшит через self-modifying code)
- Проводить проверки в watchdog-тредах с разными интервалами
- Добавить неявные проверки (нарочно "испорченные" опкоды, которые
  должны быть исправлены CRC-патчем в рантайме)
```

### 12.6 Watchdog-треды — все в одном месте

**Проблема:** все 6 `call CreateThread_wrapper` идут подряд, один NOP-паттерн нейтрализует все.

**Исправление:**
```
- Разнести запуск тредов по разным функциям
- Маскировать CreateThread под другой вызов (косвенный через таблицу)
- Запускать треды из .ygpm-кода (уже после STRG-расшифровки)
- Добавить взаимный мониторинг: тред A проверяет тред B и наоборот
```

### 12.7 Структура данных rdi слишком информативна

**Проблема:** одна структура `data_struct @ 0x1A0E0` содержит всё: ключи, размеры, RVA-адреса, эталонный CRC, таблицы тредов. Один адрес в rdi — и весь план раскрыт.

**Исправление:**
```
- Разбить на несколько структур в разных секциях
- Шифровать поля структуры относительно друг друга
- Вычислять адреса динамически, а не хранить в константах
```

---

## 13. Хронология разбора: что где застряло

| Этап | Проблема | Решение |
|------|----------|---------|
| keygen | Финальный шаг `r8^r9^r10`: думал `(r8^r9)^(r8^r10)=r9^r10`, неверно | Unicorn-эмуляция подтвердила правильный вариант |
| env_key | Статический брутфорс (~7000 CPUID) — false positives везде | Запуск Python-скрипта на реальной машине |
| EP анализ | `lea rdi, [rip+0x10CE]` → думал смещение 0xAE0, на деле 0x10E0 | Пересчёт: следующий RIP + disp, не буферный офсет |
| .zwhr дизасм | `call 0x140002120` → `disasm_fn(0x2120)` давало неверный VA | Правильный офсет = VA - ZWHR_BASE = 0x1120 |
| Второй антитампер | Первый патч убрал tamper-диалог, но появился второй | Поиск строки "Runtime" → в EP[0xD62] → watchdog thread |
| "nononoooo" | jne-патч не убирал вывод fail-строки | Функция вывода вызывается ВНУТРИ compare-wrapper до return |

---

## 14. Итог

CompotProtector — хорошо продуманная многоуровневая защита с:
- Машинно-специфичным ключом (env_key)
- Многослойным шифрованием (TLS → STRG×46 → CODE)
- Антитамперингом в двух точках
- Watchdog-тредами для runtime-мониторинга
- Сокрытием IAT (резолв по хэшу)

Главная слабость — **все слои используют один и тот же алгоритмический примитив** (keygen + mba) с детерминированными константами. Как только алгоритм восстановлен и проверен через Unicorn — вся система расшифровывается скриптом за секунды.

Для продакшн-защиты рекомендую заменить кастомный keygen на **ChaCha20-Poly1305** и добавить **нелинейную KDF** для derivation ключей из env_key.
