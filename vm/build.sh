#!/bin/sh
# Пересборка флэт-блоба виртуальной машины (интерпретатор vmRun + обёртка vmEnter).
# Запускать после правок vm_blob.c. Блоб обязан быть position-independent и без релокаций.
set -e
cd "$(dirname "$0")"

# 1. Компиляция freestanding-объекта (без CRT, без jump-таблиц, без stack-protector).
clang -c -O2 -ffreestanding -fno-stack-protector -fno-builtin -fno-jump-tables \
  -fno-asynchronous-unwind-tables -fcf-protection=none \
  -target x86_64-pc-windows-gnu vm_blob.c -o vm_blob.o

# 2. Линковка в PE (резолвит внутренний call vmEnter->vmRun в rel32).
"C:/mingw64/bin/ld.exe" -e vmEnter --image-base 0x140000000 -o vm_blob.pe vm_blob.o

# 3. Извлечение плоской секции .text.
"C:/mingw64/bin/objcopy.exe" -O binary -j .text vm_blob.pe vm_blob.bin

# 4. Проверка: релокаций быть не должно; смещения vmEnter/vmRun.
"C:/mingw64/bin/objdump.exe" -t vm_blob.pe | grep -iE "vmEnter|vmRun"
cp vm_blob.bin ../src/protect/vm/vm_blob.bin
rm -f vm_blob.o vm_blob.pe
echo "vm_blob.bin updated; vmEnter at offset 0 -> VM_ENTER_OFF in blob.rs"
