#!/usr/bin/env python3
"""Установщик русификатора Gods Will Be Watching (Deconstructeam, 2014).

    python3 install.py "<папка с игрой>"
    python3 install.py --uninstall "<папка с игрой>"

Что делает:

1. Сверяет SHA256 вашего ``data.win`` — патч применяется ТОЛЬКО к той версии,
   от которой собран.
2. Кладёт рядом ``data.win.bak`` и ``gwbw_content.ini.bak``.
3. Накладывает двоичный патч на ``data.win`` (шестой пункт в меню языков,
   кириллица во всех 22 шрифтах, статистика прохождений, которая копится
   у вас локально вместо умершего сервера разработчиков) и сверяет SHA256
   результата.
4. ДОПИСЫВАЕТ строку ``ru`` в каждую из девяти секций вашего
   ``gwbw_content.ini``. Строки остальных пяти языков не трогаются — это
   проверяется побайтово прямо во время установки.

Обновление: ставится поверх прежней версии русификатора той же командой.
Патч накладывается на оригинал из ``data.win.bak``, старые строки ``ru``
заменяются новыми.

Ничего, кроме Python 3.8+, не требуется: bspatch реализован здесь же.

**В этом наборе нет ни одного файла игры.** Двоичный патч — только разница;
русский текст — наш; ваш ``gwbw_content.ini`` дополняется на месте, а не
подменяется чужой копией. Поэтому набор можно распространять, а игру —
нельзя, и она в него не входит.

Откат: ``--uninstall`` вернёт оба ``.bak`` на место.
"""
from __future__ import annotations

import bz2
import hashlib
import json
import shutil
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PATCH = HERE / "data-ru.bsdiff"
STRINGS = HERE / "ru-strings.json"

SHA_ORIGINAL = "624a1e91e03991ed925074d69531997e8c8c3a540b6ec6af5a600073e0735ac1"
SHA_PATCHED = "59e27586cd29f8d5e8f76dc8af0d8c5213eb0871b99fb045726a27dbb30b3064"
# прежние версии русификатора: поверх них ставим, беря оригинал из data.win.bak
SHA_OLD_PATCHED = {
    "8b4cc29a090926c417948b7a1bf051d1bbbedabca20df2ce713825fa79b83cce": "0.9",
}

BOM = b"\xef\xbb\xbf"


def die(msg: str) -> "NoReturn":  # noqa: F821
    print("ОШИБКА: " + msg, file=sys.stderr)
    raise SystemExit(1)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --- bspatch (формат BSDIFF40) ------------------------------------------
# Реализован здесь, чтобы установщик не требовал pip install. Числа лежат
# в знаковой форме «модуль + старший бит как минус», а не в дополнительном
# коде — это особенность формата, обычный struct её не разберёт.

def _offtin(raw: bytes) -> int:
    value = struct.unpack("<Q", raw)[0]
    if value & (1 << 63):
        return -(value & ~(1 << 63))
    return value


def bspatch(old: bytes, patch: bytes) -> bytes:
    if patch[:8] != b"BSDIFF40":
        die("файл патча повреждён (не BSDIFF40)")
    len_ctrl, len_diff, len_new = (_offtin(patch[i:i + 8]) for i in (8, 16, 24))
    head = 32
    ctrl = bz2.decompress(patch[head:head + len_ctrl])
    diff = bz2.decompress(patch[head + len_ctrl:head + len_ctrl + len_diff])
    extra = bz2.decompress(patch[head + len_ctrl + len_diff:])

    new = bytearray(len_new)
    npos = opos = cpos = dpos = epos = 0
    while npos < len_new:
        add, copy, seek = (_offtin(ctrl[cpos + i:cpos + i + 8]) for i in (0, 8, 16))
        cpos += 24
        if npos + add > len_new:
            die("патч не сходится: блок сложения выходит за размер файла")
        # побайтовое сложение с исходником; хвост за концом old идёт как есть
        chunk = diff[dpos:dpos + add]
        base = old[opos:opos + add] if opos >= 0 else b""
        if len(base) < add:
            new[npos:npos + len(base)] = bytes(
                (a + b) & 0xFF for a, b in zip(chunk, base))
            new[npos + len(base):npos + add] = chunk[len(base):]
        else:
            new[npos:npos + add] = bytes(
                (a + b) & 0xFF for a, b in zip(chunk, base))
        npos += add
        dpos += add
        opos += add
        if npos + copy > len_new:
            die("патч не сходится: блок вставки выходит за размер файла")
        new[npos:npos + copy] = extra[epos:epos + copy]
        npos += copy
        epos += copy
        opos += seek
    return bytes(new)


# --- gwbw_content.ini ----------------------------------------------------

def parse_ini(text: str) -> "list[tuple[str, list[tuple[str, str]]]]":
    sections: "list[tuple[str, list[tuple[str, str]]]]" = []
    for line in text.split("\r\n"):
        if line.startswith("[") and line.endswith("]"):
            sections.append((line[1:-1], []))
        elif " = " in line and sections:
            lang, payload = line.split(" = ", 1)
            sections[-1][1].append((lang, payload))
        elif line.strip():
            die("неопознанная строка в gwbw_content.ini: " + repr(line[:60]))
    return sections


def add_russian(ini: Path, table: "dict[str, dict[str, str]]") -> str:
    raw = ini.read_bytes()
    if not raw.startswith(BOM):
        die("у gwbw_content.ini нет UTF-8 BOM — это не файл игры")
    text = raw.decode("utf-8-sig")
    trailing = text.endswith("\r\n")
    # прежняя версия русификатора: её строки ru снимаем и пишем новые;
    # приёмка ниже сверяет всё остальное с файлом БЕЗ них
    text = "\r\n".join(l for l in text.split("\r\n") if not l.startswith("ru = "))

    out: "list[str]" = []
    total = 0
    for section, langs in parse_ini(text):
        by_lang = dict(langs)
        if "en" not in by_lang:
            die("в секции [" + section + "] нет строки en — файл не тот")
        if section not in table:
            die("в наборе нет перевода для секции [" + section + "]")
        en_keys = set(json.loads(by_lang["en"]))
        ru = table[section]
        missing = en_keys - set(ru)
        if missing:
            die("[" + section + "] в переводе нет ключей: " + str(sorted(missing)[:5]))
        out.append("[" + section + "]")
        for lang, payload in langs:
            out.append(lang + " = " + payload)
        out.append("ru = " + json.dumps(ru, ensure_ascii=False,
                                        separators=(",", ":")))
        total += len(ru)

    result = "﻿" + "\r\n".join(out) + ("\r\n" if trailing else "")
    data = result.encode("utf-8")

    # приёмка до записи: исходные строки обязаны остаться байт в байт
    src_lines = text.split("\r\n")
    dst_lines = data.decode("utf-8-sig").split("\r\n")
    if [l for l in dst_lines if not l.startswith("ru = ")] != src_lines:
        die("внутренняя ошибка: изменились строки других языков, файл не тронут")
    for section, langs in parse_ini(data.decode("utf-8-sig")):
        by_lang = dict(langs)
        if "ru" not in by_lang:
            die("внутренняя ошибка: строка ru не добавилась в [" + section + "]")
        json.loads(by_lang["ru"])  # эмуляция load_language игры

    if data == raw:
        return "уже"
    ini.write_bytes(data)
    return "секций 9, ключей " + str(total)


# --- установка / откат ---------------------------------------------------

def uninstall(game: Path) -> int:
    done = []
    for name in ("data.win", "gwbw_content.ini"):
        bak = game / (name + ".bak")
        if bak.exists():
            shutil.copy2(bak, game / name)
            done.append(name)
    if not done:
        print("резервных копий рядом нет — откатывать нечего")
        return 1
    print("возвращено из резерва: " + ", ".join(done))
    return 0


def install(game: Path) -> int:
    datawin = game / "data.win"
    ini = game / "gwbw_content.ini"
    for p in (datawin, ini):
        if not p.exists():
            die("не найден " + str(p) + " — это папка с игрой?")
    for p in (PATCH, STRINGS):
        if not p.exists():
            die("не найден " + p.name + " — распакуйте архив целиком")

    table = json.loads(STRINGS.read_text(encoding="utf-8"))

    got = sha256(datawin)
    bak = datawin.with_suffix(".win.bak")
    base = datawin
    if got in SHA_OLD_PATCHED:
        if not bak.exists() or sha256(bak) != SHA_ORIGINAL:
            die("стоит русификатор " + SHA_OLD_PATCHED[got] + ", но рядом нет "
                "data.win.bak с оригиналом — проверьте целостность файлов игры "
                "в Steam и запустите установку снова")
        print("найден русификатор " + SHA_OLD_PATCHED[got] +
              " — обновляю, оригинал беру из data.win.bak")
        base = bak
    if got == SHA_PATCHED:
        print("data.win уже пропатчен")
    elif got != SHA_ORIGINAL and base is datawin:
        die("ваш data.win не совпадает с версией, от которой собран патч:\n"
            "  ожидался " + SHA_ORIGINAL + "\n  получен  " + got + "\n"
            "другая версия или платформа игры — патч не применён")
    else:
        if not bak.exists():
            shutil.copy2(datawin, bak)
        new = bspatch(base.read_bytes(), PATCH.read_bytes())
        tmp = datawin.with_suffix(".win.ru-tmp")
        tmp.write_bytes(new)
        if sha256(tmp) != SHA_PATCHED:
            tmp.unlink()
            die("результат патча не совпал с эталоном — data.win не тронут")
        tmp.replace(datawin)
        print("data.win пропатчен (резерв data.win.bak)")

    ini_bak = ini.with_suffix(".ini.bak")
    if not ini_bak.exists():
        shutil.copy2(ini, ini_bak)
    verdict = add_russian(ini, table)
    if verdict == "уже":
        print("gwbw_content.ini уже содержит русский этой версии")
    else:
        print("gwbw_content.ini дополнен: " + verdict +
              " (резерв gwbw_content.ini.bak)")

    print("\nготово. Запустите игру — шестым пунктом в меню языков «Русский».")
    return 0


def main(argv: "list[str]") -> int:
    args = [a for a in argv[1:] if a != "--uninstall"]
    if len(args) != 1:
        print(__doc__)
        return 2
    game = Path(args[0])
    if not game.is_dir():
        die("папка не найдена: " + str(game))
    if "--uninstall" in argv[1:]:
        return uninstall(game)
    return install(game)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
