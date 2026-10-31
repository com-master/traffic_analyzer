# traffic_analyzer

Сетевой анализатор трафика на Rust, который в реальном времени ищет в захваченных пакетах признаки типовых атак и выводит алерты в консоль.

Проект сделан на практике от университета в АО «МЦСТ» (2025).

## Что детектирует

| Детект | Как работает | Порог |
|---|---|---|
| **Анонимный вход на FTP** | В полезной нагрузке TCP-сессии ищутся команды `USER Anonymous` и `PASS Anonymous`. Алерт срабатывает, когда в одной сессии встретились обе | 1 сессия |
| **SYN-сканирование / SYN DoS** | Для каждой пары `src_ip → dst_ip` считаются TCP-сессии, где был SYN, но не было FIN дольше 3 секунд (полуоткрытые соединения) | > 100 сессий |
| **UDP-сканирование** | Считаются ICMP Destination Unreachable (type 3), которые хост отвечает на UDP-пакеты к закрытым портам | > 10 ответов на пару хостов |

Каждый алерт выводится один раз на ключ (сессию или пару хостов), чтобы не засорять вывод.

## Как устроено

- Захват пакетов: `libpcap` (крейт [`pcap`](https://crates.io/crates/pcap)), интерфейс по умолчанию, promiscuous mode.
- Разбор Ethernet → IPv4 → TCP/ICMP: [`etherparse`](https://crates.io/crates/etherparse), без копирования заголовков.
- Поиск сигнатур в payload: [`memchr::memmem`](https://crates.io/crates/memchr).
- Состояние хранится в `HashMap` по 4-tuple TCP-сессии и по парам хостов.

## Запуск

Нужны Rust (stable) и `libpcap-dev` (Debian/Ubuntu) или `libpcap` (Arch).

```bash
cargo build --release
sudo ./target/release/traffic_analyzer   # для захвата нужны root или CAP_NET_RAW
```

Без root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/traffic_analyzer
./target/release/traffic_analyzer
```

## Как проверить

В соседнем терминале или с другой машины в той же сети:

```bash
# SYN-скан
sudo nmap -sS -p 1-1000 <target>

# UDP-скан
sudo nmap -sU -p 1-200 <target>

# Анонимный FTP (на тестовом FTP-сервере)
ftp <ftp-host>      # логин: Anonymous, пароль: Anonymous
```

Пример вывода:

```
Choosed device: eth0
Potentional SYN scan or SYN dos: ("192.168.1.10", "192.168.1.20") packets: 101
Possible UDP scan detected: ("192.168.1.20", "192.168.1.10", 3)
Ftp anonymous login: ("192.168.1.10", 51234, "192.168.1.30", 21)
```

## Ограничения

- Только IPv4 и только живой захват (чтения `.pcap`-файлов нет).
- Сигнатура FTP чувствительна к регистру: ищется именно `Anonymous`.
- Пороги зашиты в код.
- Таблица сессий не очищается, поэтому на долгом захвате растёт память.

## Что можно доработать

- [ ] Чтение `.pcap` через `Capture::from_file` для воспроизводимых тестов
- [ ] Регистронезависимый поиск `USER anonymous` / `PASS`
- [ ] Учитывать ACK в детекте SYN, чтобы установленные долгие соединения не считались полуоткрытыми
- [ ] Пороги и интерфейс через аргументы CLI
- [ ] Вывод алертов в JSON для отправки в SIEM (Wazuh/ELK)
- [ ] TTL для записей о сессиях
