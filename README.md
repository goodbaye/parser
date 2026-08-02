# LogSentinel

Небольшая CLI-утилита для разбора логов SSH-аутентификации в Linux (`auth.log` / `secure`),
которая находит подозрительную активность: brute-force атаки, успешные входы после серии
неудачных попыток и входы в нетипичное время.

Проект сделан как самостоятельная учебная работа — для практики парсинга логов и логики
детектирования, похожей по духу на правила корреляции в SIEM, но реализованной с нуля
на Python, без использования готовой SIEM-системы.

## Возможности

- Разбор стандартных строк syslog от OpenSSH (`Failed password`, `Accepted password` /
  `Accepted publickey`, `Invalid user`)
- Правила детектирования:
  - **Brute force** — N и более неудачных попыток входа с одного IP в пределах скользящего временного окна
  - **Успешный вход после неудачных попыток** — успешный вход с IP, у которого незадолго до этого
    было несколько неудачных попыток (классический паттерн «атакующий в итоге зашёл»)
  - **Вход в нетипичное время** — успешный вход в настраиваемом промежутке нерабочих часов
- Отчёт в консоли, а также экспорт в JSON / CSV
- Unit-тесты (pytest) и CI-workflow на GitHub Actions

## Установка

```bash
git clone https://github.com/goodbaye/parser.git
cd parser
pip install -r requirements.txt
```

Для работы самой утилиты внешние зависимости не нужны — `requirements.txt`
содержит только `pytest`, необходимый для запуска тестов.

## Использование

```bash
python3 -m logsentinel.cli sample_logs/auth.log --year 2026
```

Экспорт результатов:

```bash
python3 -m logsentinel.cli sample_logs/auth.log --year 2026 --json findings.json --csv findings.csv
```

Опции:

| Флаг | Описание |
|---|---|
| `--year YEAR` | Год, который нужно подставить к меткам времени в логах (в строках syslog год не указан). По умолчанию — текущий год. |
| `--json PATH` | Записать результаты в формате JSON по указанному пути |
| `--csv PATH` | Записать результаты в формате CSV по указанному пути |
| `--quiet` | Не выводить отчёт в консоль |

### Пример вывода

```
Parsed 12 recognized log lines from sample_logs/auth.log

Findings: 4  (high=2, medium=2, low=0)
----------------------------------------------------------------------------------------------------
[HIGH  ] 2026-01-10T03:14:08  rule=brute_force              ip=203.0.113.5     user=root
          5 failed login attempts from 203.0.113.5 within 60s (threshold=5)
[HIGH  ] 2026-01-10T03:14:20  rule=success_after_failures   ip=203.0.113.5     user=root
          Successful login for user 'root' from 203.0.113.5 after 7 prior failed attempt(s)
[MEDIUM] 2026-01-10T02:47:33  rule=off_hours_login          ip=198.51.100.77   user=backup_svc
          Successful login for user 'backup_svc' from 198.51.100.77 at 02:47:33 (off-hours window)
[MEDIUM] 2026-01-10T03:14:20  rule=off_hours_login          ip=203.0.113.5     user=root
          Successful login for user 'root' from 203.0.113.5 at 03:14:20 (off-hours window)
----------------------------------------------------------------------------------------------------
```

## Запуск тестов

```bash
pip install -r requirements.txt
pytest -v
```

## Структура проекта

```
parser/
├── logsentinel/
│   ├── __init__.py
│   ├── parser.py      # разбор строк лога в объекты LogEvent
│   ├── detectors.py   # правила детектирования -> объекты Finding
│   ├── report.py       # вывод в консоль / JSON / CSV
│   └── cli.py          # точка входа CLI на argparse
├── tests/
│   ├── test_parser.py
│   └── test_detectors.py
├── sample_logs/
│   └── auth.log        # синтетический пример лога для демонстрации
└── .github/workflows/ci.yml
```

## Возможные доработки

- Поддержка входных данных из `journalctl` / `.evtx` (Windows Event Log)
- Правило для детектирования распределённого brute-force (много IP, одна цель-аккаунт)
- Конфигурационный файл для настройки порогов вместо жёстко заданных значений
- Оформление в виде pip-устанавливаемого CLI (`pyproject.toml`, точка входа `logsentinel`)

## Лицензия

MIT — см. [LICENSE](LICENSE).
