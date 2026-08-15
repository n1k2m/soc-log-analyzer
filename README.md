# SOC Log Analyzer

Pet-проект для автоматического анализа логов Apache. Скрипт парсит access.log, проверяет события по правилам безопасности (как в реальных SOC) и обогащает данные через Threat Intelligence API. На выходе получается наглядный визуальный отчет с разбитыми по критичности алертами.

## Структура проекта

```
soc-log-analyzer/
├── main.py            # Точка входа и оркестрация процессов
├── config.py          # Пороговые значения и настройки
├── parser_module.py   # Парсер Apache логов
├── models.py          # Минимальные typed-модели LogEntry и Alert
├── ti.py              # Загрузчик Threat Intelligence (cache → API → fallback)
├── detection.py       # Правила обнаружения и логика корреляции
├── reporter.py        # JSON-отчёт и график активности
├── data/
│   ├── access.log           # Тестовый файл логов
│   └── blacklist_cache.json # Локальный TI-кэш (замена API в режиме разработки)
├── output/            # Генерируется автоматически (добавлен в gitignore)
│   ├── report.json
│   └── activity.png
├── requirements.txt
├── tests/
│   ├── test_detection.py    # Unit-тесты detection и correlation
│   └── test_parser.py       # Unit-тесты parser
├── .env
├── .env.example
└── .gitignore
```

## Что обнаруживает

| Правило       | Уровень  | Описание                                                        |
| ------------- | -------- | --------------------------------------------------------------- |
| Brute Force   | HIGH     | N неудачных попыток входа (401) с одного IP-адреса внутри заданного временного окна |
| Blacklist Hit | HIGH     | Запросы от IP-адресов, находящихся в TI-фиде                    |
| High Traffic  | MEDIUM   | Один IP превышает установленный лимит запросов                  |
| Traffic Spike | MEDIUM   | Минутный показатель трафика превышает среднее значение в заданное число раз |
| Correlation   | CRITICAL | Brute force + попадание в blacklist от одного IP                |

Для временных бакетов трафика timestamp нормализуется в UTC перед агрегацией и построением графика.

## Быстрый запуск

```bash
git clone https://github.com/n1k2m/soc-log-analyzer
cd soc-log-analyzer

pip install -r requirements.txt

python main.py
```

После запуска результаты появятся в папке `output/`:

* `report.json` - все алерты, отсортированные по уровню критичности
* `activity.png` - график количества запросов в минуту
* `analyzer.log` - лог работы анализатора

## Тесты

Тесты используют стандартный `unittest`, дополнительные зависимости не нужны:

```bash
python -m unittest discover -s tests -v
```

Покрыты ключевые сценарии:

* brute force threshold и time window;
* несколько независимых IP;
* blacklist hit и минимальное количество запросов;
* traffic spike, обычный трафик и пустой input;
* UTC-нормализация timestamp;
* parser для корректных, malformed и invalid строк;
* correlation `BRUTEFORCE + BLACKLIST_HIT → CRITICAL`.

## Конфигурация

Пороговые значения можно изменить в `config.py`:

```python
FAILED_LOGIN_THRESHOLD = 5        # количество ответов 401 для brute force алерта
FAILED_LOGIN_WINDOW_MINUTES = 5   # временное окно для brute force detection
HIGH_REQUEST_THRESHOLD = 200      # количество запросов с одного IP для high traffic
SPIKE_MULTIPLIER = 3              # во сколько раз выше среднего должен быть всплеск
TI_MIN_REQUESTS = 3               # минимум запросов для blacklist alert
```

**Threat Intelligence:**
Инструмент сначала проверяет файл `data/blacklist_cache.json`.
Для использования актуальных данных AbuseIPDB необходимо указать `TI_API_KEY` в `.env`.
Если ключ не задан, анализатор пропускает online-загрузку TI.

Полученные данные автоматически сохраняются в кэш.


## Пример входных данных

```
192.168.1.10 - - [10/Oct/2025:13:55:36 +0000] "POST /login HTTP/1.1" 401 128
45.33.32.156 - - [10/Oct/2025:13:56:10 +0000] "GET / HTTP/1.1" 200 1024
45.33.32.156 - - [10/Oct/2025:13:56:12 +0000] "POST /login HTTP/1.1" 401 128
```

## Пример результата (`report.json`)

```json
{
  "summary": {
    "generated_at": "2025-10-10T14:00:00Z",
    "total_alerts": 4,
    "by_severity": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 1
    }
  },
  "alerts": [
    {
      "type": "BLACKLIST_HIT",
      "ip": "45.33.32.156",
      "requests": 7,
      "abuse_confidence": 97,
      "country": "US",
      "severity": "CRITICAL",
      "correlated": true
    }
  ]
}
```
