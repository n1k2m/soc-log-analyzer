# SOC Log Analyzer

Pet-проект для автоматического анализа логов Apache. Скрипт парсит access.log, проверяет события по правилам безопасности (как в реальных SOC) и обогащает данные через Threat Intelligence API. На выходе получается наглядный визуальный отчет с разбитыми по критичности алертами.

## Структура проекта

```
soc-log-analyzer/
├── main.py            # Точка входа и оркестрация процессов
├── config.py          # Пороговые значения и настройки
├── parser_module.py   # Парсер Apache логов
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
├── .env
├── .env.example
└── .gitignore
```

## Что обнаруживает

| Правило       | Уровень  | Описание                                                        |
| ------------- | -------- | --------------------------------------------------------------- |
| Brute Force   | HIGH     | 5+ неудачных попыток входа (401) с одного IP-адреса             |
| Blacklist Hit | HIGH     | Запросы от IP-адресов, находящихся в TI-фиде                    |
| High Traffic  | MEDIUM   | Один IP превышает установленный лимит запросов                  |
| Traffic Spike | MEDIUM   | Минутный показатель трафика превышает среднее значение в 3 раза |
| Correlation   | CRITICAL | Brute force + попадание в blacklist от одного IP                |

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


## Конфигурация

Пороговые значения можно изменить в `config.py`:

```python
FAILED_LOGIN_THRESHOLD = 5   # количество ответов 401 перед созданием brute force алерта
HIGH_REQUEST_THRESHOLD = 200 # количество запросов с одного IP для high traffic
SPIKE_MULTIPLIER = 3         # во сколько раз выше среднего должен быть всплеск
```

**Threat Intelligence:**
Инструмент сначала проверяет файл `data/blacklist_cache.json`.
Для использования актуальных данных AbuseIPDB необходимо указать `TI_API_KEY` в `config.py`.

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

## Возможные улучшения

* GeoIP-обогащение (MaxMind GeoLite2)
* Парсер Windows Event Logs (формат EVTX)
* Поддержка потоковой обработки логов (`tail -f` / Kafka)
* Веб-интерфейс
* Интеграция Sigma Rules
* Unit-тесты
