# Lean Security Agent

Локальный AI-агент для анализа защищенности веб-приложений.
LLM в Docker-песочнице, без доступа к интернету и хосту.

## Как работает

1. Оператор ставит задачу (например, "найти SQL-инъекции на 172.20.0.10:3000")
2. Оркестратор отправляет запрос к локальной LLM (Bionic Studio / LM Studio)
3. Модель возвращает JSON с командой: `{"tool":"run_command","argv":[...]}`
4. Оркестратор проверяет команду по белому списку, запускает в Docker-контейнере
5. Вывод обрезается (pruner), результат возвращается модели для следующего шага

## Архитектура

```
локальная LLM (127.0.0.1:1234)
     | OpenAI API
оркестратор (Python)
     | docker exec
контейнер security-agent (172.20.0.20)
     | HTTP только к цели
цель (172.20.0.10:3000)
```

Контейнер изолирован:
- nobody, read-only FS, лимит 2GB RAM
- Сеть --internal (без интернета и доступа к хосту)
- Белый список команд + блокировка опасных паттернов
- Детектор зацикливания (3 повтора = стоп)
- Smart pruner: первые 50 + последние 50 строк

## Требования

- Python 3.11+
- Docker
- GPU 8GB+ VRAM (RTX 4060/5060)
- LM Studio или Bionic Studio с моделью Qwen 9B Q4_K_M

## Быстрый старт

```
git clone https://github.com/bot067/lean-security-agent.git
cd lean-security-agent

# Запустить LM Studio, загрузить модель, убедиться что API на :1234
# Собрать контейнер и поднять цели:
docker compose -f config/docker-compose.yml up -d

# Запустить:
python src/orchestrator/main.py --task "probe 172.20.0.10:3000"
```

## Тестирование

```
pytest tests/unit/
pytest tests/integration/
pytest tests/security/
```

## Структура

```
lean-security-agent/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── docs/              # документация
├── src/               # исходный код
│   ├── orchestrator/  # точка входа, сессии
│   ├── validator/     # парсер tool_call, политики
│   ├── executor/      # docker exec
│   └── utils/         # логгер, ротация
├── config/            # Dockerfile, compose, политики
├── tests/
├── scripts/
└── examples/
```

## Лицензия

MIT