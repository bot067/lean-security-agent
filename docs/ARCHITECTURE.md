# Архитектура

Lean Security Agent состоит из четырёх модулей:

- **orchestrator** — сессия, прунер, точка входа
- **validator** — парсер tool_call, политики (белый/чёрный список)
- **executor** — выполнение в Docker-песочнице
- **utils** — логгер, ротация

Внешние компоненты:

- **Bionic Studio / LM Studio** — OpenAI-compatible LLM сервер (:1234)
- **Docker** — контейнер security-agent (nobody, R/O, 2GB)