# Local Inference Benchmark — RTX 5060 8GB (EBM Level I)

Воспроизводимый замер локального инференса, на котором работает планировщик
Lean Security Agent. Все цифры получены на реальном железе и проверяемы.

## Оборудование

| Параметр | Значение |
|---|---|
| GPU | NVIDIA GeForce RTX 5060, **8151 MiB (8 ГБ)** |
| Драйвер | 610.74 (Compute Capability 12.0, sm_120) |
| CPU / RAM | Intel Core i5-12400F / 15.8 ГБ |
| Движок | Bionic (LM Studio engine), OpenAI API `http://127.0.0.1:1234/v1` |
| Модель | `huihui-qwen3.5-9b-claude-4.6-opus-abliterated-heretic` Q4_K_S (4.98 ГБ) |

## Замеры (свип по контексту, 300 токенов на прогон, temp 0.1)

| ctx | VRAM | Темп. | Скорость | Мощность |
|---|---|---|---|---|
| 2048 | 5840 МБ | 51 °C | 58.1 ток/с | 40.6 W |
| **4096** | **5943 МБ** | 51 °C | **57.0 ток/с** | 70.9 W |
| 8192 | 5963 МБ | 51 °C | 59.5 ток/с | 68.1 W |
| 16384 | 6224 МБ | 51 °C | 59.9 ток/с | 54.1 W |

**Вывод:** скорость генерации практически не зависит от размера контекста
(57–60 ток/с); VRAM остаётся ниже 88% даже при ctx 16384. Потолок железа — ~60 ток/с.

## Сверка с прод-логами (сентябрь 2026)

Из серверных логов Bionic — чистая скорость генерации:

```
eval time = 1685.16 ms /  99 tokens (17.20 ms/tok, 58.15 tok/s)
eval time = 3346.48 ms / 199 tokens (16.90 ms/tok, 59.17 tok/s)
eval time = 4698.02 ms / 300 tokens (15.71 ms/tok, 63.64 tok/s)
eval time = 2364.04 ms / 143 tokens (16.65 ms/tok, 60.07 tok/s)
```

Замеры совпадают с прод-логами → результат воспроизводим (EBM Level I).

## Зафиксированные отказы

- **Контекст > 10k в агентском цикле:** `request (15745 tokens) exceeds the available context size (10496 tokens)` → сбой запроса. Отсюда архитектурная необходимость Smart Pruner.
- **Модель 12B на 8 ГБ:** 1.0–1.8 ток/с против 57–60 у 9B (в 40 раз медленнее) → OOM-класс.
- **reasoning без `think=False`:** пустые ответы, теги `thinking` внутри `content` → падение парсера.
- **Свободный JSON без `json_schema`:** markdown-заборы ```json внутри `content`; у движка `json_object` → HTTP 400.

## Оптимальная конфигурация планировщика

```ini
context_length  = 4096
temperature     = 0.1
think           = OFF
stopStrings     = []
response_format = json_schema   # json_object не поддерживается (400)
```

## Файлы

| Файл | Содержание |
|---|---|
| `context_sweep.json` | сырые данные свипа (VRAM/темп/мощность/ток-с) |
| `bench_context_sweep.py` | скрипт воспроизведения замера |
| `EBM_REPORT_RU.md` | полный эмпирический отчёт (EBM Level I) |

## Воспроизведение

```bash
python bench_context_sweep.py
```

Требуется запущенный Bionic/LM Studio на `:1234` и локальная Qwen 9B Q4.
