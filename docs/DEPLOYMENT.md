# Развёртывание

1. Установить LM Studio или Bionic Studio
2. Загрузить Qwen 9B Q4_K_M или аналогичную
3. Убедиться что API отвечает на 127.0.0.1:1234
4. `docker compose -f config/docker-compose.yml up -d`
5. `python src/orchestrator/main.py --task "probe 172.20.0.10:3000"`