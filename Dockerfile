# Базовый образ
FROM golang:1.24 AS builder

# Рабочая директория
WORKDIR /app

# Копируем исходный код
COPY . .

# Собираем приложение
RUN go build -o meddos .

# Финальный образ
FROM debian:stable-slim

# Устанавливаем зависимости
RUN apt-get update && apt-get install -y ca-certificates

# Рабочая директория
WORKDIR /app

# Копируем бинарник из builder-стадии
COPY --from=builder /app/meddos /app/meddos
# Копируем конфиги
COPY configs /app/configs

# Открываем порт
EXPOSE 8080

# Запускаем приложение
CMD ["/app/meddos"]
