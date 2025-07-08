# Сервис аутентификации

Сервис предоставляет JWT-аутентификацию с использованием access/refresh токенов и сессионным управлением.

## Основные возможности
- Генерация access и refresh токенов
- Обновление пары токенов
- Валидация сессий
- Выход из системы (logout)
- Защита от несанкционированного доступа
- Уведомления через webhook о подозрительной активности

## Требования
- Go 1.24+
- PostgreSQL
- Конфигурационные файлы (DBconfig.json, AuthConfig.json)

## Примеры запросов к серверу
- curl -X POST http://localhost:8080/auth/{GUID} вместо {GUID} ввести тестовый GUID
- Ответы: http.Error() или json в случае успеха с access и refresh токенами
-
- curl -X POST -H "Authorization: Bearer {access}" -H "Refresh: Refresh {refresh}" http://localhost:8080/refresh 
- вместо {access} и {refresh} надо ввести токена полученные в запросе к http://localhost:8080/auth/{GUID}
- Ответы: http.Error() или json в случае успеха с access и refresh токенами, так же в случае смены IP отправляет POST запрос на webhook указаный в конфиге
-
- curl -X GET -H "Authorization: Bearer {access}" http://localhost:8080/GUID
- Ответы: http.Error() или json с вашим GUID
-
- curl -X POST -H "Authorization: Bearer {access}" http://localhost:8080/logout вместо {access} надо ввести полученный access токен
- Ответы: http.Error() или http.StatusOk

