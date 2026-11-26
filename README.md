# Hookbox

Hookbox — сервис вебхуков для Windows и Linux. Служба на Go принимает JSON по HTTP, проверяет Bearer-токен и права пользователя, затем по порядку выполняет настроенные команды и HTTP-запросы. Конфигурация хранится в YAML.

## Запуск

Готовые сборки `hookbox-windows-amd64` и `hookbox-linux-amd64` доступны в разделе Artifacts успешного прогона [GitHub Actions](https://github.com/nem1989/hookbox/actions/workflows/tests.yml?query=branch%3Amain). В комплект Windows входят `hookbox.exe`, `Hookbox Manager.exe` и загрузчик WebView2. В Linux комплект включает бинарник `hookbox` и unit systemd.

Для локального запуска на Windows дважды щёлкни `Start Hookbox.cmd`, затем открой `Hookbox Manager.exe` и введи токен из консоли. Порт вебхуков задаётся в `config.yaml` (по умолчанию 8080), панель открывается на `127.0.0.1:8081`. Установка постоянной службы на Windows и Linux описана в [инструкции по установке](deploy/go/README.md).

## Разработка

Для сборки панели нужны Node.js и npm, для службы — версия Go из [go.mod](go.mod). Windows Manager собирается .NET SDK 10 и использует WebView2 Runtime.

```sh
cd web
npm install
npm run build
cd ..
go build ./cmd/hookbox
go test -race -count=1 ./...
```

CI запускает тесты Go на Windows и Linux, собирает дистрибутивы, проверяет работу панели в браузере и в Windows Manager.

## Архив Python

Исходники, тесты, конфигурация и документация прежней версии собраны в [reference/python](reference/python). Полная история прежней `main` сохранена в ветке [archive/python-main](https://github.com/nem1989/hookbox/tree/archive/python-main). Python требуется только для запуска архивной реализации и её тестов.
