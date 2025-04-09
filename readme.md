# Network TUN Interface Analyzer

Утилита для создания TUN-интерфейса и анализа сетевого трафика с детализацией TCP/UDP пакетов.

##  Основные функции

- Создание и настройка виртуального TUP-интерфейса
-  Перехват и анализ IPv4 трафика
-  Парсинг и отображение:
    - IP-заголовков
    - TCP-заголовков (порты, sequence numbers, флаги)
    - UDP-заголовков (порты, длина пакета)
- Проверка прав администратора

##  Установка и запуск

### Требования
- Go 1.16+
- Права администратора/root
- Установка wintun.dll (https://www.wintun.net/) добавить нужный .dll в System32

### Установка зависимостей
```bash
go get golang.org/x/sys/windows
go get golang.zx2c4.com/wintun
go get golang.org/x/net/ipv4
```

###  Сборка проекта
```bash
go build -o scantune.exe main.go
```

### Запуск (с правами администратора)
```bash
./tap-analyzer.exe
```
* чтобы залить траффик в туннель выполните команду:
```bash
Sudo route add 0.0.0.0 mask 0.0.0.0 <IP TUN INTERFACE>
```

### Контакты:
- Telegram: @sculp2ra
- Email: dimakuhtey1@gmail.com
- Mobile: +7 (912) 98-95-416
