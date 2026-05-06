# hestia-security

Security hardening, monitoring and incident response scripts for **HestiaCP** servers (Ubuntu/Debian, nginx + PHP-FPM).

## Quick Install

```bash
git clone https://github.com/romangrinev/hestia-security.git /root/server-security
cd /root/server-security
cp security-audit.env.example /etc/security-audit.env
nano /etc/security-audit.env   # заполните API-ключ и email
bash install.sh
```

## Scripts

| Скрипт | Запуск | Описание |
|--------|--------|----------|
| `01-security-audit.sh` | ежедневно в 3:00 | Полный аудит: шеллы, cron, входы, процессы, изменённые файлы. Отправляет отчёт на email |
| `02-git-cleanup.sh` | вручную | Откатывает все git-репозитории (`git checkout -- . && git clean -fd`) |
| `03-hardening.sh` | вручную (один раз) | PHP-хардинг, SSH, fail2ban, права файлов, inotifywait-мониторинг |
| `04-git-auto-restore.sh` | каждые 6 часов | Автоматически откатывает изменённые git-репозитории с email-уведомлением |

## Configuration

```bash
# /etc/security-audit.env
RESEND_API_KEY="re_xxxxxxxx"          # Resend.com API key
RESEND_FROM="security@yourdomain.com" # верифицированный домен в Resend
RESEND_TO="admin@youremail.com"       # куда слать отчёты
```

Скрипты автоматически определяют пользователей через HestiaCP (`v-list-users`).  
Чтобы задать список вручную — раскомментируйте строку `USERS=` в начале нужного скрипта.

## Manual Run

```bash
# Аудит (запустить прямо сейчас)
sudo bash /root/server-security/01-security-audit.sh 2>&1 | tee /tmp/audit.txt

# Хардинг (первый раз на новом сервере)
sudo bash /root/server-security/03-hardening.sh 2>&1 | tee /tmp/hardening.txt

# Очистка через git (после инцидента)
sudo bash /root/server-security/02-git-cleanup.sh 2>&1 | tee /tmp/cleanup.txt
```

## Requirements

- Ubuntu 20.04+ / Debian 11+
- HestiaCP
- `curl`, `git`, `inotify-tools`, `fail2ban`
- Resend.com account (бесплатно до 3000 писем/месяц)

## Firewall (iptables)

После первого запуска `03-hardening.sh` рекомендуется ограничить SSH только вашим IP:

```bash
# Разрешить SSH только с вашего IP
sudo iptables -R INPUT 10 -p tcp -s ВАШ_IP --dport 22 -j ACCEPT

# Сохранить правила (переживут перезагрузку)
sudo netfilter-persistent save
```

Чтобы добавить ваш IP в whitelist fail2ban (не будет заблокирован):

```bash
# В /etc/fail2ban/jail.local в секции [DEFAULT]:
ignoreip = 127.0.0.1/8 ВАШ_IP
sudo systemctl restart fail2ban
```

Скрипт `01-security-audit.sh` автоматически проверяет iptables и предупреждает если:
- SSH открыт для `0.0.0.0/0` (весь интернет)
- Политика `INPUT` не `DROP`
- MySQL доступен извне
- fail2ban не активен

## Cron (настраивается через `install.sh`)

```
0 3 * * *   root bash /root/server-security/01-security-audit.sh >> /var/log/security-audit.log 2>&1
0 */6 * * * root bash /root/server-security/04-git-auto-restore.sh >> /var/log/git-auto-restore.log 2>&1
```
