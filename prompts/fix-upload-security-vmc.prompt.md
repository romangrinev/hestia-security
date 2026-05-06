---
mode: agent
description: Закрыть уязвимость загрузки файлов на vmaxconstruction.com — добавить server-side валидацию MIME-типов
---

## Задача: Закрыть уязвимости загрузки файлов

Сервер был скомпрометирован — в директории `storage/app/public/` найден PHP-бэкдор
`41afc85bac8d.php` с содержимым `eval(base64_decode($_REQUEST["id"]))`.
Бэкдор попал через форму загрузки вложений.

Первопричина — в `app/Livewire/Quote.php`:
```php
#[Validate(['attachments.*' => 'max:500000'])]
public $attachments = [];
```
Валидируется **только размер файла**, тип файла не проверяется вообще.
Злоумышленник загрузил `.php` файл.

### Что нужно сделать

**1. Файл `app/Livewire/Quote.php` — главный фикс**

Замени валидацию `attachments` на whitelist разрешённых типов + адекватный лимит размера:

```php
#[Validate([
    'attachments.*' => [
        'file',
        'max:10240',
        'mimes:jpg,jpeg,png,gif,pdf,doc,docx,heic,heif',
        'mimetypes:image/jpeg,image/png,image/gif,image/heic,image/heif,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ],
])]
public $attachments = [];
```

> Обрати внимание: `max:500000` = ~488GB. Должно быть `max:10240` = 10MB.

**2. Файл `app/Models/Inquiry.php` — добавь ограничение в Spatie Media Collection**

Найди или создай метод `registerMediaCollections()`:

```php
use Spatie\MediaLibrary\HasMedia;
use Spatie\MediaLibrary\InteractsWithMedia;

class Inquiry extends Model implements HasMedia
{
    use InteractsWithMedia;

    // ... existing code ...

    public function registerMediaCollections(): void
    {
        $this->addMediaCollection('attachments')
            ->acceptsMimeTypes([
                'image/jpeg',
                'image/png',
                'image/gif',
                'image/heic',
                'image/heif',
                'application/pdf',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            ]);
    }
}
```

**3. Файл `resources/views/livewire/quote.blade.php` — добавь атрибут `accept` на input**

Найди `<input type="file"` или Livewire wire:model для attachments и добавь:
```html
accept=".jpg,.jpeg,.png,.gif,.pdf,.doc,.docx,.heic,.heif"
```

**4. Создай `.htaccess` запрещающий исполнение PHP в папках загрузок**

Создай файл `storage/app/.htaccess`:
```
<FilesMatch "\.php$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

Также создай `storage/app/public/.htaccess` с тем же содержимым.

**5. Проверь конфиг Livewire — временные файлы не должны быть в `public/`**

В `config/livewire.php` (если файла нет — создай через `php artisan vendor:publish --tag=livewire:config`):
```php
'temporary_file_upload' => [
    'disk'        => 'local',  // НЕ public!
    'rules'       => ['max:10240'],
    'directory'   => 'livewire-tmp',
    'middleware'  => 'throttle:60,1',
    'max_upload_time' => 5,
    'cleanup'     => true,
],
```

### Контекст

- Фреймворк: Laravel + Livewire (`WithFileUploads`) + Spatie Media Library
- Файлы отправляются на S3 (`disk('s3')`), но **временные** файлы хранятся локально в `storage/`
- Бэкдор был загружен как `.php` файл в `storage/app/public/`
- Есть reCAPTCHA и Honeypot защита от спама — это хорошо, но они не блокируют тип файла

### Проверка после исправления

```bash
# 1. Запусти тесты (если есть):
php artisan test --filter=QuoteTest

# 2. Попробуй загрузить .php файл вручную через форму — должна быть ошибка валидации

# 3. Убедись что в storage/ нет PHP файлов вне views:
find storage/app -name "*.php"

# 4. Проверь .htaccess в папках с загрузками:
cat storage/app/.htaccess
cat storage/app/public/.htaccess
```

### Дополнительно (опционально но рекомендуется)

После загрузки файла на S3, Spatie Media Library сохраняет путь в БД.  
Если хочешь добавить дополнительную проверку реального MIME-типа файла (не по расширению),
добавь в `create()` метод Quote.php перед `addMedia()`:

```php
foreach ($this->attachments as $item) {
    $realMime = mime_content_type($item->getRealPath());
    $allowed = [
        'image/jpeg', 'image/png', 'image/gif', 'image/heic', 'image/heif',
        'application/pdf', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ];
    if (!in_array($realMime, $allowed)) {
        $this->addError('attachments', 'File type not allowed: ' . $realMime);
        return;
    }
    $inquiry->addMedia($item->getRealPath())->toMediaCollection('attachments', 's3');
}
```
