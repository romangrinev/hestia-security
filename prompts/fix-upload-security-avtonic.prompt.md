---
mode: agent
description: Закрыть уязвимость загрузки файлов на avtonic.com — добавить server-side валидацию MIME-типов и размера
---

## Задача: Закрыть уязвимости загрузки файлов

Сервер был скомпрометирован через форму загрузки файлов. Обнаруженная уязвимость:
в `app/Livewire/QuoteForm.php` метод `imagesStep()` использует `SpatieMediaLibraryFileUpload`
с `acceptedFileTypes()` — это **только клиентская (JS) проверка**, которую легко обойти.
На сервере никакой валидации нет.

### Что нужно сделать

**1. Файл `app/Livewire/QuoteForm.php` — метод `imagesStep()`**

Найди оба поля `SpatieMediaLibraryFileUpload` и добавь в каждое:
- `.maxSize()` — ограничение размера в килобайтах
- `.rules()` — server-side валидация через Laravel

Фото (`photos`):
```php
SpatieMediaLibraryFileUpload::make('photos')
    ->collection('photos')
    ->conversion('preview')
    ->reorderable()
    ->multiple()
    ->minFiles(0)
    ->maxFiles(5)
    ->maxSize(10240)  // 10MB на файл
    ->acceptedFileTypes(['image/jpeg', 'image/gif', 'image/png', 'image/bmp'])
    ->rules(['mimetypes:image/jpeg,image/gif,image/png,image/bmp', 'max:10240'])
    ->columnSpan(12),
```

Видео (`videos`):
```php
SpatieMediaLibraryFileUpload::make('videos')
    ->collection('videos')
    ->reorderable()
    ->multiple()
    ->minFiles(0)
    ->maxFiles(5)
    ->maxSize(102400)  // 100MB на файл
    ->acceptedFileTypes(['video/mp4', 'video/mpeg', 'video/quicktime', 'video/avi'])
    ->rules(['mimetypes:video/mp4,video/mpeg,video/quicktime,video/x-msvideo', 'max:102400'])
    ->columnSpan(12),
```

**2. Создай или проверь `app/Http/Middleware` — защита временных файлов Livewire**

Убедись что в `config/livewire.php` (или `config/filesystems.php`) временные загрузки
идут на `local` диск, а **не** в `public/` директорию:

В `config/livewire.php`:
```php
'temporary_file_upload' => [
    'disk' => 'local',        // НЕ public
    'rules' => ['max:102400'], // Глобальный лимит 100MB
    'directory' => 'livewire-tmp',
    'middleware' => 'throttle:60,1',
    'preview_mimes' => [
        'png', 'gif', 'bmp', 'svg', 'wav', 'mp4',
        'mov', 'avi', 'wmv', 'mpeg', 'jpg', 'jpeg',
        'mpga', 'mp3', 'm4a', 'ogg',
    ],
    'max_upload_time' => 5,
    'cleanup' => true,
],
```

**3. Добавь `.htaccess` правило в `storage/app/` чтобы PHP не выполнялся**

Создай файл `storage/app/.htaccess`:
```
<FilesMatch "\.php$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

И аналогично `storage/app/public/.htaccess` и `storage/framework/views/.htaccess`:
```
<FilesMatch "\.php$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

**4. Проверь что `Quote` модель имеет правильные media collections с разрешёнными типами**

В `app/Models/Quote.php` найди метод `registerMediaCollections()` и убедись что есть:
```php
public function registerMediaCollections(): void
{
    $this->addMediaCollection('photos')
        ->acceptsMimeTypes(['image/jpeg', 'image/png', 'image/gif', 'image/bmp']);

    $this->addMediaCollection('videos')
        ->acceptsMimeTypes(['video/mp4', 'video/mpeg', 'video/quicktime', 'video/x-msvideo']);
}
```

Если метода нет — добавь его (нужен `use Spatie\MediaLibrary\HasMedia;` и trait `InteractsWithMedia`).

### Контекст

- Фреймворк: Laravel + Filament + Spatie Media Library + Livewire
- Диск загрузки: `public` (локальный сервер), не S3
- Атакующий загрузил PHP-файл через форму и получил возможность исполнять код

### Проверка после исправления

```bash
# Попробуй загрузить .php файл через форму — должна быть ошибка валидации
# Попробуй загрузить файл > 10MB — должна быть ошибка
# Убедись что в storage/app/ нет исполняемых PHP файлов:
find storage/app -name "*.php" -not -path "*/views/*"
```
