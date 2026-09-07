# Router Web (HTB Challenge, теория)

**Категория:** web / firmware. Карточка: новый web-сервис на роутере после патча старого бага.

Флага и эксплойта в этом каталоге нет.

## Класс

В прошивке два сервиса. Старый (`router-management`) по сюжету уже закрыт. Новый — панель на Crow C++ (`router-web-panel`): шаблоны index/admin/config/devices.

Типичная картина учебных роутеров:

1. **Admin Utility** спрятан за флагом режима шаблона (`devMode`), кнопка disabled без него.
2. Форма **ping** на админке — класс **инъекция в команду ОС**, если хост склеивается в shell.

Смотреть в корне прошивки (`rootfs.ext2`): `/opt/router-web-panel`, `/usr/bin/router-web-panel`, `admin.mustache`, обработчик ping. Не копировать готовые строки ping в форму.

## Защита

- argv без shell, allowlist хоста (буквы/цифры/точка);
- admin не включать «скрытой ссылкой», а отдельной ролью и аутентификацией;
- не оставлять debug/devMode в релизе.

## Lab Coach

```bash
python -m lab_coach session-init routerweb offline --category web
python -m lab_coach class "router admin ping command injection"
python -m lab_coach next routerweb --category web
```

Живой docker с карточки HTB — только ваш Spawn, в `SPAWNED_TARGET`. Флаг сдаёте на площадке.
