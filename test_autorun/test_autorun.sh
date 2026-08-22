if ls -la ~/.test_app2 > ~/test_autorun.txt 2>&1; then
    echo "Успешно: список сохранён в файл"
else
    echo "ОШИБКА: не удалось получить список папки" > ~/test_autorun.txt
    echo "Дата: $(date)" >> ~/test_autorun.txt
    echo "Причина: папка не существует или нет прав доступа" >> ~/test_autorun.txt
fi
