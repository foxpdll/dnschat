Chat over DNS only

Чат через сервера ДНС

Для работы требуется некий сервер с выделенной на него зоной. Например на ваш сервер смотрит запись dnschat.somedomain.net

На сервере необходимо запустить демон коммандой dnschat --server

Клиент при первом запуске генерирует ключ и выводит на консоль

Послать сообщение можно так: dnschat --msg "some text" --addr "xxxxxxxxxxxxxxxxxxxxxxxx.dnschat.somedomain.net"
