import scapy.all as scapy # импорт библиотеки
# функция сканирования - отправка ARP запросов
# отправка осуществляется на широковещательный адрес
# указанной подсети и запись ответов
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
# далее - формирование списка полученных адресов IP+MAC
    for i in answered_list:
        clients_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list
# запуск сканирования указанной подсети (указать свою,
#возможно, такую же, в формате x.x.x.1/24)
scan_result = scan("10.0.2.1/24")
# запись вывода программы в txt файл
scan_to_file = ''.join(map(str, scan_result)) #
#добавление каждого найденного адреса в строку
f = open('1.txt', 'w') # создание файла 1.txt (или любое
#другое название)в режиме w - write (запись)
f.write(scan_to_file) # запись результатов сканирования в
#созданный файл







