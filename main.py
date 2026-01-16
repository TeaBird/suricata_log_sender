import requests
import time
import json
import os
import sys
from datetime import datetime
import urllib3

urllib3.disable_warnings()

print("=" * 70)
print("МОНИТОР СОБЫТИЙ С ТОКОНОМ IDECO")
print("=" * 70)

#чувствительные данные
BOT_TOKEN = ""
CHAT_ID = ""
BASE_URL = ""
EVENTS_URL = f"{BASE_URL}/ips/alerts"
IDECO_TOKEN = ""
SESSION_TOKEN = ""

def send_telegram(msg):
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        r = requests.post(url, json={
            'chat_id': CHAT_ID,
            'text': msg,
            'parse_mode': 'HTML'
        }, timeout=10)
        return r.status_code == 200
    except:
        return False

def test_with_token():
    """Тестируем доступ с токеном"""
    session = requests.Session()
    session.verify = False
    
    # добавляем куки/токены
    cookies = {
        IDECO_TOKEN.split('=')[0] if '=' in IDECO_TOKEN else IDECO_TOKEN: 
        IDECO_TOKEN.split('=')[1] if '=' in IDECO_TOKEN else SESSION_TOKEN
    }
    
    for key, value in cookies.items():
        session.cookies.set(key.strip(), value.strip())
    
    # также пробуем как заголовок
    headers = {
        'Authorization': f'Bearer {SESSION_TOKEN}',
        'X-Auth-Token': SESSION_TOKEN,
        'Cookie': f'{IDECO_TOKEN}={SESSION_TOKEN}' if '=' not in IDECO_TOKEN else IDECO_TOKEN
    }
    
    print(" Тестирую доступ с токеном...")
    
    # пробуем разные варианты
    test_cases = [
        {"method": "cookies_only", "session": session, "headers": {}},
        {"method": "with_auth_header", "session": session, "headers": {'Authorization': f'Bearer {SESSION_TOKEN}'}},
        {"method": "with_x_auth", "session": session, "headers": {'X-Auth-Token': SESSION_TOKEN}},
        {"method": "cookie_header", "session": requests.Session(), "headers": {'Cookie': f'{IDECO_TOKEN}={SESSION_TOKEN}'}}
    ]
    
    for test in test_cases:
        print(f"\n  Пробую метод: {test['method']}")
        try:
            test_session = test['session']
            test_session.verify = False
            
            # добавляем заголовки
            for key, value in test['headers'].items():
                test_session.headers[key] = value
            
            response = test_session.get(EVENTS_URL, timeout=10)
            print(f"    Статус: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    events = data.get('data', [])
                    print(f" УСПЕХ! Событий: {len(events)}")
                    
                    if events:
                        print(f"    Пример первого события:")
                        event = events[0]
                        print(f"      Тип: {event.get('description', 'N/A')}")
                        print(f"      Результат: {event.get('result', 'N/A')}")
                        print(f"      Важность: {event.get('severity', 'N/A')}")
                    
                    return test_session, test['headers'], True
                    
                except json.JSONDecodeError:
                    print(f"    Ответ не JSON: {response.text[:200]}")
            else:
                print(f"    Ответ: {response.text[:100]}")
                
        except Exception as e:
            print(f"    Ошибка: {e}")
    
    return None, {}, False

def get_severity_text(severity_code):
    """Преобразование кода важности в текст"""
    severity_map = {
        1: " Критичный",
        2: " Опасный", 
        3: " Незначительный",
        4: " Информационный"
    }
    return severity_map.get(severity_code, f"Уровень {severity_code}")

def format_event_message(event):
    """Форматирование события для Telegram - ТОЛЬКО blocked события"""
    try:
        # Проверяем, что событие blocked
        result = event.get('result', '').lower()
        if result != 'blocked':
            return None  # Пропускаем не-blocked события
        
        # Получаем важность
        severity_code = event.get('severity', 0)
        severity_text = get_severity_text(severity_code)
        
        # Форматируем время (YYYYMMDDHHMMSS → HH:MM:SS)
        dt = str(event.get('date_time', ''))
        if len(dt) == 14:
            time_str = f"{dt[8:10]}:{dt[10:12]}:{dt[12:14]}"
        else:
            time_str = dt
        
        
        msg = f"<b></b>"
        msg += f"<b>Важность:</b> {severity_text}\n"
        msg += f"<b>Тип:</b> {event.get('description', '')}\n"
        
        # Источник
        source_ip = event.get('source_ip', '')
        source_port = event.get('source_port', '')
        source_country = event.get('source_country', '')
        
        msg += f"<b>Источник:</b>\n"
        msg += f"  • IP: {source_ip}:{source_port}\n"
        if source_country:
            msg += f"  • Страна: {source_country}\n"
        
        # Назначение
        dest_ip = event.get('destination_ip', '')
        dest_port = event.get('destination_port', '')
        dest_country = event.get('destination_country', '')
        
                
        security_event = event.get('security_event', '')
        if security_event:
            msg += f"<b>Событие:</b> {security_event}"
        
        return msg
        
    except Exception as e:
        print(f"Ошибка форматирования: {e}")
        return f"<b>BLOCKED ALERT</b>\nID: {event.get('sid', 'N/A')}"

def main():
    print(f"Использую токен: {IDECO_TOKEN}")
    print(f"Значение: {SESSION_TOKEN[:20]}...")
    
    # Тест Telegram
    print("\nТестирую Telegram...")
    if send_telegram(" Запускаю монитор с токеном IDECO (только blocked события)"):
        print("✓ Telegram работает")
    else:
        print("✗ Проблема с Telegram")
    
    # Тест с токеном
    session, headers, success = test_with_token()
    
    if not success:
        print("\n Не удалось подключиться с токеном")
        print(" Попробуйте:")
        print("1. Обновите токен (войдите заново в браузере)")
        print("2. Проверьте правильность токена")
        return
    
    print("\n" + "="*70)
    print(" ПОДКЛЮЧЕНИЕ УСПЕШНО! НАЧИНАЮ МОНИТОРИНГ...")
    print("="*70)
    
    send_telegram(" Успешное подключение к IDECO!\nМониторю только BLOCKED события...")
    
    last_events = set()  # Храним ID последних событий
    
    try:
        cycle = 0
        while True:
            cycle += 1
            current_time = datetime.now().strftime("%H:%M:%S")
            print(f"\n[{current_time}] Цикл #{cycle}")
            
            # Параметры запроса (как в интерфейсе)
            params = {
                'filter': '[{"items":[{"column_name":"date_time","operator":"date_range","value":["hour"]}],"link_operator":"and"}]',
                'sort': '[{"field":"date_time","direction":"desc"}]',
                'limit': 20  # Больше событий для фильтрации
            }
            
            try:
                # Делаем запрос
                response = session.get(
                    EVENTS_URL,
                    params=params,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    all_events = data.get('data', [])
                    
                    # Фильтруем только blocked события
                    blocked_events = [e for e in all_events if e.get('result', '').lower() == 'blocked']
                    
                    print(f" Всего событий: {len(all_events)}")
                    print(f" BLOCKED событий: {len(blocked_events)}")
                    
                    if blocked_events:
                        # Собираем ID текущих BLOCKED событий
                        current_event_ids = set()
                        for event in blocked_events:
                            sid = event.get('sid', '')
                            eid = event.get('id', '')[:8]
                            if sid:
                                current_event_ids.add(f"{sid}_{eid}")
                        
                        # Находим новые BLOCKED события
                        new_ids = current_event_ids - last_events
                        
                        if new_ids:
                            print(f" Найдено новых BLOCKED событий: {len(new_ids)}")
                            
                            # Для каждого нового BLOCKED события
                            blocked_count = 0
                            for new_id in new_ids:
                                # Находим полные данные события
                                for event in blocked_events:
                                    sid = event.get('sid', '')
                                    eid = event.get('id', '')[:8]
                                    if f"{sid}_{eid}" == new_id:
                                        # Формируем сообщение
                                        msg = format_event_message(event)
                                        
                                        if msg:  # Проверяем что сообщение создано (только для blocked)
                                            # Отправляем
                                            if send_telegram(msg):
                                                print(f"  ✓ Отправлено BLOCKED: {new_id}")
                                                print(f"    Важность: {event.get('severity', 'N/A')}")
                                                print(f"    Тип: {event.get('description', '')}")
                                                blocked_count += 1
                                            else:
                                                print(f"  ✗ Ошибка отправки: {new_id}")
                                        break
                            
                            if blocked_count > 0:
                                print(f"  Всего отправлено BLOCKED уведомлений: {blocked_count}")
                            
                            # Обновляем список последних событий
                            last_events = current_event_ids
                        else:
                            print(" Новых BLOCKED событий нет")
                            
                        # Показываем последнее BLOCKED событие для информации
                        if blocked_events:
                            latest = blocked_events[0]
                            print(f"  Последнее BLOCKED: {latest.get('description', '')}")
                            print(f"    Важность: {latest.get('severity', 'N/A')}")
                            print(f"    {latest.get('source_ip', '')} → {latest.get('destination_ip', '')}")
                        
                    else:
                        print(" Нет BLOCKED событий за последний час")
                        
                        # Но покажем последнее событие любого типа для информации
                        if all_events:
                            latest_all = all_events[0]
                            print(f"  Последнее событие (любое): {latest_all.get('description', '')}")
                            print(f"    Результат: {latest_all.get('result', 'N/A')}")
                            print(f"    Важность: {latest_all.get('severity', 'N/A')}")
                        
                else:
                    print(f"✗ Ошибка HTTP: {response.status_code}")
                    print(f"  Ответ: {response.text[:200]}")
                    
            except Exception as e:
                print(f"✗ Ошибка запроса: {e}")
            
            # Ожидание 60 секунд
            print("\n Следующая проверка через 60 сек...")
            for i in range(60, 0, -1):
                sys.stdout.write(f"\rОжидание: {i:3d} сек.")
                sys.stdout.flush()
                time.sleep(1)
            print()
            
    except KeyboardInterrupt:
        print("\n\n Остановка по запросу пользователя...")
        send_telegram(" Монитор остановлен")
    except Exception as e:
        print(f"\n\n Критическая ошибка: {e}")
        send_telegram(f" Аварийная остановка: {str(e)[:100]}")

if __name__ == "__main__":
    main()
