import requests
import time
import pandas as pd
import os
import logging
import urllib3
from datetime import datetime
import hashlib
import sys

# ============ КОНФИГУРАЦИЯ ИЗ ПЕРЕМЕННЫХ СРЕДЫ ============
BOT_TOKEN = os.environ.get('BOT_TOKEN')
CHAT_ID = os.environ.get('CHAT_ID')
IDECO_USERNAME = os.environ.get('IDECO_USERNAME')
IDECO_PASSWORD = os.environ.get('IDECO_PASSWORD')
CSV_DOWNLOAD_URL = os.environ.get('CSV_DOWNLOAD_URL')

# Параметры запроса (можно менять)
PARAMS = {
    'filter': '[{"items":[{"column_name":"date_time","operator":"date_range","value":["hour"]}],"link_operator":"and"}]',
    'format_type': 'CSV',
    'sort': '[{"field":"date_time","direction":"desc"}]'
}

CHECK_INTERVAL = 60  # Проверять каждые 60 секунд
LOG_FILE = '/tmp/monitor.log'

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Отключаем предупреждения SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ ФУНКЦИИ ============

def send_telegram_message(text):
    """Отправка сообщения в Telegram"""
    try:
        url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
        payload = {
            'chat_id': CHAT_ID,
            'text': text,
            'parse_mode': 'HTML'
        }
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code == 200:
            logging.info("Сообщение отправлено в Telegram")
            return True
        else:
            logging.error(f"Ошибка отправки: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logging.error(f"Ошибка при отправке в Telegram: {e}")
        return False

def download_csv():
    """Скачивание CSV файла с событиями"""
    try:
        session = requests.Session()
        session.verify = False
        
        headers = {
            'User-Agent': 'SecurityMonitor/1.0',
            'Accept': 'text/csv,application/csv',
        }
        
        # Если есть логин/пароль, используем базовую авторизацию
        auth = None
        if IDECO_USERNAME and IDECO_PASSWORD:
            auth = (IDECO_USERNAME, IDECO_PASSWORD)
        
        logging.info(f"Скачивание CSV с {CSV_DOWNLOAD_URL}")
        
        response = session.get(
            CSV_DOWNLOAD_URL,
            params=PARAMS,
            headers=headers,
            auth=auth,
            timeout=30,
            verify=False
        )
        
        response.raise_for_status()
        
        # Сохраняем временный файл
        temp_file = f"/tmp/events_{datetime.now().strftime('%H%M%S')}.csv"
        with open(temp_file, 'wb') as f:
            f.write(response.content)
        
        logging.info(f"CSV сохранен, размер: {len(response.content)} байт")
        return temp_file
        
    except Exception as e:
        logging.error(f"Ошибка скачивания CSV: {e}")
        return None

def parse_csv_file(file_path):
    """Чтение и парсинг CSV файла"""
    try:
        # Пробуем разные кодировки
        encodings = ['utf-8', 'cp1251', 'windows-1251', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                df = pd.read_csv(file_path, encoding=encoding)
                logging.info(f"CSV прочитан с кодировкой {encoding}, строк: {len(df)}")
                return df
            except UnicodeDecodeError:
                continue
            except Exception:
                continue
        
        # Если ни одна кодировка не подошла
        try:
            df = pd.read_csv(file_path)
            return df
        except:
            return None
            
    except Exception as e:
        logging.error(f"Ошибка парсинга CSV: {e}")
        return None

def get_severity_name(severity_code):
    """Преобразование кода важности в текст"""
    severity_map = {
        '1': 'Критический',
        '2': 'Высокий', 
        '3': 'Средний',
        '4': 'Низкий',
        '5': 'Незначительный'
    }
    severity_str = str(severity_code)
    return severity_map.get(severity_str, f"Уровень {severity_str}")

def check_new_events(last_event_id):
    """Основная функция проверки новых событий"""
    csv_file = download_csv()
    if not csv_file:
        return last_event_id
    
    try:
        df = parse_csv_file(csv_file)
        if df is None or df.empty:
            return last_event_id
        
        # Сортируем по времени
        if 'date_time' in df.columns:
            df = df.sort_values('date_time', ascending=False)
        
        # Берем самое последнее событие
        latest_row = df.iloc[0]
        
        # Создаем ID события
        event_id = str(latest_row.get('sid', ''))
        if not event_id or event_id == 'nan':
            event_str = f"{latest_row.get('date_time', '')}{latest_row.get('source_ip', '')}"
            event_id = hashlib.md5(event_str.encode()).hexdigest()[:10]
        
        # Проверяем новое ли это событие
        if event_id != last_event_id:
            # Формируем сообщение
            severity = get_severity_name(latest_row.get('severity', ''))
            
            # Эмодзи по уровню важности
            emoji = '🔴' if 'крит' in severity.lower() else \
                   '🟠' if 'высок' in severity.lower() else \
                   '🟡' if 'средн' in severity.lower() else '⚪'
            
            message = f"{emoji} <b>НОВОЕ СОБЫТИЕ БЕЗОПАСНОСТИ</b>\n\n"
            message += f"<b> Время:</b> {latest_row.get('date_time', '')}\n"
            message += f"<b> Уровень:</b> {severity}\n"
            message += f"<b> Описание:</b> {latest_row.get('description', '')}\n"
            message += f"<b> Источник:</b> {latest_row.get('source_ip', '')}:{latest_row.get('source_port', '')}\n"
            message += f"<b> Страна:</b> {latest_row.get('source_country', '')}\n"
            message += f"<b> Назначение:</b> {latest_row.get('destination_ip', '')}:{latest_row.get('destination_port', '')}\n"
            message += f"<b> Протокол:</b> {latest_row.get('protocol', '')}\n"
            message += f"<code>ID: {event_id}</code>"
            
            if send_telegram_message(message):
                logging.info(f"Отправлено уведомление для события {event_id}")
                last_event_id = event_id
            else:
                logging.error("Не удалось отправить уведомление")
        else:
            logging.info("Новых событий нет")
            
    except Exception as e:
        logging.error(f"Ошибка при проверке событий: {e}")
    
    finally:
        # Удаляем временный файл
        try:
            if os.path.exists(csv_file):
                os.remove(csv_file)
        except:
            pass
    
    return last_event_id

def main():
    """Основной цикл программы"""
    # Проверка обязательных переменных
    if not BOT_TOKEN or not CHAT_ID or not CSV_DOWNLOAD_URL:
        logging.error("Отсутствуют обязательные переменные окружения!")
        logging.error("Установите: BOT_TOKEN, CHAT_ID, CSV_DOWNLOAD_URL")
        return
    
    logging.info("=" * 60)
    logging.info(" ЗАПУСК МОНИТОРА СОБЫТИЙ БЕЗОПАСНОСТИ")
    logging.info(f" Chat ID: {CHAT_ID}")
    logging.info(f" URL: {CSV_DOWNLOAD_URL}")
    logging.info(f" Интервал: {CHECK_INTERVAL} сек")
    logging.info("=" * 60)
    
    # Отправляем стартовое сообщение
    send_telegram_message("<b>Монитор событий безопасности запущен</b>\nСистема начала мониторинг.")
    
    last_event_id = None
    
    # Основной цикл
    while True:
        try:
            last_event_id = check_new_events(last_event_id)
            time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            break
        except Exception as e:
            logging.error(f"Ошибка в основном цикле: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
