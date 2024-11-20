import json
import psycopg2
from psycopg2 import sql

# Подключение к PostgreSQL
conn = psycopg2.connect(
    dbname="Suricata_db",
    user="postgres",
    password="22502",
    host="localhost",
    port="5432"
)
cursor = conn.cursor()

# Функция для вставки данных в базу
def insert_closed_stats(data):
    try:
        query = sql.SQL("""
            INSERT INTO suricata_closed_stats (timestamp, src_ip, closed_tcp_count, closed_udp_count, closed_icmp_count)
            VALUES (%s, %s, %s, %s, %s)
        """)
        cursor.execute(query, (
            data.get('timestamp'),
            data.get('src_ip'),
            data.get('closed_tcp_count', 0),
            data.get('closed_udp_count', 0),
            data.get('closed_icmp_count', 0)
        ))
        conn.commit()
    except Exception as e:
        print(f"Ошибка при вставке данных: {e}")

# Парсер файла eve.json
def parse_logs(file_path):
    with open(file_path, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line)  # Читаем одну строку JSON
                if 'event_type' in log_entry and log_entry['event_type'] == 'stats':
                    # Обрабатываем только записи с "stats: closed"
                    stats_closed = log_entry.get('stats', {}).get('closed', {})
                    if stats_closed:
                        insert_closed_stats({
                            'timestamp': log_entry.get('timestamp'),
                            'src_ip': log_entry.get('src_ip'),
                            'closed_tcp_count': stats_closed.get('tcp', 0),
                            'closed_udp_count': stats_closed.get('udp', 0),
                            'closed_icmp_count': stats_closed.get('icmp', 0)
                        })
            except json.JSONDecodeError:
                print("Ошибка декодирования JSON")
            except Exception as e:
                print(f"Ошибка обработки строки: {e}")

# Основная часть
if __name__ == "__main__":
    log_file = "D:\Code\Sur\logs\eve.json"  # Укажите путь к вашему файлу логов
    parse_logs(log_file)

# Закрытие соединения
cursor.close()
conn.close()
