import sqlite3
import pandas as pd
import logging

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# 常量定义
EXCEL_PATH = 'Password/information.xlsx'  # 根据实际路径修改
DB_PATH = 'Password/class_website.db'  # 根据实际路径修改

def migrate_data():
    try:
        # 连接到SQLite数据库
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        logging.info("成功连接到 SQLite 数据库")

        # 读取Excel文件
        try:
            df = pd.read_excel(EXCEL_PATH, sheet_name='Sheet1')
            logging.info("成功读取 Excel 文件")
        except FileNotFoundError:
            logging.error(f"未找到 Excel 文件: {EXCEL_PATH}")
            return
        except Exception as e:
            logging.error(f"读取 Excel 文件时出错: {e}")
            return

        # 删除已存在的表（如果需要）
        cursor.execute('DROP TABLE IF EXISTS users')
        logging.info("已删除现有的 users 表")

        # 创建新的表
        cursor.execute('''
            CREATE TABLE users (
                Name TEXT PRIMARY KEY,
                display_name TEXT,
                password TEXT,
                permission INTEGER,
                banned BOOLEAN DEFAULT FALSE,
                last_login TEXT,
                register_time TEXT
            )
        ''')
        logging.info("已创建新的 users 表")

        # 将数据插入到表中
        for _, row in df.iterrows():
            try:
                cursor.execute('''
                    INSERT INTO users (Name, display_name, password, permission, banned, last_login, register_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (row['Name'], row['display_name'], row['password'], row['permission'], row['banned'], row['last_login'], row['register_time']))
            except sqlite3.IntegrityError:
                logging.warning(f"插入数据时出现完整性错误，可能是主键重复: {row['Name']}")
            except Exception as e:
                logging.error(f"插入数据时出错: {e}")

        conn.commit()
        logging.info("数据迁移成功，已提交更改")
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"SQLite 数据库操作出错: {e}")
    except Exception as e:
        logging.error(f"发生未知错误: {e}")

if __name__ == "__main__":
    migrate_data()