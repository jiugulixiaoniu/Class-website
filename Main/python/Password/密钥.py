import random
import string


def generate_random_string():
    """生成一个避免混淆字符的随机字符串，格式为'XXXXX XXXXX XXXXX XXXXX XXXXX'"""
    # 排除容易混淆的字符：O, 0, I, 1, l（小写的L）
    chars = string.ascii_uppercase.replace('O', '').replace('I', '') + string.digits.replace('0', '').replace('1', '')

    # 生成五个部分，每部分5个字符
    parts = []
    for _ in range(5):
        part = ''.join(random.choices(chars, k=5))
        parts.append(part)

    return ' '.join(parts)


# 生成并打印100段随机字符串
for _ in range(9000):
    print(generate_random_string())