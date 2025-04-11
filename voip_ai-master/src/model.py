import re
from datetime import datetime
from peewee import Model, CharField
from playhouse.db_url import connect
from config import DB_USER, DB_PASS, DB_PORT, DB_DATABASE

database = connect(f'mysql://{DB_USER}:{DB_PASS}@127.0.0.1:{DB_PORT}/{DB_DATABASE}')


class BaseModel(Model):
    class Meta:
        database = database

    def __str__(self):
        return str(self.id)


class User(BaseModel):
    telephone = CharField(max_length=11)
    name = CharField(max_length=255)
    city = CharField(max_length=255, null=True)
    coldrooms_code = CharField(max_length=255)
    coldrooms_phone = CharField(max_length=255)


with database:
    database.create_tables([User])


def validate_phone(value):
    pattern = r"^(?:\+98|0098|98|0)?(9\d{9})$"
    match = re.match(pattern, value)

    if match:
        # گرفتن شماره اصلی (10 رقمی که با 9 شروع می‌شود)
        main_number = match.group(1)
        # افزودن پیشوند 0 به شماره
        return f"0{main_number}"
    else:
        # شماره نامعتبر است
        return False


class LoginUser(BaseModel):
    email = CharField(unique=True)
    password = CharField()  # در حالت حرفه‌ای، باید هش‌شده باشد

with database:
    database.create_tables([User, LoginUser])
