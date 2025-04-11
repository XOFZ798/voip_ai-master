from src.model import User
import aiohttp
from datetime import datetime
from config import PHONE_MELIPAYAMAK, Melipayamak_API
import json
import asyncio
import os
from src.logger_config import logger, PATH
from rapidfuzz import process


class Report:
    def __init__(self, phone):
        self.user = None
        self.phone = phone
        self.coldrooms_phone_list = []
        self.reports = {}

    async def init_async(self):
        try:
            self.user = User.select().where(
                User.telephone.contains(self.phone)
            )
            if not self.user.exists():
                phone_notfound = os.path.join(PATH, "audio", "important_PhoneNotFound")
                raise AttributeError(f"User with phone {self.phone} not found.", phone_notfound)
            return self.user
        except AttributeError as e:
            message, value = e.args[0]
            raise NotImplementedError((message, value))
        except NotImplementedError as e:
            message, value = e.args[0]
            raise NotImplementedError((message, value))
        except Exception as e:
            database_error = os.path.join(PATH, "audio", "important_DataBase_error")
            raise NotImplementedError((f"Database error while retrieving user: {str(e)}", database_error))

    def check_city(self, user_input):
        cities = [user.city for user in self.user]

        words = user_input.split()
        best_city = None
        best_score = 0
        for word in words:
            match = process.extractOne(word, cities, score_cutoff=75)  # 75% similarity threshold
            if match and match[1] > best_score:  # Check if this match is the best so far
                best_city = match[0]
                best_score = match[1]
        if best_city:
            self.user = [user for user in self.user if user.city == best_city]
            return best_city
        else:
            return None

    async def send_message(self):
        data = {
            'from': PHONE_MELIPAYAMAK,
            'to': self.coldrooms_phone_list,
            'text': 'Report لغو11',
            'udh': ''
        }
        self.start_time = datetime.now()
        SendMessage_error = os.path.join(PATH, "audio", "important_sendmessage_error")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                        f'https://console.melipayamak.com/api/send/advanced/{Melipayamak_API}', json=data
                ) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}")
                        return False

                    response_data = await response.json()
                    logger.info(f"SMS sent successfully: {response_data}")
                    return True
        except aiohttp.ClientError as e:
            logger.error(f"Network error while sending message: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in send_message: {str(e)}")
        raise NotImplementedError(("Error accurred in sending message to melly payamak", SendMessage_error))

    async def get_reports(self):

        PhonCool = self.user.coldrooms_phone
        PhonCool = PhonCool.lstrip("0")
        self.coldrooms_phone_list.append(PhonCool)
        await self.send_message()

        await self.get_messages_loop()
        return self.reports

    async def get_messages_loop(self):
        while True:
            await self.get_messages(self.start_time)
            if len(self.reports) >= len(self.coldrooms_phone_list):
                return False
            await asyncio.sleep(3)

    async def get_messages(self, start_time):
        """Retrieves incoming messages from Melipayamak API."""
        data = {'type': 'in', 'number': PHONE_MELIPAYAMAK, 'index': 0, 'count': 4}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                        f'https://console.melipayamak.com/api/receive/messages/{Melipayamak_API}', json=data
                ) as response:
                    if response.status != 200:
                        logger.error(f"Failed to fetch messages: HTTP {response.status}")
                        return False

                    response_data = await response.json()
                    for item in response_data.get("messages", []):
                        datetime_object = datetime.strptime(item['sendDate'], "%Y-%m-%dT%H:%M:%S.%f")
                        if datetime_object >= start_time and item['sender'] in self.coldrooms_phone_list:
                            self.reports[item['sender']] = item["body"]
                    return True

        except aiohttp.ClientError as e:
            logger.error(f"Network error while fetching messages: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON in get_messages: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in get_messages: {str(e)}")
        return False
