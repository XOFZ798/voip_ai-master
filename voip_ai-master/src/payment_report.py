import aiohttp
from config import PHONE_MELIPAYAMAK, Melipayamak_API
import json
import os
from src.logger_config import logger, PATH


class PaymentSms:
    def __init__(self, text):
        self.phone = ['09121370283','09369475363']
        self.text = text
        

    async def send_message(self):
        data = {
            'from': PHONE_MELIPAYAMAK,
            'to': self.phone,
            'text': self.text + ' لغو11',
            'udh': ''
        }
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
        raise NotImplementedError(("Error accurred in sending payment message to melly payamak", SendMessage_error))

    async def send_reports(self):

        await self.send_message()
