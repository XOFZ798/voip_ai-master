from src.logger_config import logger, PATH
from src.payment_report import PaymentSms
import httpx
import os
from pydub import AudioSegment
import aiofiles

aipaa_error = os.path.join(PATH, "audio", "important_aipaa_error")
stt_error = os.path.join(PATH, "audio", "important_stt_error")
tts_error = os.path.join(PATH, "audio", "important_tts_error")


class Aipaa:
    TTS_URL = "https://api.aipaa.ir/api/v1/voice/tts/?expire-file=yes"
    DOWNLOAD_URL = "https://api.aipaa.ir/api/v1/file_manager/file/download/{id}/"
    TOKEN_URL = "https://api.aipaa.ir/auth/token/"

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.token = None
        self.headers = {}

    async def authenticate(self):

        payload = {
            'username': self.username,
            'password': self.password,
            'client_id': 'cK5uzw5ydbUr79iybFYhxlWOKnFXqYlsp07JULr8',
            'grant_type': 'password'
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(self.TOKEN_URL, data=payload, timeout=8)
                response.raise_for_status()
                token = response.json().get("access_token")

                if not token:
                    raise ValueError("No access token received.")

                logger.info("Aipaa Authentication successful.")
                self.token = token
                self.headers = {'Authorization': f'Bearer {self.token}'}
                return token

        except httpx.HTTPStatusError as e:
            raise NotImplementedError((f"Aipaa HTTP error during authentication: {e.response.text}", aipaa_error))
        except httpx.RequestError as e:
            raise NotImplementedError((f"Aipaa Request error during authentication: {e}", aipaa_error))
        except Exception as e:
            raise NotImplementedError((f"Aipaa Unexpected authentication error: {e}", aipaa_error))

    async def speech_to_text(self, file_path):
        file_path = f'{file_path}.wav'
        url = "https://api.aipaa.ir/api/v1/voice/asr/?asr_mode=shiva&lang_boost=accurate"

        try:
            async with httpx.AsyncClient() as client:
                async with aiofiles.open(file_path, "rb") as f:
                    file_data = await f.read()

                files = {'file': (file_path, file_data, "audio/wav")}
                response = await client.post(url, headers=self.headers, files=files)

                if response.status_code == 200:
                    response_data = response.json()
                    transcription = response_data.get('transcripts', ["Aipaa connection refused"])[0]
                    return transcription
                elif response.status_code == 402:
                    send_sms = PaymentSms("اعتبار وب سرویس آیپا به پایان رسیده است")
                    await send_sms.send_reports()
                    raise Exception(response.text)
                else:
                    raise Exception(response.text)
        except httpx.HTTPError as e:
            logger.error(f"HTTP request failed during speech-to-text: {e}")
        except FileNotFoundError:
            logger.error(f"File {file_path} not found.")
        except Exception as e:
            logger.error(f"Unexpected error in speech-to-text: {e}")
        raise NotImplementedError(("speech-to-text Error accurred", stt_error))

    async def text_to_speech(self, text, save_path):
        payload = {'input_text': text, "sample_rate": 22050, "compress": True}
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(self.TTS_URL, headers=self.headers, data=payload)

            mp3_file = f'{save_path}.mp3'
            wav_file = f'{save_path}.wav'

            if response.status_code == 200:
                data = response.json()
                download_result = await self.download_audio(data.get("file_id"), mp3_file)
                if download_result:
                    self.convert_mp3_to_wav(mp3_file, wav_file)
                    return download_result
            elif response.status_code == 402:
                send_sms = PaymentSms("اعتبار وب سرویس آیپا به پایان رسیده است")
                await send_sms.send_reports()
                raise Exception(response.text)
            else:
                raise Exception(response.text)
        except httpx.RequestError as e:
            logger.error(f"Request error in text-to-speech: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in text-to-speech: {e}")
        raise NotImplementedError(("text-to-speech Error accurred", tts_error))

    async def download_audio(self, file_id, save_path):
        try:
            url = self.DOWNLOAD_URL.format(id=file_id)
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=self.headers)
                response.raise_for_status()

            if response.status_code == 200:
                with open(save_path, 'wb') as f:
                    f.write(response.content)
                return save_path
            else:
                raise Exception(response.status_code)
                return None
        except Exception as e:
            raise Exception(f"Error downloading audio: {e}")
            return None

    @staticmethod
    def convert_mp3_to_wav(mp3_file, wav_file):
        try:
            audio = AudioSegment.from_mp3(mp3_file)
            audio = audio.set_frame_rate(8000).set_channels(1).set_sample_width(2)
            audio.export(wav_file, format="wav")
            os.remove(mp3_file)
            logger.info(f"Successfully converted {mp3_file} to {wav_file}")
            return wav_file
        except Exception as e:
            raise Exception(f"Error converting {mp3_file} to WAV: {e}")
            return None


