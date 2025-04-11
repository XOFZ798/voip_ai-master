#!/root/voip_ai/venv/bin/python


import os
import random
import asyncio
from src.functions import transcribe_and_converse, app_start
from src.logger_config import logger, PATH
from src.sms_report import Report
import uuid
from src.utils import handle_timeout_or_failure
from config import Aipaa_API, Avalai_API
from src.aipaa import Aipaa
from src.openai_module import AvalAiApi
# from asterisk.agi import AGI
from src.fake_agi import FakeAGI
AGI = FakeAGI

async def random_hello(user_name):
    # پیشوند ثابت
    prefix = "سلام "

    # لیست کلمات بدون اسم (تکی)
    prefix_words = ["عزیزدل", "دلبندم", "گلم", "قشنگم", "سرورم", "عزیزم", "نازنینم", "رییس"]

    # لیست پسوندها بدون اسم
    suffixes = ["بزرگوار", "ارجمند", "عزیز", "نازنین", "دوست داشتنی"]

    # انتخاب رندوم از لیست‌ها
    use_name = random.choice([True, False])  # تعیین اینکه اسم و پسوند نمایش داده بشه یا فقط کلمه بدون اسم
    if use_name:
        suffix = random.choice(suffixes)  # انتخاب پسوند رندوم و اضافه کردن اسم کاربر به آن
        greeting = f"{prefix} {user_name} {suffix}"
    else:
        greeting = f"{prefix} {random.choice(prefix_words)}"

    return greeting

async def main():
    agi = AGI()
    agi.answer()
    agi.verbose("App Started")
    phone = agi.get_variable("CALLERID(num)")
    phone = "0" + phone[2:]

    onhold = os.path.join(PATH, "audio", "important_hold")
    wellcome = os.path.join(PATH, "audio", "important_wellcome")
    coldroom_timeout = os.path.join(PATH, "audio", "important_coldroom-timeout")
    wait = os.path.join(PATH, "audio", "important_wait")
    ask_again = os.path.join(PATH, "audio", "important_ask-again")
    multi_wellcome = os.path.join(PATH, "audio", "important_multi_wellcome")
    city_found = os.path.join(PATH, "audio", "important_city_found")
    city_lost = os.path.join(PATH, "audio", "important_city_lost")
    goodby = os.path.join(PATH, "audio", "important_goodby")

    try:
        aipaa_bot = Aipaa(Aipaa_API[0], Aipaa_API[1])
        aval = AvalAiApi(Avalai_API)
        report = Report(phone)
        user_info = await asyncio.wait_for(report.init_async(), timeout=5)
        user_list = list(user_info)
        logger.info("Attempting to authenticate with Aipaa bot...")
        hi_text = await random_hello(user_list[0].name)

        start_app = asyncio.create_task(app_start(aipaa_bot, hi_text))
        while not start_app.done():
            logger.info("Start Onhold")
            await asyncio.to_thread(agi.stream_file, onhold)  # Play on-hold audio
            await asyncio.sleep(1)

        audio_file = await start_app
        await asyncio.to_thread(agi.stream_file, audio_file)

    except asyncio.TimeoutError:
        await handle_timeout_or_failure(agi, coldroom_timeout, f"Timeoute Error in main 1")
    except NotImplementedError as e:
        message, value = e.args[0]
        await handle_timeout_or_failure(agi, value, message)
    except Exception as e:
        await handle_timeout_or_failure(agi, coldroom_timeout, f"Error occurred in main 1: {e}")

    try:
        if len(user_list) > 1:
            await asyncio.to_thread(agi.stream_file, multi_wellcome)
            while True:
                recording_file = os.path.join(PATH, "audio", f"recording_{uuid.uuid4()}")
                agi.record_file(recording_file, 'wav', '#')
                await asyncio.to_thread(agi.stream_file, wait)

                transcription = "مشهد"
                #transcription = await asyncio.wait_for(aipaa_bot.speech_to_text(recording_file), timeout=10)
                logger.info(f'Transcription result: {transcription}')
                logger.info("Attempting to analyze audio...")
                city = report.check_city(transcription)
                if city:
                    logger.info("My ai answer : " + city)
                    report_res = asyncio.create_task(report.get_reports())
                    await asyncio.to_thread(agi.stream_file, city_found)
                    break
                else:
                    await asyncio.to_thread(agi.stream_file, city_lost)
        else:
            report_res = asyncio.create_task(report.get_reports())
            await asyncio.to_thread(agi.stream_file, wellcome)

    except asyncio.TimeoutError:
        await handle_timeout_or_failure(agi, coldroom_timeout, f"Timeoute Error in main 2")
    except NotImplementedError as e:
        message, value = e.args[0]
        await handle_timeout_or_failure(agi, value, message)
    except Exception as e:
        await handle_timeout_or_failure(agi, coldroom_timeout, f"Error occurred in main 2: {e}")

    while True:
        recording_file = os.path.join(PATH, "audio", f"recording_{uuid.uuid4()}")
        agi.record_file(recording_file, 'wav', '#')
        transcribe_chat = asyncio.create_task(transcribe_and_converse(recording_file, report_res, aipaa_bot, aval))
        await asyncio.to_thread(agi.stream_file, wait)
        try:
            while not transcribe_chat.done():
                logger.info("Start Onhold")
                await asyncio.to_thread(agi.stream_file, onhold)  # Play on-hold audio
                await asyncio.sleep(1)  # Prevent blocking other tasks

            status, final_answer_file = await transcribe_chat
            if status:
                await asyncio.to_thread(agi.stream_file, final_answer_file)
            else:
                await asyncio.to_thread(agi.stream_file, goodby)
                break

        except NotImplementedError as e:
            message, value = e.args[0]
            await handle_timeout_or_failure(agi, value, message)
        except Exception as e:
            await handle_timeout_or_failure(agi, coldroom_timeout, f"Error occurred in main 3: {e}")

    agi.hangup()


if __name__ == "__main__":
    asyncio.run(main())
