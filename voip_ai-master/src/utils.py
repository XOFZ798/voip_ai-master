import asyncio
from src.logger_config import logger


async def handle_timeout_or_failure(agi, audio_file, message):
    """Handles timeout or failed transcription cases"""
    logger.error(message)
    await asyncio.to_thread(agi.stream_file, audio_file)
    agi.hangup()
    tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.sleep(1)

    raise SystemExit("Stopping program safely.")