from src.logger_config import logger, PATH
import shutil
import os
import time

class FakeAGI:
    def __init__(self, ):
        self.path = PATH

    def answer(self):
        pass  # Does nothing

    def verbose(self, message):
        pass  # Does nothing

    def stream_file(self, file):
        pass  # Does nothing

    def record_file(self, file, format, timeout):
        original_name = os.path.basename(file).split('_')[0]
        time.sleep(5)

        # Path to the existing recording file
        source_file = os.path.join(self.path, "audio", f"{original_name}.{format}")

        try:
            # Copy the recording file to the new path
            shutil.copy(source_file, f"{file}.{format}")
            print(f"File recorded successfully: {file}")
            return file
        except Exception as e:
            print(f"Error copying recording file: {e}")
            return None

    def hangup(self):
        pass  # Does nothing

    def get_variable(self, var_name):
        if var_name == "CALLERID(num)":
            return "989369344330"
        return None