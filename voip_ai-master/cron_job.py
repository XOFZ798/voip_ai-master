import os
import time


PATH = os.path.dirname(os.path.abspath(__file__))

def cleanup_old_audio_files(folder_path, hours=24):
    now = time.time()
    cutoff_time = now - (hours * 3600)

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        
        # Skip files that start with "important_"
        if filename.startswith("important_"):
            continue

        if os.path.isfile(file_path) and os.path.getmtime(file_path) < cutoff_time:
            os.remove(file_path)
            print(f"Deleted old file: {file_path}")

# Run cleanup
cleanup_old_audio_files(os.path.join(PATH, "audio"), hours=24)

