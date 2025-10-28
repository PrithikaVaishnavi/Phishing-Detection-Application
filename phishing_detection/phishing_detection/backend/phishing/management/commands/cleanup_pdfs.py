from django.core.management.base import BaseCommand
import os
import time
from django.conf import settings

class Command(BaseCommand):
    help = 'Cleans up old temporary PDFs'

    def handle(self, *args, **options):
        temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_pdfs')
        if not os.path.exists(temp_dir):
            self.stdout.write(self.style.SUCCESS('No temp_pdfs directory found.'))
            return

        # Delete files older than 5 minutes (300 seconds)
        current_time = time.time()
        cutoff_time = current_time - 300  # 5 minutes ago

        for filename in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, filename)
            # Use os.path.isfile to check if it's a file
            if os.path.isfile(file_path):
                file_mtime = os.path.getmtime(file_path)
                if file_mtime < cutoff_time:
                    try:
                        os.remove(file_path)
                        self.stdout.write(self.style.SUCCESS(f'Deleted: {file_path}'))
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f'Error deleting {file_path}: {e}'))