import logging
from apscheduler.schedulers.background import BackgroundScheduler
from django.core.management import call_command

# Configure logging
logging.basicConfig(
    filename=r'C:\Users\PRITHIKA\Downloads\Phishing_detection_application\phishing_detection\phishing_detection\scheduler.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def start():
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        lambda: call_command('cleanup_pdfs'),
        'interval',
        minutes=5,
        id='cleanup_pdfs_job',
        replace_existing=True
    )
    scheduler.start()
    logging.info("Scheduler started: cleanup_pdfs will run every 5 minutes.")