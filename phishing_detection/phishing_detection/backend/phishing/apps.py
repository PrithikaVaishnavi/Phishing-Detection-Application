from django.apps import AppConfig

class PhishingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "phishing"

    def ready(self):
        # Start the scheduler when the app is ready
        from .scheduler import start
        start()