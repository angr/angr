BROKER_URL = "amqp://angr:aeb3cogiel5Engi@192.168.48.9:5671/angr"
BROKER_USE_SSL = True
CELERY_RESULT_BACKEND = "mongodb"
CELERY_MONGODB_BACKEND_SETTINGS = {
    "host": "192.168.48.125",
    "user": "celery_results",
}  # trashcan

CELERY_TASK_SERIALIZER = 'pickle'
CELERY_RESULT_SERIALIZER = 'pickle'
