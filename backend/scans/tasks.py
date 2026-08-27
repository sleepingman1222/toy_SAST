from celery import shared_task

@shared_task
def add_num(x,y):
    return x+y