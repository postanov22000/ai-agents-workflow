# worker.py
import os
from redis import Redis
from rq import Worker, Queue, Connection

# import the module that defines your background task
import transaction_autopilot_task

listen = ["autopilot"]

if __name__ == "__main__":
    # grab the same URL you’re using in Flask
    redis_url = os.environ["REDIS_URL"]
    redis_conn = Redis.from_url(redis_url)

    with Connection(redis_conn):
        worker = Worker(list(map(Queue, listen)))
        worker.work()
