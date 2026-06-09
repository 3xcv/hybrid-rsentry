#!/bin/bash
pkill -f "celery_app" 2>/dev/null
sleep 1
set -a && source /home/mohammad/hybrid-rsentry/.env && set +a
PYTHONPATH=/home/mohammad/hybrid-rsentry \
  /home/mohammad/hybrid-rsentry/venv/bin/celery \
  -A backend.workers.tasks:celery_app worker \
  --loglevel=info \
  >> /tmp/rsentry-celery.log 2>&1 &
echo "Worker PID: $!"
