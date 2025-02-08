#!/bin/sh

# Wait for PostgreSQL using pg_isready
until pg_isready -h db -p 5432 -U ${DB_USER} -d ${DB_NAME}
do
  echo "Waiting for PostgreSQL..."
  sleep 2
done

# Wait for Redis using redis-cli
until redis-cli -h redis -p 6379 -a ${REDIS_PASSWORD} ping | grep -q PONG
do
  echo "Waiting for Redis..."
  sleep 2
done

# Run database migrations
flask db upgrade

# Start application
exec gunicorn -k eventlet -w 4 --bind 0.0.0.0:5000 --access-logfile - --error-logfile - app:app