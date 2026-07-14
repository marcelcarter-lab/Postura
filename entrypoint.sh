#!/bin/sh
set -e

echo "Running database migrations..."
flask db upgrade

if [ "$#" -gt 0 ]; then
    echo "Running provided command: $@"
    exec "$@"
else
    echo "Starting Flask application..."
    exec flask run --host=0.0.0.0 --port=5000
fi
