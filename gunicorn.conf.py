#!/usr/bin/env python3
"""
Gunicorn configuration for Railway deployment
"""

import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', 8080)}"
backlog = 2048

# Worker processes
workers = 1  # Railway works better with 1 worker
worker_class = "sync"
worker_connections = 1000
timeout = 300  # Increased for long conversions
keepalive = 5  # Increased for better connection reuse

# Restart workers after this many requests, to help prevent memory leaks
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'simplemp3_converter'

# Server mechanics
daemon = False
pidfile = None
user = None
group = None
tmp_upload_dir = None

# SSL (not needed on Railway)
keyfile = None
certfile = None

# Preload app for better performance
preload_app = True

# Worker timeout for long-running tasks
worker_timeout = 600  # 10 minutes for very long conversions

# Graceful timeout
graceful_timeout = 30

# Forwarded allow ips (for Railway)
forwarded_allow_ips = "*"

# Secure scheme headers
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}
