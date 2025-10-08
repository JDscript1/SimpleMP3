#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wrapper script to start the application with proper SSL configuration
This MUST set environment variables BEFORE importing any modules that use SSL
"""

import os
import sys

# Set SSL environment variables BEFORE any imports
os.environ['PYTHONHTTPSVERIFY'] = '0'
os.environ['CURL_CA_BUNDLE'] = ''
os.environ['REQUESTS_CA_BUNDLE'] = ''
os.environ['SSL_CERT_FILE'] = ''

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create unverified SSL context
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

# Now import and run the app
import app_professional

if __name__ == '__main__':
    app_professional.app.run(host='127.0.0.1', port=5000, debug=True)

