#!/usr/bin/python
import sys

sys.path.insert(0, '/var/www/catalog/catalog/hotel-catalog')


from app import app as application

application.secret_key = '\xce\xc8\xed\xbf\xb2l\xf2\xc3\xfbv\xda\xa4&\x80\xb9\x11\x0f\r\xdf8\xd6\xe3\xa3\xca'
