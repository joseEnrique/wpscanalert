# -*- coding: utf-8 -*-
# From https://github.com/joseEnrique/Mongo-Abstract
import os

config = {
    # MONGO CONFIG
    "MONGO_USERNAME": None,
    "MONGO_PASSWORD": None,
    "MONGO_HOST": os.getenv('MONGO_HOST',r'192.168.250.7'),
    "MONGO_PORT": int(os.getenv('MONGO_PORT',27017)),
    "MONGO_DB_NAME": "wpscan",
}

def get_db():
    from pymongo import MongoClient
    client = MongoClient(host=config['MONGO_HOST'], port=config['MONGO_PORT'])
    db = client[config['MONGO_DB_NAME']]
    return db

def add_vulnerability(db,wp_site,title):
    db.vulnerabilities.insert({
        "wp_site":wp_site,
        "title": title
    })
    
def get_vulnerability(db,wp_site,title):
    return db.vulnerabilities.find_one({
        "wp_site":wp_site,
        "title": title
    })