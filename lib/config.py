# -*- coding: utf-8 -*-
# redis 配置信息
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_PASSWORD = '11111'
REDIS_DB = 6

# Splunk配置信息
SPLUNK_HOST = "10.1.2.10"
SPLUNK_PORT = 8089
SPLUNK_SCHEME = "https"
SPLUNK_USERNAME = ""
SPLUNK_PASSWORD = ""

rule = {
    'query': '''
        search index=nginx ng_request_method=GET ng_status!=40*
        |eval ng_request_url_short=lower(ng_request_url_short)
        |regex ng_request_url_short != "(?i)(.+\.(htm|html|ico|mp3|js|jpg|jped|gif|xml|zip|css|png|txt|ttf|rar|gz))$"
        |regex ng_request_url_short != "(?i)((\d+){5,})"
        |rex field=ng_request_url_short mode=sed "s/\/$//g"
        |stats last(ng_request_domain) last(ng_query) by ng_request_url_short, ng_status, ng_request_method''',
    'earliest_time': '-1m',
    'max_time': 60
}
