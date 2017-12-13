# -*- coding: utf-8 -*-\
from config import *
import splunklib.client as client
import sys, redis, hashlib, time
import splunklib.results as results

NAME, VERSION, AUTHOR, LICENSE = "PublicLogSorting", "V0.1", "咚咚呛", "Public (FREE)"


class Splunk_Sort():
    def __init__(self):
        self.redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
        return

    # 判断链接状态，并重连操作
    def tryConnetRedis(self, count=3):
        for i in range(count):
            if not self.redis_r.ping():
                self.redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
            else:
                return self.redis_r
        if not self.redis_r.ping():
            return False

    def md5(self, str):
        m = hashlib.md5()
        m.update(str)
        return m.hexdigest()

    def splunk(self):
        service = client.connect(host=SPLUNK_HOST, port=SPLUNK_PORT, scheme=SPLUNK_SCHEME, username=SPLUNK_USERNAME,
                                 password=SPLUNK_PASSWORD)
        # 判断重连操作
        self.redis_r = self.tryConnetRedis()

        if 'conf_splunklog_rule' in self.redis_r.hkeys("passive_config"):
            info = eval(self.redis_r.hget('passive_config', 'conf_splunklog_rule'))
        else:
            self.redis_r.hset('passive_config', 'conf_splunklog_rule', rule)
            info = rule

        query = info['query']
        earliest_time = info['earliest_time']
        max_time = info['max_time']
        kwargs_normalsearch = {"exec_mode": "normal",
                               "earliest_time": earliest_time,
                               "latest_time": "now",
                               "max_time": int(max_time),
                               "timeout": 120}

        job = service.jobs.create(query=query, **kwargs_normalsearch)

        while True:
            while not job.is_ready():
                pass
            stats = {"isDone": job["isDone"],
                     "doneProgress": float(job["doneProgress"]) * 100,
                     "scanCount": int(job["scanCount"]),
                     "eventCount": int(job["eventCount"]),
                     "resultCount": int(job["resultCount"])}

            status = ("\r%(doneProgress)03.1f%%   %(scanCount)d scanned   "
                      "%(eventCount)d matched   %(resultCount)d results") % stats

            sys.stdout.write(status)
            sys.stdout.flush()
            if stats["isDone"] == "1":
                break
            time.sleep(2)

        print "\ntotal time: %s" % job["runDuration"]

        r = self.tryConnetRedis()

        for result in results.ResultsReader(job.results()):
            # GET请求中ng_request_url_short然而并不会存在？，但是为了保持算法一致，还是进行分割一下
            MD5 = self.md5('GET' + result['ng_request_url_short'].split('?')[0])
            request_json = {
                'method': 'GET' if result['ng_request_url_short'].strip().upper() =='GET' else 'POST',
                'protocol': 'http://',
                'domain': result['last(ng_request_domain)'],
                'ng_request_url_short': result['ng_request_url_short'],
                'arg': result['ng_query']
            }
            self.redis_r.set('DataSort_' + MD5, request_json)
        r.execute_command("QUIT")
        job.cancel()

    def run(self):
        self.splunk()
