import wfuzz
import logging
import coloredlogs
import argparse
import json
from unipath import Path, FILES_NO_LINKS
import random
import requests
import queue
import threading
import time

logger = logging.getLogger(__name__)
coloredlogs.install(logger=logger)

DOMAINS = ['.googleapis.com', '.clients6.google.com', '-googleapis.sandbox.google.com', '.sandbox.googleapis.com']

parser = argparse.ArgumentParser()
parser.add_argument('-k', '--keys', type=argparse.FileType('r'), required=True)
parser.add_argument("-d", "--domain", type=int, required=True, default=0)
parser.add_argument("-v", "--verbose", dest="verbose_count", action="count", default=0)
parser.add_argument('-f', '--file', type=argparse.FileType('r'), required=True)
parser.add_argument("-o", "--output")
args = parser.parse_args()

logger.setLevel(max(3 - args.verbose_count, 0) * 10)

KEYS = []
NUM_THREADS = 16
message_queue = queue.Queue(maxsize=0)

def build_keys():
    for line in args.keys:
        line = line.strip()

        if line == "":
            continue

        key, referer = line.split(":", 1)
        KEYS.append({"key" : key, "referer": referer})

def already_have():
	already = set()

	for f in Path(args.output).walk(filter=FILES_NO_LINKS):
		if not ".git" in str(f):
			already.add(str(f.name))

	return already

def in_file():
    pa = set()
    for line in args.file:
        line = line.strip()
        if line == "":
            continue

        pa.add(line)

    return pa        

def set_to_str(s):
	z = ""
	for i in s:
		z += "-" + i.replace('-', '\\-')
	
	return z

def save_discovery(filename, content):
	f = args.output + "/" + filename
	data = json.loads(content)

	with open(f, 'w') as outfile:
		json.dump(data, outfile, indent=4, sort_keys=True, separators=(',', ': '), ensure_ascii=True)

def process_queue(q):
    while True:
        message = q.get()
        process_message(message)
        q.task_done()

def process_message(message):
    #try:
    filter_false_positive(message['api'], message['key'], message['referer'], message['content'])
    #except Exception as e: 
    #    logger.debug(e)

def run_yolo(headers, payloads):
    URL = 'https://www.googleapis.com/$discovery/rest'
                   
    logger.info(headers)
    logger.debug(payloads)
    
    with wfuzz.FuzzSession(scanmode=True, url=URL, sc=[200], headers=headers, payloads=payloads) as sess:
        logger.info("YOLO!")
        for res in sess.fuzz():
            p = "-".join([x.content for x in res.payload])
            #print(p)
            message_queue.put({"key": headers[1][1], "referer": headers[2][1], "api": p, "content": res.history.content})
            #save_discovery(p, res.history.content)

def filter_false_positive(api, key, referer, content):
    #logger.info("Filtering false positive... ({0})".format(api))
    #sleep for 60sec to remove any caching
    time.sleep(35)
    url = "https://{0}{1}/$discovery/rest".format(api, DOMAINS[args.domain])
    r = requests.get(url, headers={'referer': referer, 'X-Goog-Api-Key': key})
    if r.status_code != 200:
        logger.info("curl -H 'referer: {0}' -H 'X-Goog-Api-Key: {1}' {2}".format(referer, key, url))
        save_discovery(api, content)

def main():
    for x in range(NUM_THREADS):
        logger.info("Starting thread {0}".format(x))
        t = threading.Thread(target=process_queue, args=(message_queue,))
        t.setDaemon(True)
        t.start()

    logger.info("Welcome to yolo4.")
    build_keys()
    logger.info("Number of keys: {0}".format(len(KEYS)))

    pa = in_file()

    while True:
        looking = pa - already_have()
        c = random.choice(KEYS)

        headers = [ ("Host", "FUZZ" + DOMAINS[args.domain]),
                ("X-Goog-Api-Key", c['key']),
				("Referer",  c['referer'])]
        payloads = [("list",dict(values=set_to_str(looking)))]

        yolo4 = run_yolo(headers, payloads)


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		pass