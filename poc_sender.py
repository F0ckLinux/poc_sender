# -*- encoding: utf-8 -*-
import sys
import os
import ssl
import threading

# This restores the same behavior as before.
context = ssl._create_unverified_context()
import socket

def set_proxy(port):
    import socks
    global socket
    socks.set_default_proxy(socks.SOCKS5, "localhost", port)
    socket.socket = socks.socksocket
if os.getenv("S5"):
    set_proxy(int(os.getenv("S5")))
if os.getenv("Pthread"):
    use_thread = True
else:
    use_thread = True
Print=os.getenv("p")
if not Print:
    Print = 'hH'
PY = sys.version[0]

def dict_p(d):
    s = ""
    for k,v in d.items():
        s += str(k) + " : " + str(v).strip() + "\n"
    return s


def L(*ress):
    res = " ".join([str(i) if not isinstance(i,dict) else dict_p(i) for i in ress])
    sys.stdout.write("\x1b[32m[+]\x1b[0m \x1b[33m{}\x1b[0m\n".format(res))
    sys.stdout.flush()

def OK(*ress):
    res = " ".join([str(i) if not isinstance(i,dict) else dict_p(i) for i in ress])
    sys.stdout.write("\x1b[42;1m[●]\x1b[0m \x1b[32;1m{}\x1b[0m\n".format(res))
    sys.stdout.flush()

def EL(*ress):
    res = " ".join([str(i) for i in ress])
    sys.stdout.write("\x1b[31m[x]\x1b[0m \x1b[35m{}\x1b[0m\n".format(res))
    sys.stdout.flush()

if PY == '3':
    import urllib.request as ur
    from urllib import request, parse
    from urllib.parse import urlsplit

    def post(url, data, headers,p):
        if isinstance(data, dict):
            data = parse.urlencode(data).encode()
        if isinstance(data, str):
            data = data.encode()
        req =  request.Request(url, data=data, headers=headers)
        try:
            resp = ur.urlopen(req,context=context)
            if 'H' in p:
                L(resp.headers)
            if resp.code // 100 != 4:
                d = resp.read()
                if 'D' in p:
                    L("[%d]" % resp.code, url)
                return d
            else:
                if 'D' in p:
                    L(resp.read())
        except Exception as e:
            EL(e)


else:
    import urllib2 as ur
    import urllib
    from urlparse import urlparse as urlsplit
    def post(url, data, headers,p):
        if isinstance(data, dict):
            data = urllib.urlencode(data)
        req =  ur.Request(url, data)
        [req.add_header(k,v) for k,v in headers.items()]
        try:
            resp = ur.urlopen(req, context=context)
            if 'H' in p:
                L(resp.headers)
            if resp.code // 100 != 4:
                d = resp.read()
                if 'D' in p:
                    L("[%d]" % resp.code, url)
                return d
            else:
                if 'D' in p:
                    L(resp.read())
        except Exception as e:
            EL(e)

def parse_url(u):
    if not u.startswith("http"):
        u = "http://" + u
    a = urlsplit(u)
    return u, a.netloc, a.path

def parse_data(data):
    d = {}
    for l in data.split('\r\n'):
        if not l.strip():continue
        if '=' not in l:
            d[l.strip()] = ''
            continue
        k,v = l.strip().split("=",1)
        d[k] = v 
    return d

def get(url):
    res = ur.urlopen(url)


def send_from_sample(url,data,to_dict=False, p='h', verify='',extend_headers={},not_send=False):
    if '\r\n' not in data:
        data = data.replace('\n','\r\n')
    url, host, path = parse_url(url)
    header,data = data.split("\r\n\r\n",1)
    url_header,headers = header.split("\r\n", 1)
    H = {}
    for l in headers.split("\r\n"):
        k,v  = l.split(":")
        H[k.strip().lower()] = v.strip()
    if host:
        H['host'] = host
    H.update(extend_headers)
    del H['Content-Length'.lower()]
    if to_dict:
        data = parse_data(data)

    method,_,_  = url_header.split()
    method =  method.lower()
    if 'h' in p:
        L(H)
    if 'd' in p:
        L(data)
    if not_send:
        return (method,url, H, data)
    if method == 'get':
        return get(url)
    else:
        res = post(url, data, H,p)
        if 'D' in p:
            L(res)
        if isinstance(res, bytes):
            verify = verify.encode()

        if verify in res:
            OK(url)
        return res

if __name__ == '__main__':
    if len(sys.argv) < 3:
        EL("mus\npython %s [url] [sample_templte: raw post_data/get_data] header=value"% sys.argv[0])
        sys.exit(3)
    host = sys.argv[1]
    sample_v = sys.argv[2]
    if not os.path.exists(sample_v):
        EL("must exisgts sample file for raw POST or raw GET")
        sys.exit(2)
    if not host.startswith("http") and not os.path.exists(host):
        EL("invalid url: %s "% host)
        sys.exit(2)

    HH = {}
    if len(sys.argv) ==3:
        verify = 'currentUserId'
    elif len(sys.argv) == 4:
        verify = sys.argv[3]
    elif len(sys.argv) > 4:
        verify = sys.argv[3]
        headers_str = ''.join(sys.argv[4:])
        for header in headers_str.split(","):
            if '=' not in headers_str:
                h = header.strip()
                v = ''
                continue
            h,v = header.split("=",1)
            HH[h.strip()] = v.strip()
    with open(sample_v) as fp:
        content = fp.read()
        if os.path.exists(host):
            with open(host) as fpp:
                targets = [i.strip() for i in fpp.read().split("\n") if i.strip()]
            if use_thread:
                cs = []
                for host in targets:
                    t = threading.Thread(target=send_from_sample, args=(host, content,False,Print,verify,HH))
                    t.start()
                    cs.append(t)
                    if len(cs) > 12:
                        for i in cs:
                            i.join()
                        cs = []
                if len(cs) > 0:
                    for i in cs:
                        i.join()
            else:
                for host in targets:
                    if not host.startswith("http"):
                        EL("must include https://xx.x.xx [%s] "% host)
                        continue
                    send_from_sample(host, content,to_dict=False, p=Print,verify=verify,extend_headers=HH)

        else:
            send_from_sample(host, content, p=Print,verify=verify,extend_headers=HH)


