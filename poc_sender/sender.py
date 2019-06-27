# -*- encoding: utf-8 -*-
import sys
import os
import ssl
import threading
import argparse

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
    Print = ''
PY = sys.version[0]

def dict_p(d):
    s = ""
    for k,v in d.items():
        s += str(k) + " : " + str(v).strip() + "\n"
    return s

def to_str(i):
    if isinstance(i, bytes):
        return i.decode()
    return str(i)

def L(*ress):
    res = " ".join([to_str(i) if not isinstance(i,dict) else dict_p(i) for i in ress])
    sys.stdout.write("\x1b[32m[+]\x1b[0m \x1b[33m{}\x1b[0m\n".format(res))
    sys.stdout.flush()

def OK(*ress):
    res = " ".join([str(i) if not isinstance(i,dict) else dict_p(i) for i in ress])
    sys.stdout.write("\x1b[42;1m[●]\x1b[0m \x1b[32;1m{}\x1b[0m\n".format(res))
    sys.stdout.flush()

def EL(*ress):
    res = " ".join([str(i) for i in ress])
    sys.stderr.write("\x1b[31m[x]\x1b[0m \x1b[35m{}\x1b[0m\n".format(res))
    sys.stderr.flush()

if PY == '3':
    import urllib.request as ur
    from urllib import request, parse
    from urllib.parse import urlsplit
    import http

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
        except http.client.BadStatusLine:
            return
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
            raise e

def parse_url(u):
    if not u.startswith("http"):
        u = "http://" + u
    a = urlsplit(u)
    return u, a.netloc, a.path, a.scheme

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

def get(url, headers,p):
    try:
        res = ur.urlopen(url,headers, context=context)
        if 'H' in p:
            L(res.headers)
        if res.code == 200:
            c = res.read()
            return c
    except Exception as e:
        EL(e)
        raise e


def send_from_sample(url,data,to_dict=False, p='h', verify='',extend_headers={},not_send=False):
    if '\r\n' not in data:
        data = data.replace('\n','\r\n')
    if url != 'x':
        url, host, path,scheme = parse_url(url)
    else:
        url, host, path = ['x','','']

    header,data = data.split("\r\n\r\n",1)
    url_header,headers = header.split("\r\n", 1)
    H = {}
    for l in headers.split("\r\n"):
        k,v  = l.split(":")
        H[k.strip().lower()] = v.strip()
    if host:
        H['host'] = host
    H.update(extend_headers)
    #del H['Content-Length'.lower()]
    if to_dict:
        data = parse_data(data)
    else:
        H['content-length'] = len(data)

    aaa = url_header.split()
    method = aaa.pop(0)
    http_version = aaa[-1] if aaa.pop(-1).lower().startswith("http/") else "http/1.1"
    path = ' '.join(aaa) 
    L(path)
    if not host:
        host = H['host']
        path = xx_
        url = 'http://' + host + path
    else:
        url = scheme + "://" + host + path
    method =  method.lower()
    if 'h' in p:
        L(H)
    if 'd' in p:
        if method == 'post':
            L(data)
    if not_send:
        return (method,url, H, data)
    if method == 'get':
        res = get(url, HH,p)
        if not res:
            return
    else:
        res = post(url, data, H,p)
    if not res:
        return
    if 'D' in p:
        L(res)
    if isinstance(res, bytes):
        verify = verify.encode()

    if not verify.strip():
        OK(url)
    else:
        if verify.startswith(b"!"):
            if verify[1:] not in res:
                OK(url)
        else:
            if verify in res:
                OK(url)
    return res

def send_from_samples(url,datas_files,to_dict=False, p='h', verify='',extend_headers={},not_send=False):
    res = None
    for data_file in datas_files:
        if os.path.exists(data_file):
            with open(data_file) as fp:
                data = fp.read()
            res = send_from_sample(url, data, to_dict=to_dict, p=p, verify=verify, extend_headers=extend_headers,not_send=not_send)
    return res

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="host file or host str")
    parser.add_argument("samples",nargs="+", help="samples flow...")
    parser.add_argument("-V","--verify",default="!error", help="set verify content, ! = not ")
    parser.add_argument("-s5","--socks5-proxy",default="", help="set proxy port: like -p 1080")
    parser.add_argument("-p","--Print",default="D", help="set print content h:request head | d:request body | H : response head | D : response body")
    return parser.parse_args()

def run():
    #if len(sys.argv) < 3:
    #    EL("mus\npython %s [url] [sample_templte: raw post_data/get_data] header=value"% sys.argv[0])
    #    sys.exit(3)
    args = main()
    host = args.host
    sample_v = args.samples
    verify = args.verify
    if args.socks5_proxy:
        set_proxy(int(args.socks5_proxy))
    Print = args.Print
    if not os.path.exists(sample_v[0]):
        EL("must exisgts sample file for raw POST or raw GET")
        sys.exit(2)
    if not host.startswith("http") and not os.path.exists(host) and host != 'x':
        EL("invalid url: %s "% host)
        sys.exit(2)

    if 'h' in Print:
        EL("verify: ",verify)
    HH = {}
    if len(sample_v) < 2:
        sample_v = sample_v[0]
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
    else:
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
                    send_from_samples(host, sample_v,to_dict=False, p=Print,verify=verify,extend_headers=HH)
        else:
            send_from_samples(host, sample_v, p=Print,verify=verify,extend_headers=HH)


if __name__ == '__main__':
    run()
