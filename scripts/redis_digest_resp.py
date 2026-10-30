"""Bounded, binary-safe Redis keyspace fingerprint; never stores values.

An HMAC result only compares data actually returned by Redis. It is not a
fence, an RDB comparison, a completeness proof, or authorization to resume.
"""
import hashlib
import hmac
import re
import socket
import time

MAX_DATABASES=64
MAX_KEYS=100000
MAX_KEY=4096
MAX_VALUE=16*1024*1024
MAX_TOTAL=256*1024*1024
MAX_SCAN_CALLS=200000
MAX_REPLY_BYTES=MAX_VALUE+MAX_KEY+65536
MAX_REPLY_ITEMS=20000


class RedisDigestError(ValueError):pass


class Client:
    def __init__(self,sock,deadline):self.sock=sock;self.deadline=deadline;self.reader=sock.makefile('rb',buffering=0)
    def _timeout(self):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise ValueError
        self.sock.settimeout(min(remaining,10))
    def _exact(self,size,budget):
        if size<0 or size>budget[0]:raise ValueError
        budget[0]-=size
        out=bytearray()
        while len(out)<size:
            self._timeout();chunk=self.reader.read(size-len(out))
            if not chunk:raise ValueError
            out.extend(chunk)
        return bytes(out)
    def _line(self,budget):
        if budget[0]<2:raise ValueError
        self._timeout();line=self.reader.readline(min(1025,budget[0]+1))
        if len(line)>budget[0]:raise ValueError
        budget[0]-=len(line)
        if len(line)>1024 or not line.endswith(b'\r\n'):raise ValueError
        return line[:-2]
    def _reply(self,depth=0,budget=None):
        if budget is None:budget=[MAX_REPLY_BYTES,MAX_REPLY_ITEMS]
        if depth>4 or budget[1]<1:raise ValueError
        budget[1]-=1
        prefix=self._exact(1,budget);line=self._line(budget)
        if prefix==b'+':return line
        if prefix==b'-':raise ValueError
        if prefix==b':':
            if not re.fullmatch(rb'-?[0-9]{1,20}',line):raise ValueError
            return int(line)
        if prefix==b'$':
            if not re.fullmatch(rb'-?[0-9]{1,10}',line):raise ValueError
            length=int(line)
            if length==-1:return None
            if not 0<=length<=MAX_VALUE or length+2>budget[0]:raise ValueError
            data=self._exact(length,budget)
            if self._exact(2,budget)!=b'\r\n':raise ValueError
            return data
        if prefix==b'*':
            if not re.fullmatch(rb'-?[0-9]{1,10}',line):raise ValueError
            length=int(line)
            if length==-1:return None
            if not 0<=length<=10000 or length>budget[1]:raise ValueError
            return [self._reply(depth+1,budget) for _ in range(length)]
        raise ValueError
    def command(self,*args):
        encoded=[]
        for arg in args:
            if isinstance(arg,str):arg=arg.encode('ascii')
            if not isinstance(arg,bytes) or len(arg)>MAX_VALUE:raise ValueError
            encoded.append(arg)
        request=b'*'+str(len(encoded)).encode()+b'\r\n'+b''.join(
            b'$'+str(len(arg)).encode()+b'\r\n'+arg+b'\r\n' for arg in encoded)
        self._timeout();self.sock.sendall(request);return self._reply()
    def close(self):self.reader.close()


def fingerprint(sock,password,key,*,timeout=120):
    """Fingerprint native keys and absolute expiry in every configured DB."""
    client=None
    try:
        if not isinstance(password,bytes) or not password or not isinstance(key,bytes) or len(key)!=32:
            raise ValueError
        if type(timeout) is not int or not 1<=timeout<=300:raise ValueError
        client=Client(sock,time.monotonic()+timeout)
        if client.command('AUTH',password)!=b'OK' or client.command('PING')!=b'PONG':raise ValueError
        config=client.command('CONFIG','GET','databases')
        if (not isinstance(config,list) or len(config)!=2 or config[0]!=b'databases'
                or not isinstance(config[1],bytes) or not re.fullmatch(rb'[0-9]{1,3}',config[1])):raise ValueError
        databases=int(config[1])
        if not 1<=databases<=MAX_DATABASES or client.command('MODULE','LIST')!=[] or client.command('FUNCTION','LIST')!=[]:
            raise ValueError
        all_rows=[];total=0;calls=0;keys_total=0
        for db in range(databases):
            if client.command('SELECT',str(db))!=b'OK':raise ValueError
            cursor=b'0';seen={}
            while True:
                reply=client.command('SCAN',cursor,'COUNT','512');calls+=1
                if calls>MAX_SCAN_CALLS or not isinstance(reply,list) or len(reply)!=2:raise ValueError
                cursor,keys=reply
                if not isinstance(cursor,bytes) or not re.fullmatch(rb'[0-9]{1,20}',cursor) or not isinstance(keys,list):raise ValueError
                for name in keys:
                    if not isinstance(name,bytes) or len(name)>MAX_KEY:raise ValueError
                    value=client.command('DUMP',name);expiry=client.command('PEXPIRETIME',name)
                    if (not isinstance(value,bytes) or len(value)>MAX_VALUE or type(expiry) is not int or expiry < -1):raise ValueError
                    total+=len(name)+len(value)
                    if total>MAX_TOTAL:raise ValueError
                    record=(db.to_bytes(2,'big')+len(name).to_bytes(4,'big')+name+len(value).to_bytes(8,'big')+value
                            +str(expiry).encode('ascii'))
                    identity=hashlib.sha256(name).digest();digest=hmac.new(key,record,hashlib.sha256).digest()
                    if identity in seen and not hmac.compare_digest(seen[identity],digest):raise ValueError
                    if identity not in seen:
                        seen[identity]=digest;keys_total+=1
                        if keys_total>MAX_KEYS:raise ValueError
                if cursor==b'0':break
            size=client.command('DBSIZE')
            if type(size) is not int or size!=len(seen):raise ValueError
            all_rows.append((db,len(seen),sorted(seen.values())))
        mac=hmac.new(key,b'uter-redis-logical-digest-v1',hashlib.sha256)
        mac.update(databases.to_bytes(2,'big'))
        for db,count,values in all_rows:
            mac.update(db.to_bytes(2,'big'));mac.update(count.to_bytes(8,'big'))
            for value in values:mac.update(value)
        return {'schema':1,'digest':mac.hexdigest(),'databases':databases,'keys':keys_total,
                'rdb_compared':False,'safe_to_resume':False}
    except (OSError,ValueError,TypeError,OverflowError):raise RedisDigestError('REDIS_DIGEST_UNVERIFIED') from None
    finally:
        if client is not None:
            try:client.close()
            except OSError:raise RedisDigestError('REDIS_DIGEST_UNVERIFIED') from None
