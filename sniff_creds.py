import re, subprocess, base64
import logging
# shut up scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
import datetime

creds= set()
ips=set()
outfile = '/var/www/html/data/proxy_creds.txt'

def check_bruteforce():
    global ips, creds
    #find folks who have sent a bunch of different credentials
    for i in ips:
	count = 0
	for c in creds:
	    try:
		addr, user, passwd = c.split(":")
	    except:
		print "bruteforce detection failed to split this value into 3 parts: ", c
		continue
	    if addr == i: count +=1
	
    #ban them and print it to the log
    if count > 5: 
	subprocess.call('/usr/local/bin/ip_banner.sh %s' %i, shell=True)
	msg =  '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n'
	msg += "!\n"
	msg += "! Banned %s for %d password attempts in 5 minutes\n" %(i,count)
	msg += "!\n"
	with open(outfile,'a+') as f:
	    f.write(msg.encode('utf8'))
	print "! Banned %s for %d password attempts in 5 minutes" %(i,count)
    #reset the counters	
    ips = set()
    creds = set()

def get_creds(body, headers, url, pkt):
    if body == '':return
    user_passwd = get_login_pass(body)
    cred_type = "Forms"
    if user_passwd == None:
	user_passwd = basic_auth(headers)
	cred_type = "Basic"
    if user_passwd == None: 
	return

    #we found a credential set, let's apply filters
    try:
        http_user = user_passwd[0].decode('utf8')
        http_pass = user_passwd[1].decode('utf8')
    except UnicodeDecodeError:
	print "failed unicode decode of http creds"
        return
    if len(http_user) > 75 or len(http_pass) > 75:return

    #add credentials to global sets (used in brute force detection)
    src_ip = str(pkt[IP].src)
    creds.add(src_ip+":"+http_user+":"+http_pass)
    ips.add(src_ip)
    
    #only print out the ones with a valid url
    if len(url)!=0: cred_printer(http_user, http_pass, url, src_ip, cred_type)


def basic_auth(headers):
    '''
    Parse basic authentication over HTTP
    '''
    authorization_re = '(www-|proxy-)?authorization'
    authorization_header = None
    for header in headers:
        authorization_header = re.match(authorization_re, header)
	if authorization_header: break
    if authorization_header:
        # authorization_header sometimes is triggered by failed ftp
        try:
            header_val = headers[authorization_header.group()]
        except KeyError:
            return None
        b64_auth_re = re.match('basic (.+)', header_val, re.IGNORECASE)
        if b64_auth_re != None:
            basic_auth_b64 = b64_auth_re.group(1)
            try:
                basic_auth_creds = base64.decodestring(basic_auth_b64)
            except Exception:
		print "failed basic auth decode of ", header_val
		return None
	    try:
		user, pwd = basic_auth_creds.split(":")
	    except ValueError:
		print "failed to split basic auth string ", basic_auth_creds
		return None
	    return (user, pwd)
    return None

def cred_printer(user, pwd, url, src_ip, cred_type):
    ts= datetime.datetime.utcnow()
    msg = u'********************************************\n'
    msg += '* HTTP %s Credentials\n' % cred_type
    msg += '* IP: %s\tUTC Time:%s\n' % (src_ip, ts)
    msg += '* User: %s\t Pass: %s\n' % (user, pwd)
    msg += '* Method & URL: %s\n' % url

    with open(outfile,'a+') as f:
	f.write(msg.encode('utf8'))

    #make sure the output file doens't get too big
    data = []
    with open(outfile,'r') as f:
	for line in f: data.append(line)
    num_lines = len(data)
    if num_lines > 500:
    	f = open(outfile,'w')
    	for i in range(num_lines-500, num_lines):
	    f.write(data[i])

def get_login_pass(body):
    '''
    Regex out logins and passwords from a string
    '''
    user = None
    passwd = None
    userfields = ['log','login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword', 
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword', 'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd','senha','contrasena']
    for login in userfields:
        login_re = re.search('%s=([^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group(1)
	    break
    for passfield in passfields:
        pass_re = re.search('%s=([^&]+)' % passfield, body, re.IGNORECASE)
        if pass_re:
            passwd = pass_re.group(1)
	    break
    if user and passwd:
        return (user, passwd)
    else:
	return None

