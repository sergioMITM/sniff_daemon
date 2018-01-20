import re

def get_body_url(full_load):
#Pull out pertinent info from the parsed HTTP packet data
    url = ''
    host = ''
    method = None
    path = None
    http_methods = ['GET ', 'POST ', 'CONNECT ', 'TRACE ', 'TRACK ', 'PUT ', 'DELETE ', 'HEAD ']
    http_line, header_lines, body = parse_http_load(full_load, http_methods)
    headers = headers_to_dict(header_lines)
    if 'host' in headers: host = headers['host']

    if http_line != None:
        method, path = parse_http_line(http_line, http_methods)
        url = get_http_url(method, host, path, headers)
    return headers, body, url

def get_http_url(method, host, path, headers):
    '''
    Get the HTTP method + URL from requests
    '''
    if method != None and path != None:
        http_url_req = method + ' ' + path
	try:
            # Make sure the path doesn't repeat the host header
	    # but this fails sometimes, so we're using a try block
            if host != '' and not re.match('(http(s)?://)?'+host, path):
                http_url_req = method + ' ' + host + path
	except:
	    pass

        http_url_req = url_filter(http_url_req)

        return http_url_req

def headers_to_dict(header_lines):
    '''
    Convert the list of header lines into a dictionary
    '''
    headers = {}
    for line in header_lines:
        lineList=line.split(': ', 1)
        key=lineList[0].lower()
        if len(lineList)>1:
                headers[key]=lineList[1]
        else:
                headers[key]=""
    return headers

def parse_http_line(http_line, http_methods):
    '''
    Parse the header with the HTTP method in it
    '''
    http_line_split = http_line.split()
    method = ''
    path = ''

    # Accounts for pcap files that might start with a fragment
    # so the first line might be just text data
    if len(http_line_split) > 1:
        method = http_line_split[0]
        path = http_line_split[1]

    # This check exists because responses are much different than requests e.g.:
    #     HTTP/1.1 407 Proxy Authentication Required ( Access is denied.  )
    # Add a space to method because there's a space in http_methods items
    # to avoid false+
    if method+' ' not in http_methods:
        method = None
        path = None

    return method, path

def parse_http_load(full_load, http_methods):
    '''
    Split the raw load into list of headers and body string
    '''
    try:
        headers, body = full_load.split("\r\n\r\n", 1)
    except ValueError:
        headers = full_load
        body = ''
    header_lines = headers.split("\r\n")

    # Pkts may just contain hex data and no headers in which case we'll
    # still want to parse them for usernames and password
    http_line = get_http_line(header_lines, http_methods)
    if not http_line:
        headers = ''
        body = full_load

    header_lines = [line for line in header_lines if line != http_line]

    return http_line, header_lines, body

def get_http_line(header_lines, http_methods):
    '''
    Get the header with the http command
    '''
    for header in header_lines:
        for method in http_methods:
            # / is the only char I can think of that's in every http_line
            # Shortest valid: "GET /", add check for "/"?
            if header.startswith(method):
                http_line = header
                return http_line

def url_filter(http_url_req):
    '''
    Filter out the common but uninteresting URLs
    '''
    if http_url_req:
        d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
        if any(http_url_req.endswith(i) for i in d):
            return

    return http_url_req


