#         This file takes in requests from a client through a socket connection and sends the request to the
#         specified webserver. It then recieves the data from the websever and sends it back to the client
#         Any request that is not a GET request will return 501 not implemented
#         Any request not in HTTP format will return 401 Bad request
import socket
import sys
import json
import threading
import _thread
import re
import _json
import datetime
import _md5
import hashlib
# makes a socket connection with localhost and waits for a response
# starts new proxy thread when socket recieves data
def listen(port, key):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', port);
    print('starting up on localhost ' + str(server_address))
    sock.bind(server_address)
    sock.listen(50)
    while True:
        print('waiting for connection')
        connection, client_address = sock.accept()
        print('connection from' + str(client_address))
        _thread.start_new_thread(proxy, (port, sock, connection))
    sock.close


# parses request from socket and sends to the host specefied in the http request
# sends response from the server back to the original request host
def proxy(port, sock, connection):
    # make connection
    try:
        data = connection.recv(2048).decode(errors='ignore')
        while (data.find("\r\n\r\n") == -1):
            data += connection.recv(2048).decode()
    except:
        print("Cannot decode data")
        connection.close
        return None
    contentType = ""
    print(data)
    today = datetime.date.today()
    try:
        lines = data.split("\r\n")
        first_line = lines[0]
        request = first_line.split(" ")[0]
    except IndexError:
        badRequest = construct_badRequest_message(today,data,port)
        connection.sendall(badRequest)
    x = 0

    time = today.ctime()

    # format bad request syntax
    badRequest = construct_badRequest_message(today,data,port)

    # check first line formatting
    if (len(lines) > 2):
        if (first_line.find("HTTP/") == -1):
            x = re.search("([A-Za-z]+) *(http?://.*)*/(.)*", first_line)
        else:
            x = re.search("([A-Za-z]+) *(http?://.*)* (.)* +(HTTP/[0-9][.][0-9])*", first_line)
    else:
        x = re.search("([A-Za-z]+) +(http?://.*) +(HTTP/[0-9][.][0-9])", first_line)

    if (x is None):
        print("bad request")
        connection.send(badRequest.encode())
        connection.close()
        return None
    url = first_line.split(" ")[1]
    host = ""
    notImplemented = construct_notImplemented_message(today, data, url, port)
    # find the port if it is in the first line
    try:
        port = first_line.split(":")[2]
        port = port.split("/")[0]
    except IndexError:
        port = 80
    # parse and validate http request
    if (len(lines) > 2):
        j = 1
        while (j < len(lines)):
            res = re.search("([A-z]-?[A-z]?-?[A-z]?)+: .+", lines[j])
            if (res is None and lines[j] != "\r\n" and lines[j] != ""):
                print("bad request")
                connection.send(badRequest.encode())
                sys.exit()
            # find the host
            if (lines[j].split(":")[0] == "Host"):
                host = lines[j].split(":")[1]
                host = host.replace("\\n", "")
                host = host.replace("\\r", "")
                # if port is specified find it
                try:
                    port = lines[j].split(":")[2]
                except IndexError:
                    port = 80
            j = j + 1

    if (x is None):
        connection.send(badRequest.encode())
        print("request not implemented")
        print("connection closed")
        connection.close()
        return None

    if (request != "GET"):
        connection.send(notImplemented.encode())
        print("Requst not implemented")
        print("Connection with %s closed", host)
        connection.close()
        return None

    if (port is ""):
        port = first_line.split(":", )[2]
        port = port.split("/")[1]
    try:
        int(port)
    except ValueError:
        port = 80

    # format the url to the most simple form
    url = url.replace("https://", "")
    url = url.replace("http://", "")
    url = url.replace("/", "")
    url = url.split("~")[0]
    host = host.strip()  # get rid of any whitespace on the host
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.settimeout(10)

    serverRequest = first_line
    # format the data to relative host format
    if (data.find("http://") != -1):
        serverRequest = serverRequest.replace("http://", "")
        serverRequest = serverRequest.replace(url, "")
        serverRequest = serverRequest.replace((":" + str(port)), "")
        serverRequest = serverRequest.replace("\r\n\r\n", "")
    if (url == ""):
        serverRequest += "\r\nHost: " + str(host) + "\r\n"
    else:
        serverRequest += "\r\nHost: " + str(url) + "\r\n"
    j = 2
    while (j < len(lines)):
        if (lines[j] == "\r\n"):
            serverRequest += lines[j]
        else:
            serverRequest += lines[j] + "\r\n"
        j += 1
    url = url.replace((":" + str(port)), "")  # remove port from url
    # check for relaitve format
    if (host == ""):
        address = (url, int(port))
    else:
        address = (host, int(port))
    # make connection and send request
    print("sending request to server")
    try:
        serverSocket.connect(address);
    except socket.timeout:
        print("Connection timed out")
        serverSocket.close()
        return None
    print(serverRequest)
    #send the request to the remote server
    serverSocket.sendall(serverRequest.encode())
    Api = key
    data = b""
    receive_message(serverSocket,connection,Api,data)
    return None
#receives the requested data from the remote server and returns it to the client
#if the data type is html/text the word simple is replaced with silly
#if the data type is anything else it will hash the data and scan it with virus total and reject the request if any scan is positive
def receive_message(serverSocket,connection,Api,data):
    # receive the data from the remote server and send it back to the client
    while True:
        datum = serverSocket.recv(2048)
        if not datum:
            break
        data += datum
    # check if the file type is html
    if (data.find(b"Content-Type: text/html") != -1):
        data = data.replace(b"simple", b"silly")
        data = data.replace(b"Simple", b"Silly")
        File = False
    # else we will treat it as a file
    else:
        # remove the header from the contents of the file
        pos = data.find(b"\r\n\r\n");
        pos += len(b"\r\n\r\n")
        header = data[:pos]
        fileData = data[pos:]
        File = True
        # check if the file is a virus
        if fileData[0:6].decode("utf-8") == "CS4480":
            fileData = fileData[6:]
    # if the detected data type isnt html we will assume it is a file and scan it with virus total
    if (File):
        # hash the file and send the data to virus total
        hash = hashlib.md5(fileData).hexdigest()
        virusReq = "GET http://www.virustotal.com/vtapi/v2/file/report?apikey=" + Api + "&resource=" + hash + " HTTP/1.1\r\nConnection:close\r\n\r\n"
        virusSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        virusSocket.connect(("virustotal.com", 80))
        virusSocket.sendall(virusReq.encode())
        virusSocket.settimeout(5)
        value = b""

        # get the response from virus total
        while True:
            val = virusSocket.recv(2048)
            if not val:
                break
            value += val
        # seperate the header from the body of the json object
        pos = value.find(b"\r\n\r\n")
        pos += len(b"\r\n\r\n")
        value = value[pos:]
        # decode the json object
        resp = json.loads(value)
        total = resp["total"]
        positives = resp["positives"]
        today = datetime.date.today()
        # construct the malware message
        malwareMessage = construct_malware_message(positives,total, hash, today)
        # check if virus total detected malware
        if (positives > 0):
            connection.sendall(malwareMessage.encode())
            serverSocket.close()
            connection.close()
            return None
        # otherwise it is safe to send the data to the client
        else:
            connection.sendall(data)
            serverSocket.close()
            connection.close()
            return None

    connection.sendall(data)
    serverSocket.close()
    print("Connection closed succsessfully")
    connection.close()
    return None
#constructs the not impelmented message
def construct_notImplemented_message(date,data,url,port):
    now = datetime.datetime.now()
    notImplemented = "HTTP/1.1 501 Not Imeplemented\r\nDate:" + str(now.strftime("%a, %d %b %Y %H:%M:%S %Z"))+ "\r\nServer: CS4480-Proxy\r\nContent-Length:" + "[" + str(len(data)) + "]\r\n"
    notImplemented += "Connection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n<!DOCTYPE HTML PUBLIC \-//IETF//DTD HTML 2.0//EN>\r\n\r\n<html><head>\r\n"
    notImplemented +="<title>501 Not Implemented</title>\r\n</head><body>\r\n<h1>Not Imeplemented</h1>\n<p>This server supports no more han a mere GET request sadly.<br />"
    notImplemented +="</p>\r\n<hr>\r\n<address>Apache/2.4.29 (Ubuntu) Server at" + str(url) + "Port" + str( port) + "</address>\r\n</body></html>\r\n"
    return notImplemented
#constructs the bad request message
def construct_badRequest_message(date,data,port):
    now = datetime.datetime.now()
    badRequest = "HTTP/1.1 400 Bad Request\r\nDate:" + str(now.strftime("%a, %d %b %Y %H:%M:%S %Z")) + "\r\nServer: CS4480-Proxy\r\nContent-Length:" + "[" + str(len(data)) + "]"
    badRequest += "Connection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n<!DOCTYPE HTML PUBLIC \-//IETF//DTD HTML 2.0//EN>\r\n\r\n<html><head>\r\n"
    badRequest += "<title>400 Bad Request</title>\r\n</head><body>\r\n<h1>Bad Request</h1>\r\n<p>Your browser sent a request that this server could not understand.<br />"
    badRequest += "</p>\r\n<hr>\r\n<address>Apache/2.4.29 (Ubuntu) Server at" + str("localhost") + "Port" + str(port) + "</address>\r\n</body></html>\r\n"
    return badRequest
#constructs the malware message
def construct_malware_message(positives,total,hash,date):
    now = datetime.datetime.now()
    malewareMessage = "<html>\r\n <body>\r\n  <h1>The File you requested appears to contain Malware.</h2>\r\n  "
    malewareMessage += "<h2>Information:</h2>\r\n  <ul>\r\n   <li>MD5 Hash: " + str(hash) + "</li>"
    malewareMessage += "\r\n   <li>Positives:" + str(positives) + "/" + str(total) + "</li>\r\n   <li>Scan Date: " + str(now.strftime("%a, %d %b %Y %H:%M:%S %Z")) + "</li>"
    malewareMessage += "\r\n   <li>First Scan ID: Bkav</li>\r\n  </ul>\r\n  <p>Thanks to VirusTotal for this information.</p>"
    malewareMessage += "\r\n  <p>For more information see <a href=\"https://www.virustotal.com/f\ile/09a1c17ac55cde962b4f3bcd61140d752d86362296ee74736000a6a647c73d8c/analysis/1\/"
    malewareMessage += "\r\n548534839/\">Virus Total Permanent Link</a></p>\r\n </body>\r\n</html>\r\n"
    return malewareMessage
# gathers command line arguments and passes them into the listen method
# exits with code 1 if 2 command line arguments are not given
if __name__ == "__main__":
    if (len(sys.argv) == 3):
        port = sys.argv[1]
        key = sys.argv[2]
    else:
        sys.stdout.write("Please specify a port and a key")
        sys.exit(1)
    try:
        listen(int(port), key)
    except KeyboardInterrupt:
        pass
