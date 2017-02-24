import crypt
from hmac import compare_digest as compare_hash
import zipfile
import socket
import nmap
import json


def get_dictionary_words():
    #open and parse dictionary file
    with open('HW2dictionary.txt') as g:
        dictwords = g.readlines()
        dictwords = [x.strip() for x in dictwords]
        print "Dictionary Words", dictwords
        return dictwords


def get_passwords():
    #open and parse passwords file
    with open('HW2passwords.txt') as f:
        data = f.readlines()
        passwords = [x.split(":")[1].strip() for x in data]
        print "Passwords:", passwords
        return passwords


def get_users():
    with open('HW2passwords.txt') as f:
        data = f.readlines()
        users = [x.split(":")[0].strip() for x in data]
        print "Users:", users
        return users    


#Exercise 1
def unix_password_cracker(dictwords, passwords, users):
    i=0
    for password in passwords:
        pass_found = 0
        print "Password Hash: ", password
        #We know DES algorithm was used based on 13 char output
        #hashed password has first 2 character of DES as salt
        salt = password[:2]
        print "Identified Salt: ", salt

        #iterate through dictionary words
        for word in dictwords:
            hashed = crypt.crypt(word, salt)
            if compare_hash(password, crypt.crypt(word, salt)):
                print "Found Plaintext Password for User %s, Password = %s: " % (users[i], word)
                pass_found=1
                i += 1
        if pass_found == 0:
            print "No Password Found for User %s" % (users[i])
            i += 1
    return
                
    
#Exercise 2        
def zip_file_password_cracker(dictwords):
    for word in dictwords:
        #with zipfile.ZipFile('evil.zip', 'r', password) as zf:
        with zipfile.ZipFile('evil.zip') as zf:
            #zf.extractall(pwd=word)
            try:
                result = zf.extractall(pwd=word)
                #Returns None if no wrong password exception, which means correct password
                if result == None:
                    print "Found Zip Password: %s" % (word)
            except:
                print "Incorrect password: ", word

    return


#Exercise 3 Part 1
def port_scanner_socket():
    #what IP range do we need to scan
    print "Simple Socket Port scanner"
    ports_to_scan = [21, 22, 23, 25, 80, 143, 443]
    remoteServerIP='54.245.90.180'
    print "Scanning IP %s" % (remoteServerIP) 

    try:
        for port in ports_to_scan: 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                print "Port {}:      Open".format(port)
            else:
                print "Port {}:      Closed".format(port)
            sock.close()

    except:
        print "Exception"
    return


#Exercise 3 Part 2
def port_scanner_nmap():
    print "Nmap Port Scanner"
    nm = nmap.PortScanner()
    remoteServerIP='54.245.90.180'
    print "Scanning IP %s" % (remoteServerIP) 
    ports_to_scan = ['21', '22', '23', '25', '80', '143', '443']
    try:
        for port in ports_to_scan:
            result = nm.scan(remoteServerIP, port)
            #print result
            port = int(port)
            #print result
            reason = result['scan'][remoteServerIP]['tcp'][port]['reason']
            #print "Port %s    Result: %s" % (port, result['scan'][remoteServerIP]['tcp'][port]['reason'])
            if reason == 'conn-refused' or reason == 'no-response':
                print "Port %s    Closed" % (port)
            elif reason == 'syn-ack':
                print "Port %s    Open" % (port)
    except:
        print "Exception"
    return


def main():
    dictwords = get_dictionary_words()
    passwords = get_passwords()
    users = get_users()

    #Exercise 1
    print "Exercise #1-----------------------------------"
    unix_password_cracker(dictwords, passwords, users)
    #Exercise 2
    print "Exercise #2-----------------------------------"
    zip_file_password_cracker(dictwords)
    #Exercise 3
    print "Exercise #3-----------------------------------"
    port_scanner_socket()
    port_scanner_nmap()

    return


if __name__ == "__main__":
    main()