#original concept from http://www.smeegesec.com/2014/06/http-security-headers-nmap-parser.html

import getopt, datetime
import os
import sys
import re
import glob
from xml.dom import minidom

def usage():
    print("""
    -d, --directory   directory to read all files in one at a time; example -d /output/*.csv1
    -f, --file      xml to read in; example: -f output10-0.csv1
    -o, --output      Filename of output file for HTML report
    """)
#Check and create input and output files
def main():
    print("You made it to main!")
    if (output != ''):
        if output.endswith('.html'):
            outFile = open(output, 'w')
        else:
            outFile = open(output + '.html', 'w')
    else:
        outFile = open('nmap-SSL-scan-output.html', 'w')

    if (inFile != ''):
        if not os.path.isfile(inFile):
            print('\nThere was an error opening file: %s (1)' % inFile)
            sys.exit()
        else:
            try:
                outFile = header(outFile)
                outFile = processFile(inFile, outFile)
                outFile = footer(outFile)
            except:
                print('\nThere was an error opening file: %s (2)' % inFile)

    elif (directory != ''):
        print("Directory is not null.")
        if (wildcard == ''):
            print('\nExiting, if using directory must use wildcard as well.')
            sys.exit()
        print("Finding files.")
        findFiles = directory + '/' + wildcard
        print("Found files:")
        print(findFiles)
        onlyfiles = glob.glob(findFiles)
        print(onlyfiles)
        outFile = header(outFile)
        for f in onlyfiles:
            try:
                outFile = processFile(f, outFile)
            except:
                print('\nThere was an error opening file: %s (3)' % f)
        outFile = footer(outFile)

    else:  # if (inFile = '') and (directory = ''):
        print('\nYou must provide a file or directory to continue.')
        sys.exit()

def header(outFile):
    outFile.write(
        '<html>\n<head>\n<title>NMAP SSL Scan Report</title>\n<style>\ntable,th,td\n{\nborder:1px solid black; text-align:center; font-size:85%; letter-spacing:1px\n}\np\n{\nfont-size:85%; margin: 5; padding: 0;\n}\nh5\n{\nmargin: 0; padding: -5;\n}\nh6\n{\nmargin: 0; padding: 0;\n}\n</style></head>\n<body>\n<table>')
    outFile.write('<tr><th>')

    #List of security headers which are checked for and reported on
    headerList = ['ip', 'port', 'subjectName', 'issuerName', 'bits', 'pubkeyType', 'notBefore', 'notAfter', 'sig_algo', 'SSLv2', 'SSLv3', 'TLS1.0', 'TLS1.1', 'TLS1.2', 'Overall' ]
    for item in headerList:
        value = '</th><th bgcolor="F2F2F2">{0}'.format(item)
        outFile.write(value)
    outFile.write('</th></tr>')

    return outFile

#Parse the Nmap .xml file. Create a dictionary where each key is a specific host:port, and each value is a list of found security headers
def processFile(f, outFile):
    print('\nInput File: %s' % f)
    print('Output File: %s' % outFile.name)
    print('Reading in xml, may take awhile')

    xmlDoc = minidom.parse(f)
    hostList = xmlDoc.getElementsByTagName('host')
    assetDict = dict()

    print('Processing, may take a while')


    for host in hostList:
      assets = []
      hostname = ''
      addr = ''

      for hostChildNode in host.childNodes:
        asset = []
        if hostChildNode.nodeName == 'address':
          temp = hostChildNode.getAttribute('addrtype')
          if temp == 'ipv4':  #have to deal with issues where it pulls back both a mac and the IP address and since this is a for loop and the mac is second, that gets written as the IP!
            addr = hostChildNode.getAttribute('addr')
        if hostChildNode.nodeName == 'hostnames':
          for child in hostChildNode.childNodes:
            if child.nodeName == 'hostname':
              hostname = child.getAttribute('name')

        if hostChildNode.nodeName == 'ports':
          for portsChildNode in hostChildNode.childNodes:

            subjectName = ''
            issuerName = ''
            bits = ''
            pubkeyType = ''
            notBefore = ''
            notAfter = ''
            sig_algo = ''
            SSLv2 = 'No'
            SSLv3 = 'No'
            TLSv10 = 'No'
            TLSv11 = 'No'
            TLSv12 = 'No'
            state = ''

            if portsChildNode.nodeName == 'port':

              port = portsChildNode.getAttribute('portid')
              state = ''
              for portChildNode in portsChildNode.childNodes:
                if portChildNode.nodeName == 'state':
                  state = portChildNode.getAttribute('state')
                if state == 'open':
                  if portChildNode.nodeName == 'script':
                    id = portChildNode.getAttribute('id')
                    if id == 'ssl-cert':
                      for tableNode in portChildNode.childNodes:
                        try:
                          key = tableNode.getAttribute('key')
                          if key == 'subject':
                            for elem in tableNode.childNodes:
                              if elem.nodeType == 1:
                                value = elem.attributes['key'].nodeValue
                                if value == 'commonName':
                                  for i in elem.childNodes:
                                    subjectName = i.nodeValue
                          if key == 'issuer':
                            for elem in tableNode.childNodes:
                              if elem.nodeType == 1:
                                value = elem.attributes['key'].nodeValue
                                if value == 'commonName':
                                  for i in elem.childNodes:
                                    issuerName = i.nodeValue
                          if key == 'pubkey':
                            for elem in tableNode.childNodes:
                              if elem.nodeType == 1:
                                value = elem.attributes['key'].nodeValue
                                if value == 'bits':
                                  for i in elem.childNodes:
                                    bits = i.nodeValue
                                if value == 'type':
                                  for i in elem.childNodes:
                                    pubkeyType = i.nodeValue
                          if key == 'validity':
                            for elem in tableNode.childNodes:
                              if elem.nodeType == 1:
                                value = elem.attributes['key'].nodeValue
                                if value == 'notBefore':
                                  for i in elem.childNodes:
                                    notBefore = i.nodeValue
                                if value == 'notAfter':
                                  for i in elem.childNodes:
                                    notAfter = i.nodeValue
                          if key == 'sig_algo':
                            for i in tableNode.childNodes:
                              sig_algo = i.nodeValue
                              if sig_algo == 'sha1WithRSAEncryption':
                                sig_algo = 'sha1'
                              elif sig_algo == 'sha256WithRSAEncryption':
                                sig_algo = 'sha256'
                        except:
                          pass
    #                  asset = [addr, hostname, port, subjectName, issuerName, bits, pubkeyType, notBefore, notAfter, sig_algo]
    #                  print asset

                    elif id == 'ssl-enum-ciphers':
                      for tableNode in portChildNode.childNodes:
                        try:
                          key = tableNode.getAttribute('key')
                          if key == 'SSLv2':
                            SSLv2 = 'Yes'
                          if key == 'SSLv3':
                            SSLv3 = 'Yes'
                          if key == 'TLSv1.0':
                            TLSv10 = 'Yes'
                          if key == 'TLSv1.1':
                            TLSv11 = 'Yes'
                          if key == 'TLSv1.2':
                            TLSv12 = 'Yes'
                        except:
                          pass

                    elif id == 'sslv2':
                      SSLv2 = 'Yes'

              if state == 'open':
                asset = [hostname, addr, port, subjectName, issuerName, bits, pubkeyType, notBefore, notAfter, sig_algo, SSLv2, SSLv3, TLSv10, TLSv11, TLSv12]
    #            print asset

                outFile.write('<tr>')
                x = 0
                test = ''
                for i in asset:
                  if (x == 5) and (i == '1024'):
                    value = '<td bgcolor="FFFF33">{0}</td>'.format(i)
                  elif (x == 8) and (i != ''):
                    today = datetime.datetime.now()
                    date = datetime.datetime.strptime(i, '%Y-%m-%dT%H:%M:%S')
                    if (today > date):
                      value = '<td bgcolor="FF4D4D">{0}</td>'.format(i)
                    elif (datetime.datetime.now() + datetime.timedelta(days=90) > date):
                      value = '<td bgcolor="FFFF33">{0}</td>'.format(i)
                    else:
                      value = '<td>{0}</td>'.format(i)
                  elif (x == 9) and ((i == 'sha1') or (i == 'md5WithRSAEncryption')):
                    value = '<td bgcolor="FF4D4D">{0}</td>'.format(i)
                  elif ((x == 10) or (x == 11)) and (i == 'Yes'):
                    value = '<td bgcolor="FF4D4D">{0}</td>'.format(i)
                  elif ((x == 12) or (x == 13)) and (i == 'Yes'):
                    value = '<td bgcolor="FF4D4D">{0}</td>'.format(i)
                  elif (x == 14) and (i == "No"):
                    value = '<td bgcolor="FF4D4D">{0}</td>'.format(i)
                  elif ((x == 12) or (x == 13) or (x == 14)) and (i == 'No'):
                    test = test + 'No'
                    value = '<td>{0}</td>'.format(i)
                  else:
                    value = '<td>{0}</td>'.format(i)
                  outFile.write(value)
                  x = x + 1
                if test == 'NoNoNo':
                  outFile.write('<td bgcolor="FF4D4D">Concern</td>')
                else:
                  outFile.write('<td></td>')
                outFile.write('</tr>')
    print('File processing finished.')
    return outFile

def footer(outFile):
    outFile.write('</table>')
    outFile.write('\n</body>\n</html>')
    return outFile

try:
    opts, args = getopt.getopt(sys.argv[1:], "f:o:w:d:", ['file=', 'output=', 'wildcard=', 'directory='])
    inFile = output = directory = wildcard = ''
    proceed = False
    for opt, val in opts:
        if opt in ('-f', '--file'):
            if not os.path.isfile(val):
                print('\nFile "%s" does not appear to exist, please verify file name.' % val)
                sys.exit()
            else:
                proceed = True
            inFile = val
        if opt in ('-o', '--output'):
            output = val
        if opt in ('-d', '--directory'):
            if not os.path.isdir(val):
                print('\nDir "%s" does not appear to exist, please verify directory name.' % val)
                sys.exit()
            else:
                print("Directory selection:" + val)
                proceed = True
                directory = val
        if opt in ('-w', '--wildcard'):
            wildcard = val

    if (__name__ == '__main__') and proceed == True:
        main()
    else:
        print('Need to provide a file or directory to process')
        usage()

except getopt.error:
    usage()

