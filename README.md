Quick and dirty python script to process nmap output from the following scan:

masscan  -p21,443,8443 10.0.0.0/8 --rate 8000 | awk '{print $6}' >> /scripts/nmap/SSLscanipList.txt

nmap --unique -Pn -T4 --script=ssl-cert,ssl-enum-ciphers,sslv2 -p 21,443,8443,9443,8883 -iL /scripts/nmap/SSLscanipList.txt -oX /scripts/nmap/network.xml

python /scripts/nmap/SSL-directory-parser.py -f /scripts/nmap/network.xml
