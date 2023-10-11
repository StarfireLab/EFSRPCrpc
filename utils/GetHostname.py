# !/usr/bin/env python
# -*- coding:utf-8 -*-

import sys

from impacket.ldap import ldap

dNSHostName = []


def processRecord(item):
    global dNSHostName
    try:
        for attribute in item['attributes']:
            hostname = str(attribute['vals'][0])
            dNSHostName.append(hostname)
    except Exception as e:
        pass


def GetHostname(username, password, domain, lmhash, nthash, dcHost, doKerberos):
    domainParts = domain.split('.')
    baseDN = ''
    for i in domainParts:
        baseDN += 'dc=%s,' % i

    baseDN = baseDN[:-1]

    try:
        ldapConnection = ldap.LDAPConnection('ldap://%s' % dcHost, baseDN, dcHost)
        if doKerberos is not True:
            ldapConnection.login(username, password, domain, lmhash, nthash)
        else:
            ldapConnection.kerberosLogin(user=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash,
                                         kdcHost=dcHost)
    except ldap.LDAPSessionError as e:
        if str(e).find('strongerAuthRequired') >= 0:

            ldapConnection = ldap.LDAPConnection('ldaps://%s' % dcHost, baseDN, dcHost)
            if doKerberos is not True:
                ldapConnection.login(username, password, domain, lmhash, nthash)
            else:
                ldapConnection.kerberosLogin(user=username, password=password, domain=domain, lmhash=lmhash,
                                             nthash=nthash,
                                             kdcHost=dcHost)
        else:
            if str(e).find('NTLMAuthNegotiate') >= 0:
                print(
                    "NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos " "authentication instead.")
                sys.exit()

            else:
                if dcHost is not None:
                    print(
                        "If the credentials are valid, check the hostname and IP address of KDC. They " "must match exactly each other.")
                    sys.exit()

    searchFilter = "(sAMAccountType=805306369)"
    try:
        sc = ldap.SimplePagedResultsControl(size=100)
        ldapConnection.search(searchFilter=searchFilter,
                              attributes=['dNSHostName'],
                              sizeLimit=0, searchControls=[sc], perRecordCallback=processRecord)
    except ldap.LDAPSearchError as e:
        print(e)
        sys.exit()
    ldapConnection.close()

    global dNSHostName
    return dNSHostName
