import adal
import uuid
from msrestazure.azure_active_directory import AADTokenCredentials
import requests
import datetime
import xmltodict
import json
import urllib
import hmac
import hashlib
import binascii
import base64
from pprint import pprint
import os


def refill_consts(settings):
    t_tenant_id = input('Enter tenant id: (default={u}) '.format(u=settings['tenant_id']))
    settings['tenant_id'] = settings['tenant_id'] if t_tenant_id == '' else t_tenant_id
    settings['authority_uri'] = settings['authority_host_uri'] + '/' + settings['tenant_id']


    t_storage_account_uri = input('Enter storage account url: (default={u}) '.format(u=settings['storage_account_uri']))
    settings['storage_account_uri'] = settings['storage_account_uri'] if t_storage_account_uri == '' else t_storage_account_uri
    if not settings['storage_account_uri'].startswith('https'):
        raise Exception('Please use "https://" schema')
    settings['account_name'] = settings['storage_account_uri'].split('.')[0].split('/')[-1]

    t_container_name = input('Enter container name: (default={u}) '.format(u=settings['container_name']))
    settings['container_name'] = settings['container_name'] if t_container_name == '' else t_container_name

    t_renew_account = input('Whether to login, "true" or "false"? (default={u})'.format(u=settings['renew_account'])).lower()
    if t_renew_account == '':
        pass
    elif t_renew_account in ['true', '1', 't', 'y']:
        settings['renew_account'] = True
    elif t_renew_account in ['false', '0', 'f', 'n']:
        settings['renew_account'] = False
    else:
        raise Exception('Please specify: true/false;1/0;y/n')

    t_save_setting = input('Save this settings? (default=True) ').lower()
    if t_save_setting in ['false', 0]:
        json.dump(settings, open('settings.json', 'w'), indent=True)

    if settings['debug'] is True:
        print('Settings:')
        print('\n'.join(['  ' + line for line in json.dumps(settings, indent=True).splitlines()]))


def renew_credentials(settings):
    context = adal.AuthenticationContext(settings['authority_uri'], api_version=None)
    code = context.acquire_user_code(settings['storage_account_uri'], settings['client_id'])
    print(code['message'])
    mgmt_token = context.acquire_token_with_device_code(settings['storage_account_uri'], code, settings['client_id'])
    credentials = AADTokenCredentials(mgmt_token, settings['client_id'])
    access_token = credentials.token['access_token']
    with open('account.txt', 'w') as at_out:
        at_out.write(access_token)

    return credentials
    
def request_user_delegation_sas_token():
    if os.path.exists('account.txt') is not True:
        raise Exception('Please login first')

    access_token = open('account.txt', 'r').read()

    datetime_start = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc, microsecond=0).isoformat().replace('+00:00', 'Z')
    datetime_expiry = (datetime.datetime.utcnow() + datetime.timedelta(days=5)).replace(
        tzinfo=datetime.timezone.utc, microsecond=0).isoformat().replace('+00:00', 'Z')

    print('Requesting a user delegation key from {ft} to {tt}'.format(ft=datetime_start, tt=datetime_expiry))

    url = settings['storage_account_uri'] + '/?restype=service&comp=userdelegationkey'

    headers = {
        'Cache-Control': 'no-cache',
        'Authorization': 'Bearer {at}'.format(at=access_token),
        'x-ms-version': settings['signed_version'],
        'x-ms-client-request-id': settings['client_id']
    }

    body = '''<?xml version="1.0" encoding="utf-8"?>
<KeyInfo>
    <Start>{st}</Start>
    <Expiry>{et}</Expiry>
</KeyInfo>'''.format(st=datetime_start, et=datetime_expiry)

    response = requests.post(url, data=body, headers=headers)
    response_body = response.content.decode(response.apparent_encoding)
    result_dict = xmltodict.parse(response_body)

    if 'UserDelegationKey' in result_dict:
        delegation_key = dict(result_dict['UserDelegationKey'])
    elif 'Error' in result_dict:
        err_str = '{code}: {msg}'.format(code=result_dict['Error']['Code'], msg=result_dict['Error']['Message'].replace('\n', '\n\t'))
        raise Exception('Error when requesting delegate key \n\t{err}; \n\tDetailed content:{de}'.format(err=err_str, de=json.dumps(result_dict)))
    else:
        raise Exception('Unknown response')

    signedpermissions = 'racwdl' # (r)ead, (a)dd, (c)reate, (w)rite, (d)elete (l)ist
    signedstart = delegation_key['SignedStart']
    signedexpiry = delegation_key['SignedExpiry']
    canonicalizedresource = '/blob/{a}/{c}'.format(c=settings['container_name'], a=settings['account_name'])  # optional?
    signedidentifier = ''  # ??  delegation_key['Value']
    signedoid = delegation_key['SignedOid']
    signedtid = delegation_key['SignedTid']
    signedkeystart = delegation_key['SignedStart']
    signedkeyexpiry = delegation_key['SignedExpiry']
    signedkeyservice = delegation_key['SignedService']
    signedkeyverion = delegation_key['SignedVersion']
    signedIP = ''
    signedProtocol = 'https,http'
    signedversion = delegation_key['SignedVersion']
    signedresource='c'
    timestamp = ''
    rscc = '' # 'rscc' #'no-cache'
    rscd = '' # 'rscd'
    rsce = '' # 'rsce'
    rscl = '' # 'rscl'
    rsct = '' # 'rsct' # binary'

    string_to_sign = signedpermissions + "\n" + signedstart + "\n" + signedexpiry + "\n" + canonicalizedresource + "\n" + signedoid + "\n" + signedtid + "\n" + signedkeystart + "\n" + signedkeyexpiry  + "\n" + signedkeyservice + "\n" + signedkeyverion + "\n" + signedIP + "\n" + signedProtocol + "\n" + signedversion + "\n" + signedresource + "\n" + timestamp +  "\n" + rscc + "\n" + rscd + "\n" + rsce + "\n" + rscl + "\n" + rsct
    # print(string_to_sign)
    api_secret = delegation_key['Value']
    signature = hmac.new(base64.b64decode(api_secret), msg=string_to_sign.encode('utf-8'), digestmod=hashlib.sha256).digest()
    signature = base64.b64encode(signature).decode('utf-8')

    sas = '?&rscc={rscc}&rsce={rsce}&rscd={rscd}&rscl={rscl}&rsct={rsct}&sv={sv}&sp={sp}&sr={sr}&st={st}&se={se}&skoid={skoid}&sktid={sktid}&skt={skt}&ske={ske}&sks={sks}&skv={skv}&spr={spr}&sig={sig}'.format(
        sv=urllib.parse.quote(settings['signed_version'], safe=''),
        sp=urllib.parse.quote(signedpermissions, safe=''),
        st=urllib.parse.quote(signedstart, safe=''),
        se=urllib.parse.quote(signedexpiry, safe=''),
        skoid=urllib.parse.quote(signedoid, safe=''),
        sktid=urllib.parse.quote(signedtid, safe=''),
        sig=urllib.parse.quote(signature, safe=''),
        sks=urllib.parse.quote(signedkeyservice, safe=''),
        skv=urllib.parse.quote(signedkeyverion, safe=''),
        sr=urllib.parse.quote(signedresource, safe=''),
        skt=urllib.parse.quote(signedkeystart, safe=''),
        ske=urllib.parse.quote(signedkeyexpiry, safe=''),
        spr=urllib.parse.quote(signedProtocol, safe=''),
        snapshot=urllib.parse.quote(timestamp, safe=''),
        rscc=urllib.parse.quote(rscc, safe=''),
        rscd=urllib.parse.quote(rscd, safe=''),
        rsce=urllib.parse.quote(rsce, safe=''),
        rscl=urllib.parse.quote(rscl, safe=''),
        rsct=urllib.parse.quote(rsct, safe=''),
    )

    return sas
    

if __name__ == '__main__':
    settings = json.load(open('settings.json'))
    refill_consts(settings)
    if settings['renew_account'] is True:
        renew_credentials(settings)
    delegation_sas = request_user_delegation_sas_token()
    print('----- delegation sas signature-----')
    print(delegation_sas)
    print('-----------------------------------')
    
    pass