#!/usr/bin/python3
#
# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Performs client tasks for testing IMAP OAuth2 authentication.

To use this script, you'll need to have registered with Google as an OAuth
application and obtained an OAuth client ID and client secret.
See https://developers.google.com/identity/protocols/OAuth2 for instructions on
registering and for documentation of the APIs invoked by this code.

NOTE: The OAuth2 OOB flow isn't a thing anymore. You will need to set the
application type to "Web application" and then add https://oauth2.dance/ as an
authorised redirect URI. This is necessary for seeing the authorisation code on
a page in your browser.

This script has 3 modes of operation:

1. Generate and authorize an OAuth2 token
2. Refresh access tokens using a refresh token
3. Generate OAuth2 string for IMAP/SMTP authentication
"""

import argparse
import base64
import imaplib
import json
import smtplib
import ssl
import sys
import urllib.parse
import urllib.request


# Constants for OAuth URLs and redirect
GOOGLE_ACCOUNTS_BASE_URL = 'https://accounts.google.com'
REDIRECT_URI = 'https://oauth2.dance/'

def SetupArgumentParser():
    parser = argparse.ArgumentParser(description="OAuth2 for IMAP/SMTP authentication")
    parser.add_argument('--generate_oauth2_token', action='store_true', help='Generates an OAuth2 token for testing')
    parser.add_argument('--generate_oauth2_string', action='store_true', help='Generates an initial client response string for OAuth2')
    parser.add_argument('--client_id', default=None, help='Client ID of the application that is authenticating.')
    parser.add_argument('--client_secret', default=None, help='Client secret of the application that is authenticating.')
    parser.add_argument('--access_token', default=None, help='OAuth2 access token')
    parser.add_argument('--refresh_token', default=None, help='OAuth2 refresh token')
    parser.add_argument('--scope', default='https://mail.google.com/', help='Scope for the access token')
    parser.add_argument('--test_imap_authentication', action='store_true', help='Attempts to authenticate to IMAP')
    parser.add_argument('--test_smtp_authentication', action='store_true', help='Attempts to authenticate to SMTP')
    parser.add_argument('--user', default=None, help='Email address of user whose account is being accessed')
    parser.add_argument('--quiet', action='store_true', default=False, help='Omit verbose descriptions and only print machine-readable outputs')
    
    return parser


def AccountsUrl(command):
    return f'{GOOGLE_ACCOUNTS_BASE_URL}/{command}'


def FormatUrlParams(params):
    return '&'.join(f'{key}={urllib.parse.quote(value, safe="~-._")}' for key, value in sorted(params.items()))


def GeneratePermissionUrl(client_id, scope='https://mail.google.com/'):
    params = {
        'client_id': client_id,
        'redirect_uri': REDIRECT_URI,
        'scope': scope,
        'response_type': 'code',
        'access_type': 'offline',
        'prompt': 'consent'
    }
    return f'{AccountsUrl("o/oauth2/auth")}?{FormatUrlParams(params)}'


def AuthorizeTokens(client_id, client_secret, authorization_code):
    """ Obtains OAuth access token and refresh token. """
    params = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': authorization_code,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    request_url = AccountsUrl('o/oauth2/token')
    try:
        response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params).encode('utf-8')).read()
        return json.loads(response)
    except urllib.error.URLError as e:
        print(f"Error occurred while requesting tokens: {e}")
        sys.exit(1)


def RefreshToken(client_id, client_secret, refresh_token):
    """ Obtains a new access token using a refresh token. """
    params = {
        'client_id': client_id,
        'client_secret': client_secret,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token'
    }
    request_url = AccountsUrl('o/oauth2/token')
    try:
        response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params).encode('utf-8')).read()
        return json.loads(response)
    except urllib.error.URLError as e:
        print(f"Error occurred while refreshing token: {e}")
        sys.exit(1)


def GenerateOAuth2String(username, access_token, base64_encode=True):
    """ Generates an IMAP OAuth2 authentication string. """
    auth_string = f'user={username}\1auth=Bearer {access_token}\1\1'
    if base64_encode:
        auth_string = base64.b64encode(auth_string.encode('utf-8'))
    return auth_string


def TestImapAuthentication(auth_string):
    """ Test IMAP authentication using OAuth2 string. """
    print("Testing IMAP Authentication...")
    try:
        imap_conn = imaplib.IMAP4_SSL('imap.gmail.com', ssl_context=ssl.create_default_context())
        imap_conn.debug = 4
        imap_conn.authenticate('XOAUTH2', lambda x: auth_string)
        imap_conn.select('INBOX')
    except Exception as e:
        print(f"IMAP authentication failed: {e}")


def TestSmtpAuthentication(auth_string):
    """ Test SMTP authentication using OAuth2 string. """
    print("Testing SMTP Authentication...")
    try:
        smtp_conn = smtplib.SMTP_SSL('smtp.gmail.com', context=ssl.create_default_context())
        smtp_conn.set_debuglevel(True)
        smtp_conn.ehlo('test')
        smtp_conn.docmd('AUTH', 'XOAUTH2 ' + base64.b64encode(auth_string.encode('utf-8')).decode('utf-8'))
    except Exception as e:
        print(f"SMTP authentication failed: {e}")


def RequireOptions(options, *args):
    missing = [arg for arg in args if getattr(options, arg) is None]
    if missing:
        print(f'Missing options: {", ".join(missing)}')
        sys.exit(-1)


def main():
    parser = SetupArgumentParser()
    options = parser.parse_args()

    if options.refresh_token:
        RequireOptions(options, 'client_id', 'client_secret')
        response = RefreshToken(options.client_id, options.client_secret, options.refresh_token)
        print(f'Access Token: {response["access_token"]}')
        print(f'Access Token Expiration Seconds: {response["expires_in"]}')
    elif options.generate_oauth2_string:
        RequireOptions(options, 'user', 'access_token')
        oauth2_string = GenerateOAuth2String(options.user, options.access_token)
        print(f'OAuth2 argument:\n{oauth2_string.decode("utf-8")}')
    elif options.generate_oauth2_token:
        RequireOptions(options, 'client_id', 'client_secret')
        print(f'To authorize token, visit this url and follow the directions: {GeneratePermissionUrl(options.client_id, options.scope)}')
        authorization_code = input('Enter verification code: ')
        response = AuthorizeTokens(options.client_id, options.client_secret, authorization_code)
        print(f'Refresh Token: {response["refresh_token"]}')
        print(f'Access Token: {response["access_token"]}')
        print(f'Access Token Expiration Seconds: {response["expires_in"]}')
    elif options.test_imap_authentication:
        RequireOptions(options, 'user', 'access_token')
        TestImapAuthentication(GenerateOAuth2String(options.user, options.access_token, base64_encode=False))
    elif options.test_smtp_authentication:
        RequireOptions(options, 'user', 'access_token')
        TestSmtpAuthentication(GenerateOAuth2String(options.user, options.access_token, base64_encode=False))
    else:
        parser.print_help()
        print('Nothing to do, exiting.')


if __name__ == '__main__':
    main()
