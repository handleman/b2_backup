import argparse
import os
import base64
import json
import urllib.request
import hashlib
import urllib.parse

from urllib.request import Request, urlopen
from urllib.error import HTTPError

from pprint import pprint

# global vaiables
uploadUrl = None
authTokenUpload = None
authToken = None
apiUrl = None
bucketId = None

def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='''Makes copy of your files to given B2 folder.
            You need to have "keyID" and "App Key" to authorize in B2 services.
            KeyId and App Key can be found in B2 Cloud Storage client dashboard
            ''')
    parser.add_argument(
        "-v", "--version", action="version",
        version=f"{parser.prog} version 1.0.0"
    )
    parser.add_argument(
        'directory', help="Path to directory you want to upload to B2 cloud")
    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument(
        '-k', '--key-id', help='B2 "keyID" value (is given to you when you create B2 bucket and access "App key" for it)', required=True
    )
    requiredNamed.add_argument(
        '-a', '--app-key', help='B2 "Application Key" value (is given to you when you create B2 bucket and access "App key" for it)', required=True
    )
    return parser


def b2_authorize(applicationKeyId, applicationKeyValue):
    id_and_key = f'{applicationKeyId}:{applicationKeyValue}'
    id_and_key_base64 = base64.b64encode(
        id_and_key.encode('utf-8')).decode('utf-8')
    basic_auth_string = f'Basic {id_and_key_base64}'
    headers = {'Authorization': basic_auth_string}
    b2_auth_url = 'https://api.backblazeb2.com/b2api/v2/b2_authorize_account'

    request = Request(b2_auth_url, headers=headers)
    with urlopen(request) as response:
        auth = json.loads(response.read())
    response.close()
    return auth


def b2_get_upload_url(apiUrl, authToken, bucketId):
    b2_get_upload_url = f'{apiUrl}/b2api/v2/b2_get_upload_url'
    get_url_body = {'bucketId': bucketId}
    get_url_headers = {'Authorization': authToken}
    request = Request(b2_get_upload_url, data=json.dumps(get_url_body).encode('utf-8'), headers=get_url_headers)
    with urlopen(request) as response:
        uploadData = json.loads(response.read())
    response.close()
    return uploadData

def b2_upload_file_callback(filePathName):
    global uploadUrl, authTokenUpload
    allowed_codes = [500, 503]
    content_type = 'b2/x-auto'
    file_path_name_encoded = urllib.parse.quote(filePathName)

    # we trim backslash in order to create right directories structure on B2 Cloud
    if file_path_name_encoded[0] == '/':
        file_path_name_encoded = file_path_name_encoded[1:]

    with open(filePathName, 'br') as file:
        file_data = file.read()
    file.close()
    file_hash = hashlib.sha1(file_data).hexdigest()

    headers = {
        'Authorization': authTokenUpload,
        'X-Bz-File-Name': file_path_name_encoded,
        'Content-Type': content_type,
        'X-Bz-Content-Sha1': file_hash
    }

    request = Request(uploadUrl, data=file_data, headers=headers)
    try:
        print(f'[ Upload in progress ]: {filePathName}')
        response = urlopen(request)
        upload_info = json.loads(response.read())
        response.close()
        file_name = upload_info['fileName']
        print(f'[ Uploaded Successfully ]: {file_name}')
    except HTTPError as err:
        # B2 Cloud sends 500,503 errors when need to re-establish upload connection (upload url and authenticationToken could be changed)
        if err.code in allowed_codes:
            print('[ 503 error, reiastablishing connection... ]')
            uploadSettings = b2_get_upload_url(apiUrl, authToken, bucketId)
            uploadUrl = uploadSettings['uploadUrl']
            authTokenUpload = uploadSettings['authorizationToken']
            b2_upload_file_callback(filePathName)
    



def applyForFile(filesPath, callback):
    excludes = ['.DS_Store', '.Trashes', '.fseventsd', '.Spotlight-V100', 'desktop.ini']

    for root, directories, files in os.walk(filesPath):
        for name in files:
            if name not in excludes:
                full_name = os.path.join(root, name)
                callback(full_name)



def main() -> None:
    global authToken, uploadUrl, authTokenUpload, apiUrl, bucketId
    parser = init_argparse()
    args = vars(parser.parse_args())

    directory = args["directory"]
    keyId = args["key_id"]
    keyValue = args["app_key"]

    auth = b2_authorize(keyId, keyValue)

    apiUrl = auth['apiUrl']
    authToken = auth['authorizationToken']
    bucketId = auth['allowed']['bucketId']
    uploadSettings = b2_get_upload_url(apiUrl, authToken, bucketId)

    uploadUrl = uploadSettings['uploadUrl']
    authTokenUpload = uploadSettings['authorizationToken']
    applyForFile(directory, b2_upload_file_callback)

    print('[ All files were successfully uploaded ]!')


if __name__ == "__main__":
    main()
