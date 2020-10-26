import argparse
from array import array
from hashlib import sha1
import os
import base64
import json
import hashlib
import urllib.parse
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from typing import Callable

# global vaiables
uploadUrl: str = None
authTokenUpload: str = None
authToken: str = None
apiUrl: str = None
bucketId: str = None

def _prepare_file_name(path: str) -> str:
    full_name_encoded = urllib.parse.quote(path)
     # we trim backslash in order to create right directories structure on B2 Cloud
    if full_name_encoded[0] == '/':
        full_name_encoded = full_name_encoded[1:]
    return full_name_encoded
    


def _request_data(url: str, headers: dict, body={}) -> dict:
    request = Request(url, data=json.dumps(
        body).encode('utf-8'), headers=headers)

    try:
        with urlopen(request) as response:
            response_data = response.read()
        response.close()
        return json.loads(response_data)
    except HTTPError as err:
        print(f'err.: {err}')

# todo: apply this method to simple usual upload


def _send_file(url: str, headers: dict, body: bytes, errorCallback: Callable[[dict, bytes], dict]) -> dict:
    request = Request(url, data=body, headers=headers)
    allowed_codes = [500, 503, 401]
    try:
        with urlopen(request) as response:
            response_data = response.read()
        response.close()
        print('<- [DONE] ')
        return json.loads(response_data)
    except HTTPError as err:
        if err.code in allowed_codes:
            print('[ HTTPError, reiastablishing connection... ]')
            errorCallback(headers, body)


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


def b2_authorize(applicationKeyId: str, applicationKeyValue: str) -> dict:
    id_and_key = f'{applicationKeyId}:{applicationKeyValue}'
    id_and_key_base64 = base64.b64encode(
        id_and_key.encode('utf-8')).decode('utf-8')
    basic_auth_string = f'Basic {id_and_key_base64}'
    headers = {'Authorization': basic_auth_string}
    b2_auth_url = 'https://api.backblazeb2.com/b2api/v2/b2_authorize_account'

    return _request_data(b2_auth_url, headers)

# request for upload by chuncks


def b2_start_large_file(apiUrl: str, authToken: str, bucketId: str, fileName: str, fileHash: str) -> dict:
    contentType = "b2/x-auto"  # Content Type of the file
    large_file_url = f'{apiUrl}/b2api/v2/b2_start_large_file'
    large_file_headers = {'Authorization': authToken}
    large_file_request_body = {'fileName': _prepare_file_name(fileName), 'contentType': contentType,
                               'bucketId': bucketId, 'fileInfo': {'large_file_sha1': fileHash}}

    return _request_data(large_file_url, large_file_headers, large_file_request_body)


def b2_finish_large_file(apiUrl: str, authToken: str, fileId: str, sha1: array) -> dict:
    finish_large_url = f'{apiUrl}/b2api/v2/b2_finish_large_file'
    finish_large_headers = {'Authorization': authToken}
    finish_large_body = {
        'fileId': fileId,
        'partSha1Array': sha1
    }
    return _request_data(finish_large_url, finish_large_headers, finish_large_body)


def b2_get_upload_url(apiUrl: str, authToken: str, bucketId: str) -> dict:
    b2_get_upload_url = f'{apiUrl}/b2api/v2/b2_get_upload_url'
    get_url_body = {'bucketId': bucketId}
    get_url_headers = {'Authorization': authToken}

    return _request_data(b2_get_upload_url, get_url_headers, get_url_body)


def b2_get_upload_part_url(apiUrl: str, authToken: str, fileId: str) -> dict:
    part_file_url = f'{apiUrl}/b2api/v2/b2_get_upload_part_url'
    part_file_headers = {'Authorization': authToken}
    part_file_request_body = {'fileId': fileId}

    return _request_data(part_file_url, part_file_headers, part_file_request_body)


def b2_upload_part(apiUrlPart: str, authTokenPart: str, fileName: str, fileSize: int, fileId: str) -> list:
    global apiUrl, authToken
    chunk_size = 536870912  # ~ 500 MiB
    total_bytes_sent = 0
    part_no = 1
    part_sha1_array = []
    part_size = chunk_size
    parts_deploy_status = []

    def _retry_upload(headers: dict, chunk: bytes) -> dict:
        uploadLargeFileSettings = b2_get_upload_part_url(
            apiUrl, authToken, fileId)

        uploadPartUrl = uploadLargeFileSettings['uploadUrl']
        uploadPartToken = uploadLargeFileSettings['authorizationToken']

        headers['Authorization'] = uploadPartToken
        return _send_file(uploadPartUrl, headers, chunk, _retry_upload)

    print(f'[ Upload in progress ]: {fileName} total file size : {fileSize}')
    with open(fileName, 'br') as file:
        while chunk := file.read(part_size):
            if(total_bytes_sent < fileSize):
                residue = fileSize - total_bytes_sent
                if(residue < chunk_size):
                    part_size = residue
                print(
                    f'[PARTIAL UPLOAD] chunk # {part_no}, size: {part_size}  in progress', end='...', flush=True)
                hash = hashlib.sha1(chunk).hexdigest()
                part_sha1_array.append(hash)

                headers = {
                    'Authorization': authTokenPart,
                    'X-Bz-Part-Number': part_no,
                    'Content-Length': part_size,
                    'X-Bz-Content-Sha1': hash
                }

                deploy_status = _send_file(
                    apiUrlPart, headers, chunk, _retry_upload)
                parts_deploy_status.append(deploy_status)
                total_bytes_sent = total_bytes_sent + part_size
                print(f'<- total bytes sent: {total_bytes_sent} - [DONE]')
                part_no += 1

    return {'deploy_status': parts_deploy_status, 'sha1': part_sha1_array}


def b2_upload_file_callback(filePathName: str) -> None:
    global uploadUrl, authTokenUpload, bucketId
    content_type = 'b2/x-auto'

    def _retry_upload(headers: dict, body: bytes) -> dict:
        global uploadUrl, authTokenUpload, bucketId
        uploadSettings = b2_get_upload_url(apiUrl, authToken, bucketId)
        uploadUrl = uploadSettings['uploadUrl']
        authTokenUpload = uploadSettings['authorizationToken']

        headers['Authorization'] = authTokenUpload
        return _send_file(uploadUrl, headers, body, _retry_upload)

    print(f'[ Upload in progress ]: {filePathName}', end='...', flush=True)
    with open(filePathName, 'br') as file:
        file_data = file.read()
    file.close()

    file_hash = hashlib.sha1(file_data).hexdigest()

    headers = {
        'Authorization': authTokenUpload,
        'X-Bz-File-Name': _prepare_file_name(filePathName),
        'Content-Type': content_type,
        'X-Bz-Content-Sha1': file_hash
    }

    _send_file(uploadUrl, headers, file_data, _retry_upload)


# make b2_upload_large_file_callback
def b2_upload_large_file_callback(filePathName: str, fileSize: int) -> None:
    global authToken, bucketId, apiUrl
    with open(filePathName, 'br') as file:
        hash = hashlib.sha1()
        while chunk := file.read(131072):
            hash.update(chunk)

    fileHash = hash.hexdigest()

    startLargeFileSettings = b2_start_large_file(
        apiUrl, authToken, bucketId, filePathName, fileHash)

    fileId = startLargeFileSettings['fileId']

    uploadLargeFileSettings = b2_get_upload_part_url(apiUrl, authToken, fileId)

    uploadPartUrl = uploadLargeFileSettings['uploadUrl']
    uploadPartToken = uploadLargeFileSettings['authorizationToken']

    fileInfo = b2_upload_part(
        uploadPartUrl, uploadPartToken, filePathName, fileSize, fileId)
    sha1Array = fileInfo['sha1']

    uploadStatus = b2_finish_large_file(apiUrl, authToken, fileId, sha1Array)
    print(f'[ UPLOAD DONE ]: for {filePathName}')
    print(uploadStatus)


def applyForFile(filesPath: str, small_file_callback: Callable[[str], None], huge_file_callback: Callable[[str], None]) -> None:
    excludes = ['.DS_Store', '.Trashes', '.fseventsd',
                '.Spotlight-V100', 'desktop.ini', 'Desktop.ini']
    size_delimeter = 2147483647  # ~ 2GiB maximum file size restriction

    for root, directories, files in os.walk(filesPath):
        for name in files:
            if name not in excludes:
                full_name = os.path.join(root, name)
                fileSize = os.path.getsize(full_name)
                if fileSize < size_delimeter:
                    small_file_callback(full_name)
                else:
                    huge_file_callback(full_name, fileSize)


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
    applyForFile(directory, b2_upload_file_callback,
                 b2_upload_large_file_callback)

    print('[ All files were successfully uploaded ]!')


if __name__ == "__main__":
    main()
