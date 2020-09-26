# Python script for backup any files to B2 Cloud Service
 
Script with command line interface to backup all files in a given folder to B2 Cloud storage.
 
>Why B2 Cloud Storage?
 
Its price is about four times cheaper than S3 CLoud Storage. It has a bit lower level of possibilities in comparison with S3, but more than enough to store files and to be used as backup storage.
 
[Prices comparing table](https://www.backblaze.com/b2/cloud-storage-pricing.html)
## Prerequisites
You need to be a registered user in B2 cloud service itself and to create a "bucket" for your data in your admin panel.
 
Also you need to get your **"Key ID"** and **"Application Key"** in order to be able to authenticate to your bucket on B2 cloud service.
 
## Usage:
 
It is a shell script with given path and **two** required parameters:
 
```bash
python3 b2_backup.py -k <KEY_ID> -a <APP_KEY> <PATH_TO_FILES>
```
**where:**
* `<PATH_TO_FILES>` - relative to script folder or absolute path for directory you want to backup to B2 Cloud storage.
* `<APP_KEY>` and `<KEY_ID>` - access keys which you would receive on "App Keys" tab in your user area of B2 Cloud service. Script needs it for authentication purposes.