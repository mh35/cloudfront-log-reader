# CloudFront log reader Python library

This is the library which reads Amazon CloudFront log files.

## Example

### Read local single file

```python
from cloudfront_log_reader import CloudFrontLogReader

with CloudFrontLogReader('filename.log') as log_file:
    for line in log_file:
        print(log_file.strftime('%Y-%m-%d %H:%M:%S'))
```

### Read single log object which stores on Amazon S3 bucket

```python
from cloudfront_log_reader import CloudFrontLogReader

with CloudFrontLogReader('s3://bucket_name/log_obj.log', boto3_args={
    'profile_name': 'cli_profile'
}) as log_file:
    for line in log_file:
        print(log_file.strftime('%Y-%m-%d %H:%M:%S'))
```

### Read multiple log objects which stores on Amazon S3 bucket

```python
from boto3.session import Session
from cloudfront_log_reader import CloudFrontLogReader

sess = Session(profile_name='cli_profile')
bucket = sess.resource('s3').Bucket('bucket_name')
creds = sess.get_credentials()
for obj in bucket.objects.filter(Prefix="prefix/").all():
    obj_key = obj.key
    obj_url = 's3://bucket_name/' + obj_key
    with CloudFrontLogReader(obj_url, boto3_args={
        'aws_access_key_id': creds.access_key,
        'aws_secret_access_key': creds.secret_key,
        'aws_session_token': creds.token,
        'region_name': sess.region_name
    }) as log_file:
        for line in log_file:
            print(log_file.strftime('%Y-%m-%d %H:%M:%S'))
```
