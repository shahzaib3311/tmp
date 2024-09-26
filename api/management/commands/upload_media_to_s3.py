import os
import boto3
from django.core.management.base import BaseCommand
from django.conf import settings

class Command(BaseCommand):
    help = 'Upload local media files to S3'

    def handle(self, *args, **options):
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ['BUCKETEER_AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['BUCKETEER_AWS_SECRET_ACCESS_KEY'],
            region_name=os.environ.get('BUCKETEER_AWS_REGION', 'us-east-1')
        )
        bucket_name = os.environ['BUCKETEER_BUCKET_NAME']

        local_media_root = settings.MEDIA_ROOT

        for root, dirs, files in os.walk(local_media_root):
            for file in files:
                local_path = os.path.join(root, file)
                relative_path = os.path.relpath(local_path, local_media_root)
                s3_path = f'media/{relative_path}'
                
                self.stdout.write(f'Uploading {local_path} to s3://{bucket_name}/{s3_path}')
                
                try:
                    s3.upload_file(local_path, bucket_name, s3_path)
                    self.stdout.write(self.style.SUCCESS(f'Successfully uploaded {relative_path}'))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'Error uploading {relative_path}: {e}'))
