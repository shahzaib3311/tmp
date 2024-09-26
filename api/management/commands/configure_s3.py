from django.core.management.base import BaseCommand
import boto3
import os
import json

class Command(BaseCommand):
    help = 'Configure S3 bucket with the necessary policy and CORS settings'

    def handle(self, *args, **options):
        aws_access_key_id = os.environ['BUCKETEER_AWS_ACCESS_KEY_ID']
        aws_secret_access_key = os.environ['BUCKETEER_AWS_SECRET_ACCESS_KEY']
        bucket_name = os.environ['BUCKETEER_BUCKET_NAME']
        region_name = os.environ.get('BUCKETEER_AWS_REGION', 'us-east-1')

        # Initialize S3 client
        s3 = boto3.client(
            's3',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name
        )

        # Set bucket policy
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*"
                }
            ]
        }

        try:
            s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))
            self.stdout.write(self.style.SUCCESS('Successfully set bucket policy'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error setting bucket policy: {e}'))

        # Set CORS configuration
        cors_configuration = {
            'CORSRules': [
                {
                    'AllowedHeaders': ['*'],
                    'AllowedMethods': ['GET', 'POST', 'PUT'],
                    'AllowedOrigins': ['*'],
                    'ExposeHeaders': ['ETag'],
                    'MaxAgeSeconds': 3000
                }
            ]
        }

        try:
            s3.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_configuration)
            self.stdout.write(self.style.SUCCESS('Successfully set CORS configuration'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error setting CORS configuration: {e}'))
