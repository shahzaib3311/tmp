"""
URL configuration for dripsaint_back project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include, re_path
from django.views.static import serve
from django.http import HttpResponse, HttpResponseNotFound
import boto3
import os

def serve_s3_file(request, path):
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.environ['BUCKETEER_AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=os.environ['BUCKETEER_AWS_SECRET_ACCESS_KEY'],
        region_name=os.environ.get('BUCKETEER_AWS_REGION', 'us-east-1')
    )
    bucket_name = os.environ['BUCKETEER_BUCKET_NAME']

    try:
        file_obj = s3.get_object(Bucket=bucket_name, Key=path)
        response = HttpResponse(file_obj['Body'].read(), content_type=file_obj['ContentType'])
        response['Content-Disposition'] = f'attachment; filename={os.path.basename(path)}'
        return response
    except s3.exceptions.NoSuchKey:
        return HttpResponseNotFound('File not found')


urlpatterns = [
   path("admin/", admin.site.urls),
   path("api/", include("api.urls")),
   path('media/<path:path>/', serve_s3_file, name='serve_s3_file'),
]
