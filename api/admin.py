from django.contrib import admin
from django.apps import apps
from api.models import User

# Get all models from your app
app = apps.get_app_config('api')

# Register each model
for model_name, model in app.models.items():
    admin.site.register(model)