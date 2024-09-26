from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'is_superuser']
        read_only_fields = ['is_superuser']

class AddresSerializer(serializers.ModelSerializer):
    class Meta:
        model = Addres
        fields = "__all__"

class CitySerializer(serializers.ModelSerializer):
    class Meta:
        model = City
        fields = "__all__"

class ProductTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductType
        fields = "__all__"

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['id', 'product_name', 'product_detail', 'product_type', 'product_price', 'discount_price', 'in_stock', 'thumbnail']

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.thumbnail and instance.thumbnail.url:
            relative_path = instance.thumbnail.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['thumbnail'] = relative_path
        return representation

class ProductMediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductMedia
        fields = ['product', 'media']

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.media and instance.media.url:
            relative_path = instance.media.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['media'] = relative_path
        return representation

class DesignTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = DesignType
        fields = "__all__"

class ShirtStyleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShirtStyle
        fields = "__all__"

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.image and instance.image.url:
            relative_path = instance.image.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['image'] = relative_path
        return representation

class DesignSerializer(serializers.ModelSerializer):
    class Meta:
        model = Design
        fields = ['id', 'design_name', 'design_type', 'design_detail', 'design_price', 'discount_price', 'image']

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.image and instance.image.url:
            relative_path = instance.image.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['image'] = relative_path
        return representation

class CartSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCart
        fields = ['id', 'product', 'quantity', 'size']

class UserDesignCartSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDesignCart
        fields = "__all__"

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.design.image and instance.design.image.url:
            relative_path = instance.design.image.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['design_image'] = relative_path
        if instance.shirt_style.image and instance.shirt_style.image.url:
            relative_path = instance.shirt_style.image.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['shirt_style_image'] = relative_path
        return representation

class UserCustomCartSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCustomCart
        fields = "__all__"

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.image and instance.image.url:
            relative_path = instance.image.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['image'] = relative_path
        return representation

class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['id', 'user', 'paymenttype', 'order_date', 'shipping_addres', 'totalPrice']

class OrderedProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderedProduct
        fields = "__all__"

class OrderedDesignSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderedDesign
        fields = "__all__"

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.design.image and instance.design.image.url:
            relative_path = instance.design.image.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['design_image'] = relative_path
        if instance.shirt_style.image and instance.shirt_style.image.url:
            relative_path = instance.shirt_style.image.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['shirt_style_image'] = relative_path
        return representation

class OrderedCustomSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderedCustom
        fields = "__all__"

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.image and instance.image.url:
            relative_path = instance.image.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/")
            representation['image'] = relative_path
        return representation

class PromoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PromoCodes
        fields = "__all__"
