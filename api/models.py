from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
import datetime

class UserManager(BaseUserManager):
    def create_user(self, email, first_name,last_name, password=None, is_active=True):
        if not email:
            raise ValueError("User must have an email")
        if not password:
            raise ValueError("User must have a password")
        if not first_name and not last_name:
            raise ValueError("User must have a full name")

        user = self.model(
            email=self.normalize_email(email)
        )
        user.first_name = first_name
        user.last_name = last_name
        user.set_password(password)  # change password to hash
        user.admin = False
        user.staff = False
        user.active = is_active
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name,last_name, password=None, **extra_fields):
        if not email:
            raise ValueError("User must have an email")
        if not password:
            raise ValueError("User must have a password")
        if not first_name and not last_name:
            raise ValueError("User must have a full name")

        user = self.model(
            email=self.normalize_email(email)
        )
        user.first_name = first_name
        user.last_name = last_name
        user.set_password(password)
        user.is_superuser = True
        user.is_staff = True
        user.active = True
        user.save(using=self._db)
        return user
class User(AbstractUser):
    # Add any additional fields you want in your custom user model
    username = None
    email = models.EmailField(unique=True, null=False, blank=False)
    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'
    REGISTRATION_CHOICES = [
        ('email', 'Email'),
        ('google', 'Google'),
    ]
    phone_number = models.CharField(max_length=20, blank=True)
    REQUIRED_FIELDS = ["first_name", "last_name"]
    registration_method = models.CharField(
        max_length=10,
        choices=REGISTRATION_CHOICES,
        default='email'
    )
    objects = UserManager()

    def __str__(self):
       return self.username

class City(models.Model):
    city = models.CharField(max_length=20, null=False)
    shipping_charges = models.FloatField(default=0.0, null=False)
    is_active = models.BooleanField(default=True)

class Addres(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    address = models.CharField(max_length=255,)
    city = models.ForeignKey(City, on_delete=models.PROTECT)
    postal_code = models.IntegerField()
    is_active = models.BooleanField(default=True)

class ProductType(models.Model):
    product_type = models.CharField(max_length=50)

class Product(models.Model):
    product_name=models.CharField(max_length=50, null=False)
    product_detail=models.TextField()
    product_type = models.ForeignKey(ProductType, on_delete=models.CASCADE)
    product_price=models.FloatField(default=0,null=False)
    discount_price = models.FloatField(default=None ,null=True)
    thumbnail=models.ImageField(default='defaults/product_def.jpg', upload_to='product/media/')
    in_stock=models.IntegerField(default=0)


class ProductMedia(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    media = models.FileField(upload_to='product/media/')

class DesignType(models.Model):
    design_type = models.CharField(max_length=50)
class Design(models.Model):
    design_name=models.CharField(max_length=50, null=False)
    design_type = models.ForeignKey(DesignType, on_delete=models.CASCADE)
    design_detail=models.TextField()
    design_price=models.FloatField(default=0,null=False)
    discount_price = models.FloatField(default=None ,null=True)
    image=models.ImageField(default='defaults/product_def.jpg', upload_to='designs/premade/')

class ShirtStyle(models.Model):
    style = models.CharField(max_length=30)
    image = models.ImageField(upload_to='designs/shirt_styles/')
    available = models.BooleanField(default=True)

def get_default_expiry():
    return datetime.date.today() + datetime.timedelta(days=20)

class PromoCodes(models.Model):
    code = models.CharField(max_length=6, null=False, unique=True)
    discount = models.FloatField(default=0, null=False)
    discount_type = models.CharField(
        max_length=10, choices=[('percentage', 'Percentage'), ('value', 'Value')], default='percentage')
    uses = models.IntegerField(default=1)
    starting = models.DateField(default=datetime.date.today)
    expiry = models.DateField(default=get_default_expiry)


class UserPromoHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    promo = models.ForeignKey(PromoCodes, on_delete=models.CASCADE)
class UserCart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    size = models.CharField(max_length=10)

class UserDesignCart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    design = models.ForeignKey(Design, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    shirt_style = models.ForeignKey(ShirtStyle, on_delete=models.CASCADE)
    size = models.CharField(max_length=10)

class UserCustomCart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    shirt_style = models.ForeignKey(ShirtStyle, on_delete=models.CASCADE)
    size = models.CharField(max_length=10)
    image = models.FileField(upload_to='custom/images/')
    url = models.URLField(null=True)



class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    paymenttypes = [
        ('cod', 'COD'),
        ('card', 'Card')
    ]
    paymenttype = models.CharField(
        max_length=10,
        choices=paymenttypes,
        default='cod'
    )
    shipping_addres=models.ForeignKey(Addres, on_delete=models.DO_NOTHING,  null=False)
    totalPrice = models.FloatField(default=0.0, null=False)
    order_date = models.DateTimeField(auto_now_add=True)
    payment_id = models.CharField(max_length=100, null=True)
    promo_used = models.ForeignKey(PromoCodes, on_delete=models.SET_NULL, null=True)

class OrderedProduct(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    size = models.CharField(max_length=10)
    quantity = models.IntegerField(default=1)

class OrderedDesign(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    design = models.ForeignKey(Design, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    shirt_style = models.ForeignKey(ShirtStyle, on_delete=models.CASCADE)
    size = models.CharField(max_length=10)
class OrderedCustom(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    shirt_style = models.ForeignKey(ShirtStyle, on_delete=models.CASCADE)
    size = models.CharField(max_length=10)
    image = models.ImageField(upload_to='custom/images/')
    url = models.URLField(null=True)

class Transaction(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    transaction_id = models.CharField(max_length=100)
