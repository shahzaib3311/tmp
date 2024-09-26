
from urllib.parse import urlencode
import jwt, datetime
from rest_framework import serializers
from rest_framework.views import APIView
from django.conf import settings
from django.shortcuts import redirect
from rest_framework.response import Response
from .mixins import PublicApiMixin, ApiErrorsMixin
from .utils import google_get_access_token, google_get_user_info, generate_tokens_for_user
from rest_framework import status
from .serializers import UserSerializer
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.mail import send_mail
from django.conf import settings
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from rest_framework import generics, permissions
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from.models import *
from.serializers import *
from django.contrib.auth.tokens import default_token_generator
from io import BytesIO
from PIL import Image
import base64
from .code import *
from django.core.files.base import File
from urllib.request import urlopen
from django.core.files.temp import NamedTemporaryFile
import tempfile 
import stripe
import json
from django.shortcuts import get_object_or_404
from .tasks import process_custom_product
from django.utils.html import strip_tags

class LoginApi(PublicApiMixin, ApiErrorsMixin, APIView):
    class InputSerializer(serializers.Serializer):
        code = serializers.CharField(required=False)
        error = serializers.CharField(required=False)
        email = serializers.EmailField(required=False)
        password = serializers.CharField(required=False)
        first_name = serializers.CharField(required=False)
        last_name = serializers.CharField(required=False)
        phone_number = serializers.CharField(required=False)

    def get(self, request, *args, **kwargs):
        input_serializer = self.InputSerializer(data=request.GET)
        input_serializer.is_valid(raise_exception=True)

        validated_data = input_serializer.validated_data

        code = validated_data.get('code')
        error = validated_data.get('error')

        login_url = f'{settings.BASE_FRONTEND_URL}'
        if error or not code:
            params = urlencode({'error': error})
            return redirect(f'{login_url}?{params}')
        redirect_uri = f'{settings.BASE_FRONTEND_URL}/google'
        print("redirected")
        access_token = google_get_access_token(code=code, 
                                               redirect_uri=redirect_uri)
        user_data = google_get_user_info(access_token=access_token)
        try:
            user = User.objects.get(email=user_data['email'])
            access_token, refresh_token = generate_tokens_for_user(user)
            response_data = {
                'user': UserSerializer(user).data,
                'access_token': str(access_token),
                'refresh_token': str(refresh_token)
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            # username = user_data['email'].split('@')[0]
            first_name = user_data.get('given_name', '')
            last_name = user_data.get('family_name', '')

            user = User.objects.create(
                email=user_data['email'],
                first_name=first_name,
                last_name=last_name,
                registration_method='google'
            )
            access_token, refresh_token = generate_tokens_for_user(user)
            response_data = {
                'user': UserSerializer(user).data,
                'access_token': str(access_token),
                'refresh_token': str(refresh_token)
            }
            payload = {"user": user.id,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            response = Response()
            response.set_cookie('jwt', token)
            response.data = {"message": "Login Successful"}
            response.status_code = 200
            return response

    def post(self, request, *args, **kwargs):
        input_serializer = self.InputSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)

        validated_data = input_serializer.validated_data
        print(validated_data)
        email = validated_data.get('email')
        password = validated_data.get('password')
        first_name = validated_data.get('first_name')
        last_name = validated_data.get('last_name')
        phone_number = validated_data.get('phone_number')
        if email and password and first_name and last_name and phone_number:  # Registration
            try:
                validate_email(email)
            except ValidationError:
                return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(email=email).exists():
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.create(
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone_number = phone_number
            )
            user.set_password(password)
            #user.active = False
            

            # Send verification email
            #self.send_verification_email(user)
            user.save()
            payload = {"user": user.id,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            response = Response()
            response.set_cookie(
                                            'jwt', 
                                            token, 
                                            httponly=True, 
                                            secure=True, 
                                            samesite='None'
                                        )
            response.set_cookie(
                                            'jwt', 
                                            token, 
                                            httponly=True, 
                                            secure=True, 
                                            samesite='lax'
                                        )
            response.data = {"message": "Login Successful"}
            response.status_code = 200
            return response
        elif email and password:  # Login
            user = authenticate(email=email, password=password)
            if user is not None:
                access_token, refresh_token = generate_tokens_for_user(user)
                response_data = {
                    'user': UserSerializer(user).data,
                    'access_token': str(access_token),
                    'refresh_token': str(refresh_token)
                }
                payload = {"user": user.id,
                    "exp": datetime.datetime.now() + datetime.timedelta(days=365)}
                token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
                response = Response()
                response.set_cookie(
                                                    'jwt', 
                                                    token, 
                                                    httponly=True, 
                                                    secure=True, 
                                                    samesite='None'
                                                )
                response.set_cookie(
                                            'jwt', 
                                            token, 
                                            httponly=True, 
                                            secure=True, 
                                            samesite='lax'
                                        )
                response.data = {"message": "Login Successful", "jwt": token}
                response.status_code = 200
                return response
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error': 'Invalid data provided'}, status=status.HTTP_400_BAD_REQUEST)

    def send_verification_email(self, user):
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        base_url = "http://www.dripsaint.com"
        verification_url = f"{base_url}/verify/{uidb64}/{token}"

        subject = 'Verify your email'
        message = f"Hi {user.first_name},\n\nPlease click on the following link to verify your email:\n\n{verification_url}\n\nThanks!"
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

class VerifyEmail(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.active = True
            user.save()
            return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid verification link'}, status=status.HTTP_400_BAD_REQUEST)
class WhoAmI(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        user = UserSerializer(user).data
        return Response({'message': "Found User", "user": user})
class Logout(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Already Loged out"}, status=401)
        response = Response({'message': "Logged Out"})
        response.delete_cookie('jwt')
        return response
class CityView(APIView):
    def get(self, request):
        cities = City.objects.filter(is_active=True)
        serialized = CitySerializer(cities, many=True)
        return Response({'message':"We are Shipping in these Cities",'cities':serialized.data})
    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user.is_superuser:
            return Response({"message": str(user.is_superuser)+": Dont have Permission to Add Cities"}, status=401)
        serializer = CitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':"City Added",'City':serializer.data})
        else:
            return Response({'message':"City not Added"}, status=500)
class AddressView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        adresses = Addres.objects.filter(user=user,is_active=True)
        serialized = AddresSerializer(adresses, many=True).data
        for i in serialized:
            i["city"] = CitySerializer(City.objects.get(pk=i["city"])).data
        return Response({'message':"Your Saved Addesses",'addresses':serialized})
    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        request.data['user'] = user.id
        serializer = AddresSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':"Address Added",'adress':serializer.data})
        else:
            return Response({'message':"Address not Added"}, status=500)
class ProductTypeView(APIView):
    def get(self, request):
        product_types = ProductType.objects.all()
        product_types = ProductTypeSerializer(product_types, many=True)
        return Response({'message':"Product Types",'product_types':product_types.data})
    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user.is_superuser:
            return Response({"message": str(user.is_superuser)+": Dont have Permission"}, status=401)
        product_type = ProductTypeSerializer(data=request.data)
        if product_type.is_valid():
            product_type.save()
            return Response({'message':"Product Type Added",'product_type':product_type.data})
        else:
            return Response({"message": "Product Type not added"}, status=500)
class GetProducts(APIView):
    def get(self, request):
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response({'message':"Found these Products",'products':serializer.data})
class AddProducts(APIView):

    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user.is_superuser:
            return Response({"message": str(user.is_superuser)+": Dont have Permission to Add products"}, status=401)
        #request.data['product_type'] = ProductType.objects.get(pk=request.data['product_type'])
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':"Product Added",'product':serializer.data})
        else:
            return Response({'message':"Product not Added"}, status=500)
        
class ChangeProduct(APIView):

    def post(self, request, id):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user.is_superuser:
            return Response({"message":"Un authorized"}, status=401)

        
        product = Product.objects.get(pk=id)

        if 'product_name' in request.data:
            product.product_name= request.data['product_name']
            
        if 'product_detail' in request.data:
            product.product_detail= request.data['product_detail']
            
        if 'price' in request.data: 
            product.price= request.data['price']
            
        if 'product_price' in request.data:
            product.product_price= request.data['product_price']
            
        if 'discount_price' in request.data:
            product.discount_price= request.data['discount_price']
            
        if 'thumbnail' in request.data:
            product.thumbnail= request.data['thumbnail']
            
        if 'in_stock' in request.data:
            product.in_stock= request.data['in_stock']
            
        product.save()   
        serialized=ProductSerializer(product)
        return Response({'message':"product udated","product":serialized.data},status=200)

class ShirtStyleView(APIView):
    def get(self, request):
        shirt_styles = ShirtStyle.objects.all()
        shirt_styles = ShirtStyleSerializer(shirt_styles, many=True)
        return Response({'message': "Shirt Styles", 'shirt_styles': shirt_styles.data})

    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(pk=payload['user'])
        except jwt.ExpiredSignatureError:
            return Response({"message": "Unauthenticated - Token Expired"}, status=401)
        except jwt.InvalidTokenError:
            return Response({"message": "Unauthenticated - Invalid Token"}, status=401)
        except User.DoesNotExist:
            return Response({"message": "User does not exist"}, status=401)

        if not user.is_superuser:
            return Response({"message": str(user.is_superuser) + ": Don't have Permission"}, status=401)

        shirt_style = ShirtStyleSerializer(data=request.data)
        if shirt_style.is_valid():
            shirt_style.save()
            return Response({'message': "Shirt Style Added", 'shirt_style': shirt_style.data})
        else:
            return Response({"message": "Shirt Style not added"}, status=500)
class DesignTypeView(APIView):
    def get(self, request):
        design_types = DesignType.objects.all()
        design_types = DesignTypeSerializer(design_types, many=True)
        return Response({'message': "Design Types", 'design_types': design_types.data})

    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(pk=payload['user'])
        except jwt.ExpiredSignatureError:
            return Response({"message": "Unauthenticated - Token Expired"}, status=401)
        except jwt.InvalidTokenError:
            return Response({"message": "Unauthenticated - Invalid Token"}, status=401)
        except User.DoesNotExist:
            return Response({"message": "User does not exist"}, status=401)

        if not user.is_superuser:
            return Response({"message": str(user.is_superuser) + ": Don't have Permission"}, status=401)

        design_type = DesignTypeSerializer(data=request.data)
        if design_type.is_valid():
            design_type.save()
            return Response({'message': "Design Type Added", 'design_type': design_type.data})
        else:
            return Response({"message": "Design Type not added"}, status=500)
class GetDesigns(APIView):
    def get(self, request):
        designs = Design.objects.all()
        serializer = DesignSerializer(designs, many=True)
        return Response({'message':"Found these Designs",'designs':serializer.data})


class AddDesigns(APIView):

    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user.is_superuser:
            return Response({"message": str(user.is_superuser)+": Dont have Permission to Add products"}, status=401)
        #request.data['product_type'] = ProductType.objects.get(pk=request.data['product_type'])
        print(request.data)
        serializer = DesignSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':"Design Added",'design':serializer.data})
        else:
            print("serializer invalid")
            return Response({'message':"Design not Added"}, status=500)

class GetCustomProduct(APIView):
    def post(self, request):
        custom = request.data['custom']
        design_id = request.data.get('id')
        custom_img = request.data.get('custom_img')
        task = process_custom_product.delay(custom, design_id, custom_img)
        
        if custom == "no":
            design = Design.objects.get(pk=design_id)
            serializers = DesignSerializer(design)
            return Response({'task_id': task.id, "design": serializers.data}, status=status.HTTP_202_ACCEPTED)
        
        return Response({'task_id': task.id}, status=status.HTTP_202_ACCEPTED)

class TaskStatus(APIView):
    def get(self, request, task_id):
        task = process_custom_product.AsyncResult(task_id)
        if task.state == 'PENDING':
            response = {
                'state': task.state,
                'status': 'Pending...'
            }
        elif task.state != 'FAILURE':
            response = {
                'state': task.state,
                'result': task.result,
            }
        else:
            response = {
                'state': task.state,
                'result': str(task.info),  # this is the exception raised
            }
        return Response(response)
'''
class GetCustomProduct(APIView):
    def post(self, request):
        designSerialized = None
        if request.data['custom'] == "no":
            design = Design.objects.get(pk=int(request.data['id']))
            designSerialized = DesignSerializer(design).data
            custom_image_url = "https://api.dripsaint.com"+(design.image.url)
        else:
            custom_image_url = request.data['custom_img']
        try:
            output_img = replace_shirt_print(custom_image_url)
            print("replace function working")
            # Convert the image to a format that can be sent in the response
            _, buffer = cv2.imencode('.jpg', output_img)
            image_bytes = buffer.tobytes()
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')
            print("image encoding working")
            return Response({'image': image_base64, 'design': designSerialized}, status=status.HTTP_200_OK)
        except ValueError as e:
            print("hello")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
'''
class GetProductDetails(APIView):
    def get(self, request, id):
        product = Product.objects.get(pk=id)
        product_serialized = ProductSerializer(product)
        
        if product:
            try:
                media = ProductMedia.objects.filter(product=product)
                images_serializer = ProductMediaSerializer(media, many=True)
                return Response({'message':"Media Uploaded",'Product':product_serialized.data,'Images':images_serializer.data})
            except:
                return Response({'message':"Media not Added"}, status=500)
        else:
            return Response({'message':"Product Not Found"}, status=404)
class UploadProductImage(APIView):  
    def post(self, request, id): 
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user.is_superuser:
            return Response({"message": str(user.is_superuser)+": Dont have Permission to Add products"}, status=401)
        product = Product.objects.get(pk=id)
        if product:
            request.data['product'] = product
            try:
                media = ProductMedia.objects.create(product=product, media=request.data['media'])
                media.save()
                serializer = ProductMediaSerializer(media)
                return Response({'message':"Media Uploaded",'Image':serializer.data})
            except:
                return Response({'message':"Media not Added"}, status=500)
        else:
            return Response({'message':"Product Not Found"}, status=404)

class ProductDiscount(APIView):
    def post(self, request, id):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user.is_superuser:
            return Response({"message": str(user.is_superuser)+": Dont have Permission to Add Discount"}, status=401)
        product = Product.objects.get(pk=id)
        if not product:
            return Response({"message": "Invalid Product ID"}, status=404)
        if request.data['discount'] == True:
            product.discount_price = request.data['discount_price']
        else:
            product.discount_price = None
        product.save()
        return Response({"message": "PRoduct Discount Updated", "product" : ProductSerializer(product).data})

class Cart(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user:
            return Response({"message": "User not found"}, status=401)
        cart = UserCart.objects.filter(user=user)
        serializer = CartSerializer(cart, many=True).data
        for i in serializer:
            i['product'] = ProductSerializer(Product.objects.get(pk=i['product'])).data
        return Response({'message':"here is your cart",'cart':serializer})
    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        
        user = User.objects.get(pk=payload['user'])
        if not user:
            return Response({"message": "User not found"}, status=401)
        product = Product.objects.get(pk=request.data["product"])
        if not product:
            return Response({"message": "Product not found"}, status=401)
        # apply this try thingy everywhere there is .get
        try:
            carts = UserCart.objects.filter(user=user, product=product)
        except:
            carts = None
        for cart in carts:
            if cart.size==request.data['size']:
                cart.quantity += request.data['quantity']
                cart.save()
                return Response({'message':"Product Added to cart"})
        request.data['product'] = product
        request.data['user'] = user
        
        try:
            cart = UserCart.objects.create(user=user, product=product, quantity=request.data['quantity'], size=request.data['size'])
            cart.save()
            return Response({'message':"Product Added to cart"})
        except:
            return Response({"message":"Failed to add Product"}, status=401)
class UserDesignCartView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(pk=payload['user'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return Response({"message": "Invalid or expired token"}, status=401)
        
        cart = UserDesignCart.objects.filter(user=user)
        serializer = UserDesignCartSerializer(cart, many=True).data
        
        for item in serializer:
            item['design'] = DesignSerializer(Design.objects.get(pk=item['design'])).data
            item['shirt_style'] = ShirtStyleSerializer(ShirtStyle.objects.get(pk=item['shirt_style'])).data
        
        return Response({'message': "Here is your design cart", 'cart': serializer})

    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(pk=payload['user'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return Response({"message": "Invalid or expired token"}, status=401)
        
        try:
            design = Design.objects.get(pk=request.data["design"])
            shirt_style = ShirtStyle.objects.get(pk=request.data["shirt_style"])
        except (Design.DoesNotExist, ShirtStyle.DoesNotExist):
            return Response({"message": "Design or Shirt Style not found"}, status=404)

        
        try:
            print("hello")
            carts = UserDesignCart.objects.filter(user=user, design=design, shirt_style=shirt_style)
        except:
            print("eror")
            carts = None
        if carts:
            for cart in carts:
                if cart.size == request.data['size']:
                    cart.quantity += request.data['quantity']
                    cart.save()
                    return Response({'message': "Design added to cart"}, status=200) 
        new_cart_item = UserDesignCart.objects.create(
            user=user,
            design=design,
            quantity=request.data['quantity'],
            shirt_style=shirt_style,
            size=request.data['size']
        )
        new_cart_item.save()
        return Response({'message': "Design added to cart"}, status=200)
            

class UserCustomCartView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(pk=payload['user'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return Response({"message": "Invalid or expired token"}, status=401)
        
        cart = UserCustomCart.objects.filter(user=user)
        serializer = UserCustomCartSerializer(cart, many=True).data
        
        for item in serializer:
            item['shirt_style'] = ShirtStyleSerializer(ShirtStyle.objects.get(pk=item['shirt_style'])).data
            item['design'] = {
                "design_name": "AI Generated Design",
                "design_price": 6600,
                "discount_price": 3500,
            }
        
        return Response({'message': "Here is your Custom Product", 'cart': serializer})

    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(pk=payload['user'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return Response({"message": "Invalid or expired token"}, status=401)
        
        try:
            shirt_style = ShirtStyle.objects.get(pk=request.data["shirt_style"])
        except ShirtStyle.DoesNotExist:
            return Response({"message": "Shirt Style not found"}, status=404)

        image = request.data.get('image')
        if request.FILES.get('image'):  # Handling file upload
            image = request.FILES['image']
            url = None
        elif image:  # Handling external URL
            url = image
            image = None


        try:
            new_cart_item = UserCustomCart.objects.create(
                user=user,
                quantity=request.data['quantity'],
                shirt_style=shirt_style,
                size=request.data['size'],
                image=image,
                url=url
            )
            new_cart_item.save()
            return Response({'message': "Custom Product added to cart"}, status=200)
        except Exception as e:
            return Response({"message": f"Failed to add Custom Product to cart: {str(e)}"}, status=500)

class DeleteCartItem(APIView):
    def delete(self,request, id, type):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(pk=payload['user'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return Response({"message": "Invalid or expired token"}, status=401)
        cartItem = None
        if type == "cart":
            cartItem=UserCart.objects.get(pk=id)
        elif type == "designCart":
            cartItem=UserDesignCart.objects.get(pk=id)
        elif type == "customCart":
            cartItem=UserCustomCart.objects.get(pk=id)
        if cartItem == None:
            return Response({"message": "Cart Item not found"}, status=404)
        if not(cartItem.user == user):
            return Response({"message": "Unauthorized to remove this item"}, status=401)
        cartItem.delete()
        return Response({"message": "Cart Item deleted"}, status=200)
class UpdateCartQuantity(APIView):
    def get(self, request,item,id, action):
        token = request.COOKIES.get('jwt')
        if not token:
            print("hello")
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if item == 'product':
            cart_item = UserCart.objects.get(pk=id)
        else:
            cart_item = UserDesignCart.objects.get(pk=id)
        if cart_item.user == user:

            if action == 'add':
                cart_item.quantity += 1
                cart_item.save()
                return Response({'message':"Quantity updated successfully"})
            elif action == 'minus':
                if cart_item.quantity > 1:
                    cart_item.quantity -= 1
                    cart_item.save()
                    return Response({'message':"Quantity updated successfully"})
            else:
                return Response({"message": "Invalid action"}, status=400)
        else:

            return Response({"message": "Unauthorized"}, status=401)

'''
class Checkout(APIView):
    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user:
            return Response({"message": "User not found"}, status=401)
        try:
            address = Addres.objects.get(pk=request.data['address_id'], user=user)
        except:
            return Response({"message": "Address Error Try Again"}, status=401)
        city = address.city
        if not city.is_active:
            return Response({"message": "We are currently not available in this city. Thank you"}, status=401)
        cart = UserCart.objects.filter(user=user)
        if cart:
            order = Order.objects.create(user=user, shipping_addres=address)
            try: 
                for i in cart:
                    i = CartSerializer(i).data
                    product = Product.objects.get(pk=i['product'])
                    producttoadd = OrderedProduct.objects.create(order=order, product=product, quantity=i['quantity'], custom_img=i['custom_img'], size=i['size'])
                    if product.discount_price != None:
                        order.totalPrice+=product.discount_price
                    else:
                        order.totalPrice+=product.product_price
                    producttoadd.save()
                for i in cart:
                    i.delete()
                if 'promo_code' in request.data:
                    promo = PromoCodes.objects.get(pk=request.data['promo_code'])
                    if promo:
                        if (promo.expiry < datetime.now) and (promo.uses > 0) and (not UserPromoHistory.objects.filter(user=user, promo=promo).exists()):
                            if promo.discount_type in ('percentage', 'Percentage'):
                                order.totalPrice = order.totalPrice - (order.totalPrice * promo.discount / 100)
                            else:
                                order.totalPrice = order.totalPrice - promo.discount
                        promo.uses -= 1
                    promo.save()
                    UserPromoHistory.objects.create(user=user, promo=promo).save()
                    order.promo_used = promo
                order.totalPrice+=city.shipping_charges
                order.save()
                serializedOrder = OrderSerializer(order).data
                return Response({'message':"Order has been placed", "order": serializedOrder})
            except:
                order.delete()
                return Response({'message':"Error while placing order"}, status=401)
        else:
            return Response({'message':"Empty Cart"}, status=404)
        
    def generate_invoice(self):
        pass
'''



class CreateCheckoutSession(APIView):
    def calculate_total_price(self, user_id):
        total_price = 0

        # Fetch cart items for the user
        user_cart_items = UserCart.objects.filter(user_id=user_id)
        user_design_cart_items = UserDesignCart.objects.filter(user_id=user_id)
        user_custom_cart_items = UserCustomCart.objects.filter(user_id=user_id)

        # Process UserCart items
        for item in user_cart_items:
            if item.quantity > 0:
                product_price = item.product.discount_price if item.product.discount_price not in [None, 0] else item.product.product_price
                total_price += product_price * item.quantity

        # Process UserDesignCart items
        for item in user_design_cart_items:
            if item.quantity > 0:
                design_price = item.design.discount_price if item.design.discount_price not in [None, 0] else item.design.design_price
                total_price += design_price * item.quantity

        # Process UserCustomCart items
        for item in user_custom_cart_items:
            if item.quantity > 0:
                # Assuming a fixed price for custom designs
                total_price += 3500 * item.quantity

        return total_price

    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=401)
        except jwt.DecodeError:
            return Response({"message": "Error decoding token"}, status=401)
        
        user_id = payload['user']
        user = User.objects.get(pk=user_id)
        order = None
        
        try:
            # Fetching required data
            address_id = request.data['shipping_address']
            if not address_id:
                return Response({"message": "Address ID is required"}, status=400)
            address = get_object_or_404(Addres, pk=address_id)
            shipping_charge = address.city.shipping_charges
            print("Shipping Charges:", shipping_charge)
            # Prepare line items and calculate total price
            # Example based on your cart structure
            total_price = self.calculate_total_price(user_id)
            if shipping_charge:
                total_price += shipping_charge
            order = Order.objects.create(
                user=User.objects.get(pk=user_id),
                shipping_addres=address,
                totalPrice=total_price,
                paymenttype='card'
            )
            response = requests.post(
                'https://ipg1.apps.net.pk/Ecommerce/api/Transaction/GetAccessToken',
                data={
                    'MERCHANT_ID': settings.PAYFAST_MERCHANT_ID,
                    'SECURED_KEY': settings.PAYFAST_SECURED_KEY,
                    'BASKET_ID': '',
                    'TXNAMT': ''
                }
            )
            access_token = response.json().get('ACCESS_TOKEN')
            return Response({"message": "Order created","order_id": order.pk, "total_price": total_price, "access_token": access_token}, status=200)
            
            # Get PayFast access token
            
            '''
            data = {
                    'CURRENCY_CODE': "PKR",
                    'MERCHANT_ID': settings.PAYFAST_MERCHANT_ID,
                    'MERCHANT_NAME': 'Dripsaint',
                    'TOKEN': access_token,
                    'TXNAMT': total_price,
                    'CUSTOMER_MOBILE_NO': user.phone_number,
                    'CUSTOMER_EMAIL_ADDRESS': user.email,
                    'CHECKOUT_URL': "https://api.dripsaint.com/api/confirm_transaction/",
                    'SUCCESS_URL': f"{settings.BASE_FRONTEND_URL}/checkout?success=true&order_id={order.id}",
                    'FAILURE_URL': f"{settings.BASE_FRONTEND_URL}/checkout?cancel=true&order_id={order.id}",
                    'BASKET_ID': order.id,
                    'TRAN_TYPE': 'ECOMM_PURCHASE',
                    'ORDER_DATE': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'SIGNATURE': '',  # Add the signature value here if available
                    'VERSION': 'MERCHANT_CART-0.1',
                    'TXNDESC': 'Item Purchased from Cart',
                    'PROCCODE': '00',
                    'STORE_ID': '',  # Optional Store ID
                    'Recurring_Transaction': 'true',
                    'MERCHANT_USERAGENT': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
                    'ITEMS': [
                        {
                            'SKU': 'SAMPLE-SKU-01',
                            'NAME': 'An Awesome Dress',
                            'PRICE': 150,
                            'QTY': 2
                        },
                        {
                            'SKU': 'SAMPLE-SKU-02',
                            'NAME': 'Ice Cream',
                            'PRICE': 45,
                            'QTY': 5
                        }
                    ]
                }
            print(data)
            # Initiate PayFast transaction
            transaction_response = requests.post(
                'https://ipg1.apps.net.pk/Ecommerce/api/Transaction/PostTransaction',
                data=data,
            )

            if transaction_response.status_code == 200:
                return Response({"message": "Redirecting...", "url": transaction_response.url})

            return Response({"message": "Error while checking out", "error": transaction_response.text}, status=500)
        '''
        except Exception as e:
            if order:
                order.delete()
            return Response({"message": "Error while checking out", "error": str(e)}, status=500)
class TransactionView(APIView):
    def post(self, request):
        order_id = request.data['bucket_id']
        transaction = Transaction.objects.create(order_id=Order.objects.get(pk=order_id), transaction_id=request.data['transaction_id'])
        return Response({"message": "Transaction successfull"}, status=200)

class ConfirmCheckout(APIView):
    def get(self, request, order_id):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=401)
        except jwt.DecodeError:
            return Response({"message": "Error decoding token"}, status=401)
        user = User.objects.get(pk=int(payload['user']))

        try:
            order = Order.objects.get(pk=order_id)
        except ValueError:
            return Response({"message": "Invalid order ID format"}, status=400)
        
        if order.user != user:
            return Response({"message": "Order Not Yours"}, status=status.HTTP_400_BAD_REQUEST)

        cart = UserCart.objects.filter(user=user)
        design_cart = UserDesignCart.objects.filter(user=user)
        custom_cart = UserCustomCart.objects.filter(user=user)

        if not cart.exists() and not design_cart.exists() and not custom_cart.exists():
            return Response({'message': "Order already exists"}, status=status.HTTP_200_OK)

        try:
            cart_items = []
            design_cart_items = []
            custom_cart_items = []

            for item in cart:
                OrderedProduct.objects.create(
                    order=order,
                    product=item.product,
                    quantity=item.quantity,
                    size=item.size
                )
                cart_items.append({
                    'product_name': item.product.product_name,
                    'quantity': item.quantity,
                    'size': item.size,
                    'price': item.product.discount_price,
                })
                item.delete()

            for item in design_cart:
                OrderedDesign.objects.create(
                    order=order,
                    design=item.design,
                    quantity=item.quantity,
                    shirt_style=item.shirt_style,
                    size=item.size
                )
                design_cart_items.append({
                    'design_name': item.design.design_name,
                    'quantity': item.quantity,
                    'shirt_style': item.shirt_style,
                    'size': item.size,
                    'price': item.design.discount_price
                })
                item.delete()

            for item in custom_cart:
                OrderedCustom.objects.create(
                    order=order,
                    quantity=item.quantity,
                    shirt_style=item.shirt_style,
                    size=item.size,
                    image=item.image,
                    url=item.url
                )
                custom_cart_items.append({
                    'shirt_style': item.shirt_style,
                    'quantity': item.quantity,
                    'size': item.size,
                    'price': 3500,
                    **({'url': item.url} if item.url is not None else None)
                })
                item.delete()

            order.save()
            context = {
                'customer_name': user.username,
                'order_number': order_id,
                'total_amount': order.totalPrice, 
                'cart_items': cart_items,
                'design_cart_items': design_cart_items,
                'custom_cart_items': custom_cart_items
            }

            # Render email template
            subject = 'Order Confirmation'
            html_message = render_to_string('emails/order_confirmation_1.html', context)
            plain_message = strip_tags(html_message)
            from_email = settings.EMAIL_HOST_USER
            to_email = user.email

            # Send email
            try:
                send_mail(subject, plain_message, from_email, [to_email], html_message=html_message, fail_silently=False)
            except:
                print("Email not sent")

            return Response({'message': "Order has been placed", "order": order_id}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'message': "Error while placing order", 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class CancelOrder(APIView):

    def get(self, request, order_id):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=401)
        except jwt.DecodeError:
            return Response({"message": "Error decoding token"}, status=401)
        user = User.objects.get(pk=int(payload['user']))

        try:
            order = Order.objects.get(pk=order_id)
        except ValueError:
            print("order not found")
            return Response({"message": "Invalid order ID format"}, status=400)
        
        if order.user != user:
            print("user not yours")
            return Response({"message": "Order Not Yours"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            order.delete()
            return Response({'message': "Order has been canceled"}, status=status.HTTP_200_OK)
        except Exception as e:
            print("didnt delete")
            return Response({'message': "Error while canceling order", 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class PromoView(APIView):
    def get(self,request,code):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        if not code:
            return Response({"message": "no promo"}, status=401)
        try:
            promo = PromoCodes.objects.get(code=code)
            if promo.expiry < datetime.datetime.today().date():
                return Response({"message":"Promo Expired"},status=404)
            if promo.uses <= 0:
                return Response({"message": "Promo Used"}, status=404)
            serialized = PromoSerializer(promo)
            return Response({'message':"Here is the detail of your promo Code you entered", "Promo": serialized.data})
        except:
            return Response({"message": "Promo not Valid"}, status=404)
        
        
    def get_expiry(self, days):
        return datetime.date.today() + datetime.timedelta(days=20)
    def post(self,request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        
        user = User.objects.get(pk=payload['user'])
        if not user:
            return Response({"message": "User not found"}, status=401)
        if not user.is_superuser:
            return Response({"message":"users is not authorized"},status=401)
        if 'promo_code' in request.data:
            try:
                promo = PromoCodes.objects.get(code=request.data['promo_code'])
                return Response({"message":"promocode already exists"},status=400)
            except:
                new_promo=PromoCodes.objects.create(code=request.data['promo_code'],discount=request.data['discount'],discount_type=request.data['type'],uses=request.data['uses'])
                serialized=PromoSerializer(new_promo)
                return Response({"message":"promocode created","Promo": serialized.data})
    

class GetAllOrders(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user.is_superuser:
            return Response({"message":"Un authorized"}, status=401)
        orders = Order.objects.all()
        orders = OrderSerializer(orders, many=True).data
        return Response({"message": "FOund these orders", "orders": orders})

class GetMyOrders(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        orders = Order.objects.filter(user=user)
        orders = OrderSerializer(orders, many=True).data
        return Response({"message": "FOund these orders", "orders": orders})
class GetThisOrder(APIView):
    def get(self, request, order_id):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        order = Order.objects.get(pk=order_id)
        if not user.is_superuser:
            if order.user != user:
                return Response({"message": "This order is not yours"}, status=401)
        i = OrderSerializer(order).data
        i['user'] = UserSerializer(User.objects.get(id=i['user'])).data
        i['shipping_addres'] = AddresSerializer(Addres.objects.get(id=i['shipping_addres'])).data
        ordered_products = OrderedProduct.objects.filter(order=i['id'])
        i["order_products"] = OrderedProductSerializer(ordered_products, many=True).data
        for c in i["order_products"]:
            c['product'] = ProductSerializer(Product.objects.get(id=c['product'])).data
        ordered_design = OrderedDesign.objects.filter(order=i['id'])
        i["order_design"] = OrderedDesignSerializer(ordered_design, many=True).data
        for c in i["order_design"]:
            c['design'] = DesignSerializer(Design.objects.get(id=c['design'])).data
            
            c['shirt_style'] = ShirtStyleSerializer(ShirtStyle.objects.get(id=int(c['shirt_style']))).data
        ordered_custom = OrderedCustom.objects.filter(order=i['id'])
        i["order_custom"] = OrderedCustomSerializer(ordered_custom, many=True).data
        for c in i["order_custom"]:
            c['shirt_style'] = ShirtStyleSerializer(ShirtStyle.objects.get(id=int(c['shirt_style']))).data
        return Response({"message": "order details", "order": i})
class UserApi(APIView):
    def get(self,request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(pk=payload['user'])
        if not user.is_superuser:
            return Response({"message": str(user.is_superuser)+": Dont have Permission to access userlist"}, status=401)
        users = User.objects.all()
        user = UserSerializer(users, many=True).data
        return Response({"message": "found these users","user": user})

class UpdatecityApi(APIView):
    def post(self, request,id):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(pk=payload['user'])
        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=401)
        except jwt.DecodeError:
            return Response({"message": "Token is invalid"}, status=401)
        except User.DoesNotExist:
            return Response({"message": "User does not exist"}, status=401)
        
        if not user.is_superuser:
            return Response({"message": "Don't have permission to update cities"}, status=401)
        try:
            city = City.objects.get(pk=id)
            
        except City.DoesNotExist:
            return Response({"message": "City not found"}, status=404)
        
        serializer = CitySerializer(city, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': "City updated", 'City': serializer.data}, status=200)
        else:
            return Response({'message': "City not updated", 'errors': serializer.errors}, status=400)

class DeletecityApi(APIView):
    def post(self, request,id):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Unauthenticated"}, status=401)
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(pk=payload['user'])
        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired"}, status=401)
        except jwt.DecodeError:
            return Response({"message": "Token is invalid"}, status=401)
        except User.DoesNotExist:
            return Response({"message": "User does not exist"}, status=401)
        
        if not user.is_superuser:
            return Response({"message": "Don't have permission to update cities"}, status=401)
        try:
            print(id)
            city = City.objects.get(pk=id)
        except City.DoesNotExist:
            return Response({"message": "City not found"}, status=404)
        
        city.delete()
        return Response({'message': "City deleted"}, status=200)
          