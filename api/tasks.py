from celery import shared_task
from .models import Design
from .serializers import DesignSerializer
import cv2
import base64
import numpy as np
import requests
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

@shared_task
def process_custom_product(custom, design_id=None, custom_img=None):
    designSerialized = None
    if custom == "no":
        design = Design.objects.get(pk=int(design_id))
        designSerialized = DesignSerializer(design).data
        custom_image_url = "https://api.dripsaint.com" + (design.image.url.replace("https://bucketeer-9e464def-6eb2-47fb-80c4-5f2649de73e3.s3.amazonaws.com/", "/media/"))
    else:
        custom_image_url = custom_img
    
    shirt_placeholder_sets = [
        ('https://api.dripsaint.com/media/media/ai/shirt1.png', 'https://api.dripsaint.com/media/media/ai/placeholder1.png'),
        ('https://api.dripsaint.com/media/media/ai/shirt2.png', 'https://api.dripsaint.com/media/media/ai/placeholder2.png'),
    ]
    
    images_base64 = []
    
    try:
        custom_image = download_image_from_url(custom_image_url)
        _, buffer = cv2.imencode('.jpg', custom_image)
        image_bytes = buffer.tobytes()
        image_base64 = base64.b64encode(image_bytes).decode('utf-8')
        images_base64.append(image_base64)
        for shirt_image_path, placeholder_image_path in shirt_placeholder_sets:
            output_img = replace_shirt_print(custom_image, shirt_image_path=shirt_image_path, placeholder_image_path=placeholder_image_path)
            _, buffer = cv2.imencode('.jpg', output_img)
            image_bytes = buffer.tobytes()
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')
            images_base64.append(image_base64)
            del output_img  # Free memory
        del custom_image # free memory
        return {'images': images_base64, 'design': designSerialized}
    
    except ValueError as e:
        logger.error(f"ValueError: {e}")
        return {'error': str(e)}
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {'error': 'An unexpected error occurred.'}

def download_image_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error on bad status
        image_array = np.asarray(bytearray(response.content), dtype=np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
        return image
    except requests.exceptions.RequestException as e:
        print(f"Error downloading image: {e}")
        return None

def replace_shirt_print(custom_image, shirt_image_path, placeholder_image_path):
    shirt_image_path = shirt_image_path
    placeholder_image_path = placeholder_image_path
    
    # Load the images
    shirt_img = download_image_from_url(shirt_image_path)
    placeholder_img = download_image_from_url(placeholder_image_path)
    custom_img = custom_image
    
    if shirt_img is None:
        raise ValueError("Shirt image not found.")
    if placeholder_img is None:
        raise ValueError("Placeholder image not found.")
    if custom_img is None:
        raise ValueError("Custom image not found.")
    print("images downloaded")
    
    # Convert images to grayscale
    shirt_gray = cv2.cvtColor(shirt_img, cv2.COLOR_BGR2GRAY)
    placeholder_gray = cv2.cvtColor(placeholder_img, cv2.COLOR_BGR2GRAY)
    print("cv2 working")
    
    # Perform template matching
    result = cv2.matchTemplate(shirt_gray, placeholder_gray, cv2.TM_CCOEFF_NORMED)
    print("result made")
    _, _, _, max_loc = cv2.minMaxLoc(result)
    
    # Get the coordinates of the detected placeholder region
    placeholder_w, placeholder_h = placeholder_gray.shape[::-1]
    placeholder_x, placeholder_y = max_loc
    
    # Resize the custom image to match the size of the detected placeholder region
    custom_resized = cv2.resize(custom_img, (placeholder_w, placeholder_h))
    
    # Replace the placeholder region in the shirt image with the resized custom image
    shirt_img[placeholder_y:placeholder_y + placeholder_h, placeholder_x:placeholder_x + placeholder_w] = custom_resized
    
    print("shirt replaced")
    return shirt_img
