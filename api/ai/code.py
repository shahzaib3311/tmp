import cv2
import numpy as np
import requests
from io import BytesIO

def download_image_from_url(url):
    response = requests.get(url)
    if response.status_code != 200:
        raise ValueError("Error downloading image from URL.")
    image_array = np.array(bytearray(response.content), dtype=np.uint8)
    image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
    return image

def replace_shirt_print(custom_image_url):
    shirt_image_path = './shirt.png'
    placeholder_image_path = './placeholder.png'
    custom_image_url = custom_image_url
    output_image_path = './output_image.jpg'
    # Load the images
    shirt_img = cv2.imread(shirt_image_path)
    placeholder_img = cv2.imread(placeholder_image_path)
    custom_img = download_image_from_url(custom_image_url)

    if shirt_img is None:
        raise ValueError("Shirt image not found.")
    if placeholder_img is None:
        raise ValueError("Placeholder image not found.")
    if custom_img is None:
        raise ValueError("Custom image not found.")
    
    # Convert images to grayscale
    shirt_gray = cv2.cvtColor(shirt_img, cv2.COLOR_BGR2GRAY)
    placeholder_gray = cv2.cvtColor(placeholder_img, cv2.COLOR_BGR2GRAY)
    
    # Perform template matching
    result = cv2.matchTemplate(shirt_gray, placeholder_gray, cv2.TM_CCOEFF_NORMED)
    _, _, _, max_loc = cv2.minMaxLoc(result)
    # Get the coordinates of the detected placeholder region
    placeholder_w, placeholder_h = placeholder_gray.shape[::-1]
    placeholder_x, placeholder_y = max_loc
    
    # Extract the region of interest (ROI) from the shirt image
    roi = shirt_img[placeholder_y:placeholder_y+placeholder_h, placeholder_x:placeholder_x+placeholder_w]
    
    # Resize the custom image to match the size of the detected placeholder region
    custom_resized = cv2.resize(custom_img, (placeholder_w, placeholder_h))
    
    # Replace the placeholder region in the shirt image with the resized custom image
    shirt_img[placeholder_y:placeholder_y+placeholder_h, placeholder_x:placeholder_x+placeholder_w] = custom_resized
    
    # Save the output image
    #cv2.imwrite(output_image_path, shirt_img)
    
    return shirt_img

# Example usage



