import cv2
import numpy as np
import requests
from io import BytesIO

def download_image_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error on bad status
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"Error downloading image: {e}")
        return None

def replace_shirt_print(custom_image_url):
    shirt_image_path = 'https://api.dripsaint.com/media/ai/shirt.png'
    placeholder_image_path = 'https://api.dripsaint.com/media/ai/placeholder.png'
    custom_image_url = custom_image_url
    print("custom image url: "+custom_image_url)
    output_image_path = './ai/output_image.jpg'
    # Load the images
    shirt_img = download_image_from_url(shirt_image_path)
    placeholder_img = download_image_from_url(placeholder_image_path)
    custom_img = download_image_from_url(custom_image_url)
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
    
    # Extract the region of interest (ROI) from the shirt image
    roi = shirt_img[placeholder_y:placeholder_y+placeholder_h, placeholder_x:placeholder_x+placeholder_w]
    
    # Resize the custom image to match the size of the detected placeholder region
    custom_resized = cv2.resize(custom_img, (placeholder_w, placeholder_h))
    
    # Replace the placeholder region in the shirt image with the resized custom image
    shirt_img[placeholder_y:placeholder_y+placeholder_h, placeholder_x:placeholder_x+placeholder_w] = custom_resized
    
    # Save the output image
    #cv2.imwrite(output_image_path, shirt_img)
    print("shirt replaced")
    return shirt_img

# Example usage



