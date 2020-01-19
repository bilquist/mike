# core/utils.py

from PIL import Image



def crop_image_to_square(image):
	"""Turn a given image into a square"""
	img_width, img_height = image.size
	if img_width == img_height:
		return image ## Image is already a square
	# Crop if it is not a square
	if img_width < img_height:
		overspill = img_height - img_width
		left = 0
		top = int(overspill / 2)
		right = img_width
		bottom = img_width + top
	elif img_width > img_height:
		overspill = img_width - img_height
		left = int(overspill / 2)
		top = 0
		right = img_height + left
		bottom = img_height
	return image.crop((left, top, right, bottom))
	