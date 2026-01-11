from PIL import Image
import numpy as np


class Steganography:
    def __init__(self):
        self.method = 'LSB'

    def hide_in_image(self, image_path, message, output_path=None):
        """Hide message in image using LSB method"""
        try:
            img = Image.open(image_path)
            img_array = np.array(img)

            # Convert message to binary
            binary_msg = ''.join(format(ord(c), '08b') for c in message)
            binary_msg += '1111111111111110'  # End marker

            if len(binary_msg) > img_array.size:
                return None, "Message too large for image"

            # Flatten image array
            flat_array = img_array.flatten()

            # Hide message in LSB
            for i in range(len(binary_msg)):
                flat_array[i] = (flat_array[i] & ~1) | int(binary_msg[i])

            # Reshape and save
            encoded_array = flat_array.reshape(img_array.shape)
            encoded_img = Image.fromarray(encoded_array.astype(np.uint8))

            if output_path is None:
                output_path = image_path.replace('.', '_encoded.')

            encoded_img.save(output_path)
            return output_path, None

        except Exception as e:
            return None, str(e)

    def extract_from_image(self, image_path):
        """Extract hidden message from image"""
        try:
            img = Image.open(image_path)
            img_array = np.array(img)
            flat_array = img_array.flatten()

            # Extract LSBs
            binary_data = ''
            for pixel in flat_array:
                binary_data += str(pixel & 1)

            # Find end marker
            end_marker = '1111111111111110'
            end_pos = binary_data.find(end_marker)

            if end_pos == -1:
                return None, "No hidden message found"

            binary_msg = binary_data[:end_pos]

            # Convert binary to text
            message = ''
            for i in range(0, len(binary_msg), 8):
                byte = binary_msg[i:i + 8]
                if len(byte) == 8:
                    message += chr(int(byte, 2))

            return message, None

        except Exception as e:
            return None, str(e)