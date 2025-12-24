from PIL import Image
import io

def hide_data_in_image(cover_image_bytes, data_bytes):
    """
    Hide data_bytes inside cover_image_bytes using LSB steganography.
    Returns bytes of the new PNG image.
    """
    img = Image.open(io.BytesIO(cover_image_bytes)).convert('RGB')
    width, height = img.size
    pixels = img.load()

    length = len(data_bytes)
    full_data = length.to_bytes(4, 'big') + data_bytes
    
    capacity = (width * height * 3) // 8
    if len(full_data) > capacity:
        raise ValueError(f"Image too small. Needs to hold {len(full_data)} bytes, but capacity is {capacity} bytes.")

    data_index = 0
    bit_index = 0
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            
            channels = [r, g, b]
            new_channels = []
            
            for channel in channels:
                if data_index < len(full_data):
                    bit = (full_data[data_index] >> (7 - bit_index)) & 1
                    
                    new_channel = (channel & 0xFE) | bit
                    new_channels.append(new_channel)
                    
                    bit_index += 1
                    if bit_index == 8:
                        bit_index = 0
                        data_index += 1
                else:
                    new_channels.append(channel)
            
            pixels[x, y] = tuple(new_channels)
            
            if data_index >= len(full_data):
                break
        if data_index >= len(full_data):
            break
            
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()

def reveal_data_from_image(steg_image_bytes):
    """
    Extract hidden data from LSB steganography image.
    """
    img = Image.open(io.BytesIO(steg_image_bytes)).convert('RGB')
    width, height = img.size
    pixels = img.load()
    
    data_bytes = bytearray()
    current_byte = 0
    bit_index = 0
    
    size_read = False
    expected_size = 0
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            channels = [r, g, b]
            
            for channel in channels:
                bit = channel & 1
                current_byte = (current_byte << 1) | bit
                bit_index += 1
                
                if bit_index == 8:
                    data_bytes.append(current_byte)
                    current_byte = 0
                    bit_index = 0
                    
                    if not size_read and len(data_bytes) == 4:
                        expected_size = int.from_bytes(data_bytes, 'big')
                        size_read = True
                        data_bytes = bytearray()
                        
                    elif size_read and len(data_bytes) == expected_size:
                        return bytes(data_bytes)

    if size_read and len(data_bytes) < expected_size:
        raise ValueError("Image corrupt or data truncated")
        
    raise ValueError("No valid data found")
