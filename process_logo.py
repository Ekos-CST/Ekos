import math
from PIL import Image, ImageDraw

def process_logo():
    src_path = 'C:/Users/erenc/OneDrive/Pictures/Gemini_Generated_Image_432n1b432n1b432n.png'
    img = Image.open(src_path).convert('RGBA')
    width, height = img.size

    # Check top-left corner color for background identification
    corner_r, corner_g, corner_b, _ = img.getpixel((0, 0))

    # 1. Create transparent background version for in-app UI display
    data = img.get_flattened_data() if hasattr(img, 'get_flattened_data') else list(img.getdata())
    new_data = []

    for item in data:
        r, g, b, a = item
        # Distance from background color
        dist = math.sqrt((r - corner_r)**2 + (g - corner_g)**2 + (b - corner_b)**2)
        if dist < 35:
            # Make background transparent with smooth edge transition
            alpha = int(max(0, min(255, (dist - 10) * 10.2)))
            new_data.append((r, g, b, alpha))
        else:
            new_data.append((r, g, b, 255))

    transparent_img = Image.new('RGBA', img.size)
    transparent_img.putdata(new_data)
    
    # Save in-app transparent logo
    transparent_img.save('gui/public/assets/logo.png', 'PNG')
    print('Transparent in-app logo saved: gui/public/assets/logo.png')

    # 2. Create Taskbar Icon with Rounded Radius Corners (Border Radius)
    icon_size = 256
    taskbar_img = transparent_img.resize((icon_size, icon_size), Image.LANCZOS)

    # Create anti-aliased rounded corner mask
    mask_scale = 4
    large_size = icon_size * mask_scale
    radius_large = int(large_size * 0.22) # 22% rounded border-radius

    mask = Image.new('L', (large_size, large_size), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, large_size, large_size), radius=radius_large, fill=255)
    
    mask = mask.resize((icon_size, icon_size), Image.LANCZOS)

    # Create taskbar icon with solid dark background + rounded mask + logo
    bg_color = (15, 10, 26, 255) # Dark purple obsidian background for taskbar icon
    taskbar_base = Image.new('RGBA', (icon_size, icon_size), bg_color)
    
    # Composite transparent logo over taskbar base
    taskbar_base.paste(taskbar_img, (0, 0), taskbar_img)
    
    # Apply rounded mask
    rounded_taskbar_icon = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 0))
    rounded_taskbar_icon.paste(taskbar_base, (0, 0), mask)
    
    rounded_taskbar_icon.save('gui/public/assets/taskbar_icon.png', 'PNG')
    rounded_taskbar_icon.save('gui/public/assets/icon.ico', 'ICO')
    print('Taskbar rounded radius icon saved: gui/public/assets/taskbar_icon.png')

if __name__ == '__main__':
    process_logo()
