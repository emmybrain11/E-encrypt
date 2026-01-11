import os
import shutil

# Create directories
folders = ['screens', 'data', 'assets', 'core', 'ui']
for folder in folders:
    os.makedirs(folder, exist_ok=True)
    print(f"Created folder: {folder}")

# Create __init__.py files
for folder in ['core', 'ui', 'screens']:
    with open(os.path.join(folder, '__init__.py'), 'w') as f:
        pass

print("Setup complete!")