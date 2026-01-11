with open('main.py', 'r') as f:
    lines = f.readlines()

# Remove problematic lines
lines_to_remove = []
for i, line in enumerate(lines):
    # Remove stray ) on line that only has )
    if i == 419 and line.strip() == ')':  # Line 420 in editor (0-indexed)
        lines_to_remove.append(i)
    # Remove extra ) line after the Label constructor
    if i == 426 and line.strip() == ')':  # Line 427 in editor
        lines_to_remove.append(i)

# Remove lines in reverse order
for i in sorted(lines_to_remove, reverse=True):
    del lines[i]

# Write back
with open('main.py', 'w') as f:
    f.writelines(lines)

print("Removed stray parentheses. Testing syntax...")
