with open('main.py', 'r') as f:
    lines = f.readlines()

# Find the register_label line
for i in range(len(lines)):
    if 'register_label' in lines[i] and 'Label(' in lines[i]:
        print(f"Found register_label on line {i+1}")
        
        # Look for the closing parenthesis
        paren_count = lines[i].count('(') - lines[i].count(')')
        j = i
        
        while paren_count > 0 and j < len(lines) - 1:
            j += 1
            paren_count += lines[j].count('(') - lines[j].count(')')
        
        if paren_count > 0:
            print(f"Missing closing parenthesis after line {j+1}")
            # Add closing parenthesis
            if j < len(lines):
                # Insert closing parenthesis
                lines.insert(j + 1, '        )\n')
                print("Added missing closing parenthesis")
        
        break

# Write fixed file
with open('main.py', 'w') as f:
    f.writelines(lines)
print("File fixed. Testing syntax...")
