path = r'c:\Users\meire\Documents\Nova pasta\muty-transporte-2026\index.html'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    # Only remove the one around line 1640-1650 if it's a redeclaration
    if i > 1000 and ('const AUTH_KEY' in line or 'const USER_KEY' in line):
        print(f"Removing line {i+1}: {line.strip()}")
        continue
    new_lines.append(line)

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
print("Cleanup finished.")
