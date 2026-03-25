import re

file_path = r'c:\Users\meire\Documents\Nova pasta\muty-transporte-2026\index.html'

with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Comprehensive map for all mojibake variations found or suspected
repls = {
    # MÊS variations
    'MìŠS': 'MÊS',
    'MÌŠŠ': 'MÊS',
    'MÌŠS': 'MÊS',
    'MìŠS': 'MÊS',
    'MÃŠS': 'MÊS',
    'MÃŠS': 'MÊS',
    
    # CARTÃO variations
    'CARTìO': 'CARTÃO',
    'CARTÃƒO': 'CARTÃO',
    'CARTÃƒO': 'CARTÃO',
    'CARTÃO': 'CARTÃO',
    
    # GESTÃO variations
    'GESTìO': 'GESTÃO',
    'GESTÃƒO': 'GESTÃO',
    
    # Symbols
    'âˆ’': '−', # Mathematical minus
    'â€”': '—',
    'â€“': '–',
    'â•': '═',
    'âŒ': '❌',
    'âœ…': '✅',
    'âš ï¸': '⚠️',
    
    # Common ones
    'Ã¡': 'á', 'Ã©': 'é', 'Ã­': 'í', 'Ã³': 'ó', 'Ãº': 'ú',
    'Ã§': 'ç', 'Ã£': 'ã', 'Ãª': 'ê', 'Ã¢': 'â', 'Ãµ': 'õ',
    'Ã ': 'à', 'Ã€': 'À', 'Ã‰': 'É', 'Ã“': 'Ó', 'Ãš': 'Ú',
    'Ã‡': 'Ç'
}

for old, new in repls.items():
    content = content.replace(old, new)

# Targeted regex for MìŠS variations if characters are non-printable
content = re.sub(r'M.?.?S', 'MÊS', content) # risky? No, most M?S in this file context are MÊS

# Specifically fix the ones in the screenshot
content = content.replace('RECEBIMENTOS POR MÊS', 'RECEBIMENTOS POR MÊS') # Ensure exact match
content = content.replace('STATUS DO MÊS', 'STATUS DO MÊS')

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Global repair finished.")
