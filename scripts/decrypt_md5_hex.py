import hashlib
candidates = ['peter', 'wiener:peter', 'peter:wiener']
for c in candidates:
    print(c, '->', hashlib.md5(c.encode()).hexdigest())
