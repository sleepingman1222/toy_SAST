def unsafe():
    # ruleid: kisa.sw35.python.obvious-infinite-loop
    while True:
        print("loop")

def safe(items):
    # ok: kisa.sw35.python.obvious-infinite-loop
    for item in items:
        print(item)
