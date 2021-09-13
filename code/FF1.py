import math
import utils


# need real radix
# need real Tweak and t
# need own ceil func
# dont understand PRF func
radix = 10
T = b'0101010101010101'
t = 16
n = b'1000100010001000'
u = len(n)//2
v = len(n)-u
A = n[:u]
B = n[u:]
b = math.ceil(math.ceil(v*math.log2(radix))/8)
d = 4*math.ceil(b/4)+4
P = b'00000001'+ b'00000010'+b'00000001' + \
    radix.to_bytes(3,'big') + b'00001010' + \
    (u % 256).to_bytes(1,'big') + \
    len(n).to_bytes(3,'big') + t.to_bytes(1,'big')

for x in range(0,9):
    Q = T + (0).to_bytes(-t-b-1,'big') + x.to_bytes(1,'big') + num_radix(B)
    R = 10
    


print(x)

def tonumber(asd):
    #make bit to integer
    return 100