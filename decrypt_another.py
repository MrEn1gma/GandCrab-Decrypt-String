from Cryptodome.Cipher import ARC4, Salsa20
from base64 import b64decode
import numpy as np
import idaapi

def decrypt_list_target_extensions(key_1, sizekey_1, addrcip_1, sizeCip_1, key_2, sizekey_2, addrcip_2, sizeCip_2, key_3, sizekey_3, addrcip_3, sizeCip_3):
    extension_1 = ida_bytes.get_bytes(addrcip_1, sizeCip_1)
    extension_2 = ida_bytes.get_bytes(addrcip_2, sizeCip_2)
    extension_3 = ida_bytes.get_bytes(addrcip_3, sizeCip_3)
    key_exten1 = ida_bytes.get_bytes(key_1, sizekey_1)
    key_exten2 = ida_bytes.get_bytes(key_2, sizekey_2)
    key_exten3 = ida_bytes.get_bytes(key_3, sizekey_3)
    
    arc4_1 = ARC4.new(key_exten1)
    x = arc4_1.decrypt(extension_1)
    arc4_2 = ARC4.new(key_exten2)
    y = arc4_2.decrypt(extension_2)
    arc4_3 = ARC4.new(key_exten3)
    z = arc4_3.decrypt(extension_3)
    list_target_extension = ""
    out1 = [(i ^ 5) for i in x]
    out2 = [(i ^ 5) for i in y]
    out3 = [(i ^ 5) for i in z]
    for _ in range(len(out1)):
        chk = 0
        if(chk in out1):
            out1.remove(0)
            
    for _ in range(len(out2)):
        chk1 = 0
        if(chk1 in out2):
            out2.remove(0)
            
    for _ in range(len(out3)):
        chk2 = 0
        if(chk2 in out3):
            out3.remove(0)
            
    list_target_extension = "[+] List extension do not encrypt: " + str("".join([chr(i) for i in out1])) + "\n" + "[+] List extension must be encrypt: " + str("".join([chr(i) for i in out2])) + str("".join([chr(i) for i in out3]))
    return list_target_extension
    
print(decrypt_list_target_extensions(0x413c5c, 16, 0x413c70, 548, 0x413e94, 16, 0x413ea8, 188, 0x413f64, 16, 0x413f78, 3781))

# Decrypt PC_DATA
print("\n--- PC_DATA ---")
pc_key = ".oj=294~!z3)9n-1,8^)o((q22)lb$".encode()
pc_cipher = b64decode("7ftDEgLb/ZS0lcmZbHM61I/J+AOoD+QKyw7LboogFHYeWLYCxZ+XYFtxBmDb9KHJOJDfAveVruDURWTIXHRKQxSaxLPQzr4SaOgCapOX2qbLGOIpU0uVIkugicQ2qivs7UgEXVJiDcF0iWP/gFL8WqBHGyOgMof74iZHO883kWa60KsRG/ofEubBktl3sqmHT/UeIK90f4NTA3Q0Aa7fDOtFnCOTB5ome7FLZ/fMCt27gAb2/52sUzN7xdxdWKoyoIWs5zhHRnLzMN2B2FCdeiqo6lrnnIaZ6V9BSTXO4zB9mPr7qICkGFwpU6i/RSEVcPfH0wpSWSCYtNWJJNBZBilqqMZrR7W3ZLHPmYGRj0eJP9/y/fM3LOXjXaO0r1pWo+YkTxTJi/a4L0V0svf5S0uz66BfoUfFwZ2CPDSx4yhFudDoMFoN6ieVyOmvqBxvfLwArtgyoy8F1fOlXDmW7qZ4Buw/gTuwIUyBb8YftNxTLWijqrjEwB/itTONKJOg3o3LWKn+7wkTvCmihYFNEr9E4CN7AJnhnNRKIBD1XUGeyfaMbJ0e1lo/q+RXezYEh3TGCu/rONcZPBaVdco=")
arc4 = ARC4.new(pc_key)
pc_output = arc4.decrypt(pc_cipher)
pc_plaintext = [i for i in pc_output]

for i in range(len(pc_plaintext)):
    pcchk = 0
    if(pcchk in pc_plaintext):
        pc_plaintext.remove(0)
        
print("".join([chr(i) for i in pc_plaintext]))

# Decrypt Command & Control
print("\n--- Command & Control ---")
cc_key = np.array([0x93, 0x22, 0x4F, 0xC4, 0xF7, 0x28, 0x6B, 0x75, 0x4B, 0x5C, 0x36, 0xD3, 0x9C, 0x23, 0x68, 0x26], "<u1").tobytes()
cc_cipher = ida_bytes.get_bytes(0x414e50, 4358)
cc_out = ARC4.new(cc_key).decrypt(cc_cipher)

cc_out = [(i ^ 5) for i in cc_out]
for i in range(len(cc_out)):
    if(0 in cc_out):
        cc_out.remove(0)
        
print("".join([chr(i) for i in cc_out]))

# Decrypt rsa public key
print("\n--- RSA PUBLIC KEY ---")
rc4key = np.array([0xBA, 0xFE, 0x9B, 0xDB, 0xD2, 0x40, 0x5D, 0x7A, 0x09, 0x69, 0x9F, 0x0E, 0xF3, 0x99, 0x8A, 0x61], "<u1").tobytes()
cipher = ida_bytes.get_bytes(0x413B48, 276)
arc4 = ARC4.new(rc4key)
rc4out = arc4.decrypt(cipher)
res = []

for i in range(len(rc4out)):
    res.append(rc4out[i] ^ 5)
    
res = np.array(res, "<u1").tobytes()
pkey_ = np.array([0x40, 0x68, 0x61, 0x73, 0x68, 0x62, 0x72, 0x65, 0x61, 0x6B, 
                 0x65, 0x72, 0x20, 0x44, 0x61, 0x6E, 0x69, 0x65, 0x6C, 0x20, 
                 0x4A, 0x2E, 0x20, 0x42, 0x65, 0x72, 0x6E, 0x73, 0x74, 0x65, 
                 0x69, 0x00], "<u1").tobytes()
salsa20_nonce = np.array([0x40, 0x68, 0x61, 0x73, 0x68, 0x62, 0x72, 0x00] ,"<u1").tobytes()
salsa = Salsa20.new(key=pkey_, nonce=salsa20_nonce)
rsa_public_key = salsa.decrypt(res)
print(rsa_public_key)