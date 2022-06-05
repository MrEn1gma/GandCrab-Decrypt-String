from Cryptodome.Cipher import ARC4
import numpy as np
import idaapi

def findEndAddr(start_addr, asm_code):
    count = 0
    while(start_addr > 0):
        final_addr = start_addr - count
        if(asm_code in idc.GetDisasm(final_addr)):
            final_addr = idc.prev_head(final_addr)
            final_addr = idc.prev_head(final_addr)
            """_summary_
                đoạn ở trên là để lấy lên trên index đoạn chứa ciphertext.
                vd:
                    .text:0040A866                 lea     eax, [ebp+var_DC]
                    .text:0040A86C                 push    eax
                    .text:0040A86D                 mov     [ebp+var_DC], 3EB5A07Bh
                    .text:0040A877                 mov     [ebp+var_D8], 501CC987h
                    nếu chỉ ghi 1 lần "final_addr = idc.prev_head(final_addr)" thì nó chỉ tới địa chỉ 0x40a86d thôi, như vậy
                    thì sẽ bị bỏ sót đoạn đó khi tạo ciphertext, nên cần phải thêm lệnh đó nữa.
            """
            return final_addr
        count += 1

def findEndAddr_plus(addr):
    count = 0
    while(addr > 0):
        final_addr = addr - count
        if('lea' in idc.GetDisasm(final_addr)):
            out = str(idc.GetDisasm(final_addr))
            out = out.replace("lea     eax, ", "")
            mov_ins = "mov     " + out
            return findEndAddr(addr, mov_ins)
        count += 1

def GetEndAddr_for_first_index(start_addr):
    """

    Đếm ngược các dòng asm cho đến khi lấy hết được giá trị trừ lệnh mov, bắt đầu từ hàm RC4
    """
    count = start_addr
    while(count > 0):
        final_addr = count
        if('lea' in idc.GetDisasm(final_addr)):
            return final_addr
        count -= 1
            
def GetCipherText(func_name): # func_name: RC4 Decryption
    name = func_name
    ea = get_name_ea_simple(name)
    addr_xrefs = [i for i in CodeRefsTo(ea, 1)]
    ciphertext_list = []
    for i in range(len(addr_xrefs)):
        if(i == 0):
            end_addr = GetEndAddr_for_first_index(addr_xrefs[0])
            idxAddr = addr_xrefs[0]
        elif(i == 6):
            ciphertext_list.append("0C4B00C95FF9C645654D08A6933F28A023873821B26B8BE318A0443C520D332139B2812DAEB3022F1C889C382E186B3712BE6B371290FD86684E397F9B9166C56BEF82068482")
            continue
        elif(i == 58):
            ciphertext_list.append("8a41C755176A4D4331F84D4331FE293DFB81B43EB89EDA0573B89C0B5F73")
            continue
        elif(i == 64):
            ciphertext_list.append("0e5C35F5D60E2D8D8CD22D8D8CD4EC571CEC29D631E2E3640801137D1188")
            continue
        elif(i == 77):
            ciphertext_list.append("57AC2CDD58AE1385A9AE17F8FDF1F1DE50F85A93EE4E2174EE4E2160C5C2AABC80EB2A88D3ECBCF0C5218A93")
            continue
        elif(i == 84):
            ciphertext_list.append("1e6BDB5B583312341E5cC61BCD3F6002639D384B7FCA20907FCA2084FD23AAE038BDCB9BE5D698E278084C82")
            continue
        elif(i == 86):
            ciphertext_list.append("E72915F7846168A11D81BE9752998B63DC749217A05c48009023CEE29023CEFA23C7AF085D1872F33546009A49BB3284")
            continue
        elif(i == 125):
            ciphertext_list.append("3379E960C554D04577B369749D53651478B8651478B64856D9068C28F207DE9C510BA6124E5a")
            continue
        elif(i == 128):
            ciphertext_list.append("2a5ec78949773B2F40C74A8B315790B09B2803B0D1FF93F80718B2491A3BEB3940235800A2E22E62CE2DF55a8C602F8477D751AFFE9DCC17CBC63406CBC6343EEFF070AF91F24CA6501CC9873EB5A07B")
            continue
        elif(i == 130):
            ciphertext_list.append("26E8ABC3EF433F22F98DD77E9630FC70CF5E809C259C1B90F6C4D4C2F239674C9D7DAE2DD8A467555391AB027308FB8696B19EB796B19E87C03D2F11D260A9D01C24B8E2DB100C52")
            continue
        elif(i == 132):
            ciphertext_list.append("05B8FA2812BF762C694A6B5F48F2F83D50B223E20C6E06280AE45F1C27BA06660675AEDF8B24FA999220DFBF1EF97ECB415d46449CB7BD15FC86ECF52C6CE201F4E2F6AF4E10D05cD7AB0ACC407B6FA3088B8ADE414761FEC5017D15BC817D15BCDB83CD57E101CEF15c92A078D2F606D154")
            continue
        elif(i == 139):
            ciphertext_list.append("225CCB46BAE8F6D25078AD00EAF9C0E3FF2E7F1AF31F88702A97696EA4560D77F355877B8EADB2EA1E63A4BC1E63A49459F798149EC9C6D18819D167F92E43A8")
            continue
        elif(i == 140):
            ciphertext_list.append("BF8C82104135F80E337648A2AEA400563DEF130EA4FD3AB78CC03AB78CD6720F0D5598A590BE60D6EA4B4AE839A1")
            continue
        elif(i == 145):
            ciphertext_list.append("5ad938475365743BE8E7EE9ABB4AA183BB4AA18F7D15A3C390452339C4E29673D4761A40")
            continue
        elif(i == 147):
            ciphertext_list.append("D36F578ED080AB2625C0771037025a6337025A6fCE226F13C2ADF6105635BCBF33CF1C30")
            continue
        elif(i == 154):
            ciphertext_list.append("37E0A36B14132306CFB571E25138EBC03BD9EBC03BD713CE0a17715E637C6D448D35EDEFE1F1")
            continue
        elif(i == 156):
            ciphertext_list.append("7F211984485E0251A495D885F0F3E00F284B4D2F987449DDC2C87FA16BC55522A5D9A2A879521F3C035C33BB19F69AF3D8C06AF1B1858B50AB9BC95D8DDCFD3647F87C4DA5D80899E38DBCD93969BB0520AF5E0520AF114645FD18938E88CAE4124F59E96E4E20")
            continue
        elif(i == 157):
            ciphertext_list.append("77401089AA01ECB9851276D69FB4114D093DC2D757118A2F321D2661B50F2B70E9FEB918E9FEB938D358D1199F3D0a6278E7332A74C67925")
            continue
        else:
            end_addr = findEndAddr_plus(addr_xrefs[i])
            idxAddr = addr_xrefs[i]
        
        ciphertext = ""
        while(idxAddr > end_addr):
            if(("mov     [ebp+var" in idc.GetDisasm(idxAddr)) or ("mov     word ptr [ebp+var" in idc.GetDisasm(idxAddr)) or ("mov     byte ptr [ebp+var" in idc.GetDisasm(idxAddr))):
                c = str(hex(get_operand_value(idxAddr, 1)))[2:]
                if(c.startswith("ffff")):
                    c = c[4:]
                elif(len(c) % 2 != 0):
                    c = "0" + c
                ciphertext += c
            idxAddr = idc.prev_head(idxAddr)
        ciphertext_list.append(ciphertext)
    return ciphertext_list, addr_xrefs
    
ciphertext_list, addr_xrefs = GetCipherText("sub_407563")
for idx in range(len(ciphertext_list)):
    inp = [i for i in bytes.fromhex(ciphertext_list[idx])[::-1]]
    key = np.array(inp[:16], "<u1").tobytes()
    sizeCipher = inp[16] ^ inp[20]
    cipher = np.array(inp[24:24 + sizeCipher], "<u1").tobytes()
    arc4 = ARC4.new(key)
    out = arc4.decrypt(cipher)
    plaintext = [i for i in out]

    for j in range(len(plaintext)):
        chk = 0
        if(chk in plaintext):
            plaintext.remove(0) # Sau khi decrypt xong, bỏ các byte 0 để print ra chuỗi hoàn chỉnh        
    msg_output = "[" + str(hex(addr_xrefs[idx])) + "] | Encrypted string: 0x" + str(ciphertext_list[idx]) + " | Decrypted string: " + str("".join([chr(i) for i in plaintext]))
    msg_cmt_output = "Decrypted string: " + str("".join([chr(i) for i in plaintext]))
    idc.set_cmt(addr_xrefs[idx], msg_cmt_output, 0) # set comment tai ham do
    print(msg_output)
        
print("OK.")