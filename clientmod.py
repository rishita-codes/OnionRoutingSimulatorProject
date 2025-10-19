import nodes
from secrets import token_bytes
import crypto

class Client(nodes.Node):
    def __init__(self,node_id,ip,pubkey=None,prikey=None):
        super().__init__(node_id,ip,pubkey,prikey)

    def onion_encrypt(data,relnet,circuit,client,server):
        data=data.encode()
        key1=token_bytes(16)
        ciphertext1,tag1,nonce1=crypto.encrypt_data(data,key1)
        #encrypt_next(relnet[circuit['EXIT']],server,nonce1)
        ctkey1=crypto.pubkey_encrypt(key1,relnet[circuit['EXIT']].public_key)
        cttag1=crypto.pubkey_encrypt(tag1,relnet[circuit['EXIT']].public_key)
        ctnonce1=crypto.pubkey_encrypt(nonce1,relnet[circuit['EXIT']].public_key)

        key2=token_bytes(16)
        ciphertext2,tag2,nonce2=crypto.encrypt_data(ciphertext1,key2)
        #encrypt_next(relnet[circuit['MIDDLE']],Relnet[circuit['EXIT']],nonce1)
        ctkey2=crypto.pubkey_encrypt(key2,relnet[circuit['MIDDLE']].public_key)
        cttag2=crypto.pubkey_encrypt(tag2,relnet[circuit['MIDDLE']].public_key)
        ctnonce2=crypto.pubkey_encrypt(nonce2,relnet[circuit['MIDDLE']].public_key)

        key3=token_bytes(16)
        ciphertext3,tag3,nonce3=crypto.encrypt_data(ciphertext2,key3)
        #encrypt_next(server,,relnet[circuit['GUARD']],nonce1)
        ctkey3=crypto.pubkey_encrypt(key3,relnet[circuit['GUARD']].public_key)
        cttag3=crypto.pubkey_encrypt(tag3,relnet[circuit['GUARD']].public_key)
        ctnonce3=crypto.pubkey_encrypt(nonce3,relnet[circuit['GUARD']].public_key)
    
        return ciphertext3,((ctkey1, cttag1, ctnonce1), (ctkey2, cttag2, ctnonce2), (ctkey3, cttag3, ctnonce3))

    def encrypt_next(a,b,nonce):
        rel1=relnet[a]
        rel2=relnet[b]
        ctip,tag=encrypt_data(rel2.ip,key,nonce)
        rel1.set_next(ctip)
        rel2.set_pre(a)


    


        

    
        