from enum import IntEnum
import crypto
#from cryptography.fernet import Fernet

class NodeStatus(IntEnum):
    GUARD=1
    MIDDLE=2
    EXIT=3

class Node:
    def __init__(self,node_id,ip,pubkey=None,prikey=None):
        self.node_id=node_id
        self.ip=ip
        self.data=None
        self.next=None
        self.public_key=crypto.get_pub_key(self.node_id+"publickey.pem")
        self.private_key=crypto.get_pri_key(self.node_id+"privatekey.pem")
        self.pre=None
        self.nonce=None
        self.tag=None
        self.unboxed_data=None
        print(f'Setting up {self.node_id}: Done')      

    def __repr__(self):
        #return f"(node_id={self.node_id}, ip={self.ip}, pre={self.pre}, next={self.next})"
        return "(node_id=%10s, ip=%10s, pre=%10s, next=%10s)"%(self.node_id,self.ip,self.pre,self.next)

    def set_data(self,data):
        self.data=data

    def reset_data(self):
        self.data=None

    def set_next(self,next):
        self.next=next
        
    def reset_next(self):
        self.next=None

    def set_pre(self,pre):
        self.pre=pre
        
    def reset_pre(self):
        self.pre=None

    def unbox(self, ctkey, cttag, ctnonce):
        key=crypto.prikey_decrypt(ctkey,self.private_key)
        tag=crypto.prikey_decrypt(cttag,self.private_key)
        nonce=crypto.prikey_decrypt(ctnonce,self.private_key)
        plaintext=crypto.decrypt_data(self.data,key,tag,nonce)
        self.unboxed_data=plaintext
        return plaintext

        

class Relay(Node):
    def __init__(self,node_id,ip,pubkey=None,prikey=None):
        super().__init__(node_id,ip,pubkey,prikey)
        self.status=None
    def set_status(self,status: NodeStatus):
        self.status=status
    def get_status(self):
        return self.status
    def __repr__(self):
        return "(node_id=%10s, ip=%10s, pre=%10s, next=%10s, status=%10s)"%(self.node_id,self.ip,self.pre,self.next,self.status)
        
        

def main():    
    a=Node('kkkk99xx','10.20.10')
    b=Node('nnn88yy','11.23.100')
    d='this is the secret'
    a.data=d
    a.set_next(b)
    a.pass_data()
    print(b.data)
    

if __name__=="__main__":
    main()