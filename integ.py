import clientmod
import crypto
import networking
import nodes

print("\n**************ONION ROUTING SIMULATOR**************\n\n")
pt=input("Enter request to be sent to the server:\n--> ")

print()
client=clientmod.Client('client',10000)
server=nodes.Node('server',77777)
client.data=pt

n=5
relnet,client,server,directory,circuit=networking.set_connection(client,server,n)
guardn=relnet[circuit['GUARD']]
middlen=relnet[circuit['MIDDLE']]
exitn=relnet[circuit['EXIT']]
# return (ctkey1, cttag1, ctnonce1), (ctkey2, cttag2, ctnonce2), (ctkey3, cttag3, ctnonce3)
ct3,rels=clientmod.Client.onion_encrypt(pt,relnet,circuit,client,server)
r1,r2,r3=rels

guardn.data=ct3
#print(ct3,guardn.data,sep='\n\n')
ct2=guardn.unbox(r3[0], r3[1], r3[2])

middlen.data=ct2
ct1=middlen.unbox(r2[0], r2[1], r2[2])

exitn.data=ct1
ptn=exitn.unbox(r1[0], r1[1], r1[2])

#print(ct3,ct2,ct1,pt,sep='\n\n')
server.data=ptn.decode()
#print(server.data)
print(f'\nData with each node:\nclient:\n\t{client.data}\nguard node:\n\t{guardn.data}\n\t{guardn.unboxed_data}\nmiddle node:\n\t{middlen.data}\n\t{middlen.unboxed_data}\nexit node:\n\t{exitn.data}\n\t{exitn.unboxed_data}\nserver:\n\t{server.data}\n')
