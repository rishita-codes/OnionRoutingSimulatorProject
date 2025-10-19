import nodes
import random

def set_connection(client,server,n):
    relnet={}
#    client=nodes.Relay('node100',1000)
#    server=nodes.Relay('node777',7777)
    relnet[client.ip]=client
    relnet[server.ip]=server
    for i in range(n):
        while True:
            ip=random.randint(100000,1000000)
            if ip not in relnet:
                break
        rel=nodes.Relay('node'+str(i+1),ip)
        #print(rel)
        relnet[ip]=rel
    print()
    #print(relnet)
    directory={}
    for i in relnet:
        directory[relnet[i].node_id]=i

    relay_ids=list(directory.keys())
    #print(relay_ids)
    #print(directory)

    relay_ids.remove(client.node_id)
    relay_ids.remove(server.node_id)
    #print(relay_ids)
    selected_relays=tuple(random.sample(relay_ids,k=3))
    #print(selected_relays)

    #for i in selected_relays:
        #print(relnet[directory[i]])

    circuit={}
    status=('GUARD','MIDDLE','EXIT')
    for i,j in zip(selected_relays,status):
        rel=relnet[directory[i]]
        rel.set_status(j)
        #print(rel.status)
        circuit[j]=rel.ip

    #print(circuit)

    def set_path(a,b):
        rel1=relnet[a]
        rel2=relnet[b]
        rel1.set_next(b)
        rel2.set_pre(a)


    #print(directory)
    set_path(client.ip,circuit['GUARD'])    
    set_path(circuit['GUARD'],circuit['MIDDLE'])
    set_path(circuit['MIDDLE'],circuit['EXIT'])
    set_path(circuit['EXIT'],server.ip)

    print('Setting up relay network: Done!')
    print('%15s %15s:'%('IP ADDRESS','NODE DATA'))
    for i in relnet:
        print('%15d:'%(i),relnet[i])
    return relnet,client,server,directory,circuit



