import os,sys
import rsa
import rc4


def WANNA_decrypt(orifile,privkey):
    if os.path.exists(orifile) is False:
        return
    newfile = orifile + ".ns.decrypt"
    with open(orifile, 'rb') as enc_file:
        enc = enc_file.read()
    p1 = enc.find('WannaRenkey')
    p2 = enc.find('WannaRen1')
    p3 = enc.find('WannaRen2')

    benc = p1==0 and p2 >0 and p3 > 0
    if benc == False:
        #print "file:%s is not encrypt"%orifile
        return
    print "decrypting %s"%(orifile)
    #rc4 key
    rc4_key = rsa.decrypt(enc[11:267], privkey).decode()  
    
    #rc4 decrypt
    #WannaRen1{data}WannaRen2
    data = enc[p2+9:-9]
    res = rc4.rc4(data,rc4_key)

    #save to new file
    #WannaRena{filedata}WannaRenb
    if res.find("WannaRena")<0 or res.find("WannaRenb") < 0:
        print "decrypt %s failed."%(orifile)
    with open(newfile,'wb') as n:
        n.write(res[9:-9])
    print "decrypt %s to %s"%(orifile, newfile)

def traveldir(path,key):
    if os.path.exists(path) is False:
        return
    if os.path.isfile(path):
        WANNA_decrypt(path,key)
        return
    dirs =  os.listdir(path)
    for file in dirs:
        file = os.path.join(path,file)
        if os.path.isdir(file):
            traveldir(file, key)
        else:
            WANNA_decrypt(file, key)
        

def main(key,path):
    with open(key, 'rb') as privatefile:
        p = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(p)

    traveldir(path, privkey)


if __name__ == "__main__":
    if len(sys.argv)<2:
        print "please input dir or file path"
        sys.exit()

    path = sys.argv[1]
    key = "./key"
    key = os.path.realpath(key)
    main(key, path)
    