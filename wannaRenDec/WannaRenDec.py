import os,sys
import rsa
import rc4


def WANNA_decrypt(orifile,privkey, out):
    if os.path.exists(orifile) is False:
        return
    newfile =  os.path.join(out,os.path.basename(orifile))
    if newfile.endswith('.WannaRen'):
        newfile = newfile[:-9]

    #for big file hang
    with open(orifile, 'rb') as enc_file:
        enc = enc_file.read(11)
        if enc != 'WannaRenkey':
            return

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

def traveldir(path,key, out):
    if os.path.exists(path) is False:
        return
    if os.path.isfile(path):
        WANNA_decrypt(path,key, out)
        return

    #no permission
    try:
        dirs =  os.listdir(path)
    except Exception as e:
        print "check dir %s, Error: %s"%(path, e)
        return

    for file in dirs:
        file = os.path.join(path,file)
        try:
            if os.path.isdir(file):
                print "check dir %s"%(file)
                traveldir(file, key, out)
            else:
                WANNA_decrypt(file, key, out)
        except Exception as e:
            print "check %s. Error:%s"%(file, e)


def main(key,path, out):
    with open(key, 'rb') as privatefile:
        p = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(p)

    traveldir(path, privkey, out)
    print "check dir %s end"%(path)


if __name__ == "__main__":
    if len(sys.argv)<2:
        print "please input dir or file path"
        sys.exit()

    path = sys.argv[1]
    key = "./key"
    out = "./decrypt_out"
    key = os.path.realpath(key)
    path = os.path.realpath(path)
    out = os.path.realpath(out)
    if os.path.exists(out) is False:
        os.makedirs(out)

    main(key, path, out)
    print "Output path: %s"%(out)
