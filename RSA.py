import math
import random
import time
import profile
import sys


# this checks if a number is prime
# for the sake of speed it is done probabiliticly
# the probablitity of error is 1/2^(error*2)
# with the error set at 40 it is roughly as likely to be wrong as there is to be a mchine failure causing a wrong answer
# this can be set higher or lower for the sake of speed
def Miller_Rabin_prime(num, error = 40):
    rng = random.SystemRandom()
    d = num-1
    s = 0
    while d%2==0:
        d = d/2
        s+=1
    for a in rng.sample(xrange(2,2147000000),error):
        if pow(a,d,num)!=1:
            count = 0
            for r in xrange(0,s):
                if pow(a,(2**r)*d,num)!=num-1:
                    count +=1
                else:
                    break
            if count == s:
                return False
    return True

# this turns any string into a integer
# this is done by converting each letter/charecter into its ascii value (0-256)
# streching this to three digits
# and concatonating it to a integer
def getValueString(string):
    return int("".join([str(ord(item)).zfill(3) for item in list(string)]))

# this reverses the above function
# it adds 0s as nessesary becouse leading 0s are lost
def getStringValue(num):
    num = str(num)
    num = "0"*((3-(len(num)%3))%3)+num
    return "".join([chr(int(num[i:i+3])) for i in range(0, len(num), 3)])

# This selects a random prime in some range
def getRandomPrime(start,end):
    rng = random.SystemRandom()
    i = rng.randrange(start,end,2)
    while not Miller_Rabin_prime(i):
        i = rng.randrange(start,end,2)
    return i

# this function computes The GCD of two numbers and can be used to get the multiplicative modulo inverse
def extendedGCD(a,b):
    s = 0
    old_s = 1
    t = 1
    old_t = 0
    r = b
    old_r = a
    while r !=0:
        quotient = old_r/r
        old_r,r = r,old_r-quotient*r
        old_s,s = s,old_s-quotient*s
        old_t,t = t,old_t-quotient*t
    return old_r,old_s,old_t

#this will generate the public and private keys
def getKeys( bits = 1024):
    minprime,maxprime = 2**bits+1,2**(bits+1)-1
    p = getRandomPrime(minprime,maxprime)
    q = getRandomPrime(minprime,maxprime)
    n = p*q
    e = getRandomPrime(10001,99999)
    while e == p or e ==q:
        e = getRandomPrime(minprime,maxprime)
    d = extendedGCD(e,(p-1)*(q-1))[1] %((p-1)*(q-1))
    return (n,d),(n,e)

# to write the keys to files
def writeKeysToFile(privateKey, publicKey):
    with open("privateKey.txt","w") as f:
        f.write(str(privateKey[0])+"\n"+str(privateKey[1]))
    with open("publicKey.txt","w") as f:
        f.write(str(publicKey[0])+"\n"+str(publicKey[1])
    
)
# to encrypt a message
def encrypt(message,recieverPublicKey):
    encodedMessage = pow(getValueString(message),recieverPublicKey[1],recieverPublicKey[0])
    return encodedMessage

# to decrypt a message
def decrypt(encodedMessage, yourPrivateKey):
    message = pow(int(encodedMessage),yourPrivateKey[1],yourPrivateKey[0])
    return getStringValue(message)


def usage():
    print """usage
To generate your keys
python RSA.py getKeys [number of Bits]
To Encrypt a message
python RSA.py encrypt message <file location of their public key>
To Decrypt a message
python RSA.py decrypt  <encrypted Message location> <file location of your private key>
To print this message
python RSA>py -h
"""
       
if __name__ == '__main__':
    args = sys.argv
    if args[1] == "getKeys":
        if len(args) ==2:
            privateKey,publicKey = getKeys()
            writeKeysToFile(privateKey,publicKey)
        elif len(args)==3:
            try:
                privateKey,publicKey = getKeys(args[2])
                writeKeysToFile(privateKey,publicKey)
            except ValueError as e:
                usage()
                quit()
    elif args[1] == "encrypt":
        if len(args)!=4:
            usage()
        else:
            try:
                with open(args[3],"r") as f:
                    n = int(f.readline())
                    e = int(f.readline())
                    recieverPublicKey = (n,e)
                    with open("encryptedMessage.txt","w") as f:
                        f.write(str(encrypt(args[2],recieverPublicKey)))
            except IOError as e:
                usage()
    elif args[1] == "decrypt":
        if len(args)!=4:
            usage()
        else:
            try:
                with open(args[3],"r") as f:
                    n = int(f.readline())
                    d = int(f.readline())
                    privateKey = (n,d)
                    with open(args[2],"r") as f:
                        message = f.readline()
                    print decrypt(message,privateKey)
            except IOError as e:
                usage()
    else:
        usage()
                    
                
                
            



