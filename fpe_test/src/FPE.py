import Format
import Mode
import formatter
import fpe_csv
from utils import reverse

def generate_tweak(length):
    return formatter.mode_selector.ff1.get_random_bytes(length)

def generate_key():
    return formatter.mode_selector.ff1.get_random_bytes(16) 

class New:
    def __init__(self, key, tweak, mode):
        self.tweak = tweak
        self.mode = mode
        if mode == Mode.FF3:
            self.key = reverse(key)
        else:
            self.key = key

    def set_key(self,key):
        if mode == Mode.FF3:
            self.key = reverse(key)
        else:
            self.key = key

    def encrypt(self,text,dataFormat):
        return formatter.encrypt(text,self.key,self.tweak,dataFormat,self.mode)

    def decrypt(self,text,dataFormat):
        return formatter.decrypt(text,self.key,self.tweak,dataFormat,self.mode)

    def encryptCSV(self,csvFilePath,encryptedFilePath,formats):
        return fpe_csv.encrypt_csv(csvFilePath,encryptedFilePath,self.key,self.tweak,formats,self.mode)

    def decryptCSV(self,csvFilePath,decryptedFilePath,formats): 
        return fpe_csv.decrypt_csv(csvFilePath,decryptedFilePath,self.key,self.tweak,formats,self.mode)

    def generateData(self,csvFilePath,rows,formats,names):
        return fpe_csv.generate_test_data(csvFilePath,rows,formats,names,self.tweak,self.mode)  


