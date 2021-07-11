from os import path
import nacl
from nacl.utils import random


class PersistentPairing:
    global PAIRING_PATH
    PAIRING_PATH = "./pairings/receiver/"

    def __init__(self, name):
        persistent_pairing_filepath = PAIRING_PATH + "accessory-secret-seed-" + name
        if not path.exists(persistent_pairing_filepath):
            pairing_secret_seed = random(nacl.bindings.crypto_sign_SEEDBYTES)
            persistent_pairing_file = open(persistent_pairing_filepath, "wb")
            persistent_pairing_file.write(pairing_secret_seed)
            persistent_pairing_file.close()
        else:
            persistent_pairing_file = open(persistent_pairing_filepath)
            pairing_secret_seed = persistent_pairing_file.read()
            persistent_pairing_file.close()

        self.pairing_ltsk = nacl.signing.SigningKey(pairing_secret_seed, encoder=nacl.encoding.RawEncoder)
        self.pairing_ltpk = bytes(self.accessory_ltsk.verify_key)

    @property
    def ltpk(self):
        return self.pairing_ltpk

    def ltsk(self):
        return self.pairing_ltsk
    
    def loadPublic(self, identifyer):
        persistent_pairing_file_path = PAIRING_PATH + identifyer.decode("utf-8") + ".pub"
        if path.exists(persistent_pairing_file_path):
            persistent_pairing_file = open(persistent_pairing_file_path, "rb")
            persistent_public = persistent_pairing_file_path.read()
            persistent_pairing_file.close()

            return persistent_public
        else:
            return False
        
    def savePublic(self, identifyer):
        persistent_pairing_file_path = PAIRING_PATH + identifyer.decode("utf-8") + ".pub"
        if path.exists(persistent_pairing_file_path):
            persistent_pairing_file = open(persistent_pairing_file_path, "rb")
            persistent_public = persistent_pairing_file_path.read()
            persistent_pairing_file.close()

            return persistent_public
        else:
            return False
