import os
import shutil

class VaultStorage:
    def __init__(self):
        self.vault_path = ".secure_vault_data"
        if not os.path.exists(self.vault_path):
            os.makedirs(self.vault_path)

    def wipe_everything(self):
        if os.path.exists(self.vault_path):
            shutil.rmtree(self.vault_path)
            print("[!] EMERGENCY WIPE: Local data physically deleted.")