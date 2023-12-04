import subprocess

from node import Node
from protocol import *

class Proxy(Node):
    def __init__(self, client, server):
        self.client = client
        self.server = server
    
    def forward(self):
        previous_result = 0
        while True:
            result = subprocess.run(
                ["adb", "shell", "content", "query", "--uri", "content://sms", "--projection", "body", "--where", f"\"address=\'{self.client}\'", "--sort", "\"date DESC\"", "|", 
                 "cut", "-d", "=", "-f", "2"],
                capture_output=True)
            smses = str(result.stdout, encoding="utf-8").split("\n")[:-1]
            
            try:
                smses.remove("No result found.")
            except ValueError:
                pass
            num_smses = len(smses)
           
            if num_smses > previous_result:
                new_smses = smses[:(num_smses - previous_result)]
                for sms in new_smses:
                    self.send_sms(self.server, sms)
            
            previous_result = num_smses

if __name__ == "__main__":
    proxy = Proxy("0123456789", "0123456789")
    proxy.forward()