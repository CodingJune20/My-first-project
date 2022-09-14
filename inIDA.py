import idaapi
import idc
import idautils

import os
import sys
import subprocess
from tqdm import *

#To import capstone, append python path
conda_path = os.path.expanduser('~') + "\\anaconda3\\lib\\site-packages"
pip_path = []
pip_path.append(conda_path)
pip_path.append("C:\\Program Files\\Python38\\Lib\\site-packages")

# If you have module import Error, Please add path of python you used when install pip 

your_path = ""  #ex "C:\\Users\\admin ..." or r"C:\Users\admin..."
pip_path.append(your_path)


for pip in pip_path:
    sys.path.append(pip)

try:
    from capstone import *
    import requests

except ModuleNotFoundError:
   
    print("""
        There is no path, Then Follow the guide
            1. find the pip install path
                At you install requirements (opne the python with it)
                $ import site
                $ site.getsitepackages()

                then find path end with 'side-packages'
            
            2. Add path to the 'your_path'
    """)
    
    raise Exception("There aren't pip path is added!")

    exit()
    

class Normalization():
    
    def __init__(self):
        self.normalized_instns = []
        self.corpus_data = {}


    def disassemble_and_normalize_instructions(self, func_asm_list,func_add_list):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        if len(func_asm_list) > 0 : #asm_list has been made?
            for i in range(len(func_asm_list)):
                normalized_instrucntions = ''
                CODE = func_asm_list[i]
                for j in md.disasm(CODE, func_add_list[i]):
                    opcode = j.mnemonic
                    
                    #passing nop
                    if opcode == 'nop':
                        continue


                    try:
                        operands_str = j.op_str
                        operands = [x.strip() for x in operands_str.strip().split(',')]

                        normalized_instr = opcode if len(operands_str) == 0 \
                                else str(opcode + '_' + '_'.join(operands))
                        normalized_instrucntions += normalized_instr + ', '
                        self.normalized_instns.append(normalized_instr)

                    except AttributeError:
                        print("Error is created on operands parts")
                        pass

                    if len(normalized_instrucntions) > 0:
                        self.corpus_data[func_add_list[i]] = normalized_instrucntions[:-2]
                    
        else:  
            print("There is no function name(sub_) in text")

    def preprocessing(self,path):
        corpus = open(path, encoding='utf-8').read().split('\n')

        new_extracted_list = [i.split('\t') for i in corpus]    

        
        function_name_list = [i[0] for i in new_extracted_list if i[0] != '']
        function_body_list = [i[1] for i in new_extracted_list if i[0] != '']
    

        function_name_list = [i.replace('_', ' ').lstrip() for i in function_name_list]
        function_name_list = [i.replace('  ', ' ') for i in function_name_list]
        function_body_list = [i.replace(' + ', '+') for i in function_body_list]
        function_body_list = [i.replace(' - ', '-') for i in function_body_list]
        function_body_list = [i.replace(' ', '_') for i in function_body_list]
        function_body_list = [i.replace(',_', ', ') for i in function_body_list]

        function_body_list = [i for i in function_body_list if i]
        function_name_list = [i for i in function_name_list if i]


        #print("Removing number token ...")
        for i, name in enumerate(function_name_list):
            temp_name_list = name.split(' ')
            for j, tok in enumerate(temp_name_list):
                if tok.isnumeric():
                    temp_name_list.pop(j)
            temp_name = " ".join(temp_name_list)
            function_name_list[i] = temp_name

        nero_code = []
        nero_text = []

        for com_idx in range(0, len(function_name_list)):
            nero_code.append(function_body_list[com_idx])
            nero_text.append(function_name_list[com_idx])

        set_of_code = set(nero_code)
        
        remove_different_code = True
        if remove_different_code == True:
            for s in set_of_code:
                tmp = ''
                # remove codes that has different function name but same code.
                for i, code in enumerate(nero_code):
                    if s == code and tmp == '':
                        tmp = nero_text[i]
                    elif s == code and tmp != nero_text[i]:
                        nero_code[i] = None
                        nero_text[i] = None

        #print("Removing None values...")
        nero_text_res = [i for i in nero_text if i]
        nero_code_res = [i for i in nero_code if i]

        final = []
        for t, c in zip(nero_text_res, nero_code_res):
            final.append([t,c])

        # make [function_name, code] unique
        final = list(tuple([tuple(i) for i in final]))

        with open("./source.txt", mode='w', encoding='utf-8') as out:
            for c in final:
                out.write(c[1]+'\n')
        '''
        with open("./target.txt", mode='w', encoding='utf-8') as out:
            for c in final:
                out.write(c[0]+'\n')
        '''
        for i,c in enumerate(final):        
            self.corpus_data[func_add_list[i]] = c[1]

if __name__ == "__main__":

    #start and end point of 'text'
    for seg in idautils.Segments():
        if(idc.get_segm_name(seg) == '.text'):
            text_start_ea = idc.get_segm_start(seg)
            text_end_ea = idc.get_segm_end(seg)



    # Read byte codes in each function
    func_dict = {}
    func_name_list = []
    func_add_list = []
    func_asm_list = []
    for func in idautils.Functions():
        func_start_ea = idc.get_func_attr(func,FUNCATTR_START)
        func_end_ea = idc.get_func_attr(func, FUNCATTR_END) 
        func_name = idc.get_func_name(func)
        if func_start_ea >= text_start_ea and func_end_ea <= text_end_ea and 'sub_' in func_name:
            func_add_list.append(func_start_ea)
            asmcode = b''
            cur_addr = func_start_ea
            while cur_addr <= func_end_ea:
                asmcode += idc.get_bytes(cur_addr,idc.get_item_size(cur_addr))
                cur_addr = idc.next_head(cur_addr,func_end_ea)
            func_asm_list.append(asmcode)
            func_dict[func_start_ea] = asmcode
            func_name_list.append(func_name)



    
    ida_path = idaapi.get_user_idadir() + "\\plugins\\AsmDepictor"
    os.chdir(ida_path)

    data_name = idaapi.get_root_filename()

    #Nomralize
    nn = Normalization()
    nn.disassemble_and_normalize_instructions(func_asm_list,func_add_list)

    with open("./" + data_name + ".txt", mode = 'w', encoding= 'utf-8' ) as out:
        for i,func_add in enumerate(func_add_list):
            out.write(func_name_list[i] +"\t" + nn.corpus_data[func_add]+"\n")
    nn.preprocessing("./" + data_name+ ".txt")


    command = "subword-nmt apply-bpe --codes ./pretrained_voca.voc --input ./source.txt --output ./source_bpe.txt"
    res = subprocess.call(command)

    with open("./source_bpe.txt", mode= 'r') as out:
        lines = out. readlines()
        for i,line in enumerate(lines):
            line = line.strip()
            func_asm_list[i] = line


    fail_cnt = 0
    success_cnt = 0
    # Change function name
    print("\nDeducing function name...")
    for i in tqdm(range(len(func_add_list))):
        code_ex = func_asm_list[i]
        response = requests.post("http://115.145.172.80:30303/predictions/AsmDepictor", json={'code': code_ex}).text
        if response.startswith("{"):
            idaapi.force_name(func_add_list[i],"_________",SN_NOCHECK)
            fail_cnt += 1
            continue
        idaapi.force_name(func_add_list[i], "@@"+response, SN_NOCHECK)
        success_cnt += 1
    # Remove files
    print("\nRemoving additional file...")
    if os.getcwd() == ida_path:
        for file in tqdm(os.listdir()):
            if file == "inIDA.py" or file == "pretrained_voca.voc":
                continue
            os.remove(file)

    print(f"[+] {success_cnt} function success to deduce name")
    print(f"[-] {fail_cnt} function failed to deduce name")

