
"""
File last updated 20 April 2024
Version 0.3
"""


import pandas as pd
import numpy as np
import pickle

riscv_registers = {
    'r0': 'r0',
    'r1': 'r1',
    'r2': 'r2',
    'r3': 'r3',
    'r4': 'r4',
    'r5': 'r5',
    'r6': 'r6',
    'r7': 'r7',
    'r8': 'r8',
    'r9': 'r9',
    'r10': 'r10',
    'r11': 'r11',
    'r12': 'r12',
    'sp': 'sp',
    'lr': 'lr',
}

def return_instruction_type(instr):
    instr = str(instr).upper().strip()
    instr_base = instr.split('.')[0]

    arithmetic = {
        'ADC','ADCS','ADD','ADDS','ADDW',
        'SUB','SUBS','SUBW','SBC','SBCS','RSB','RSBS',
        'CMN','CMP','AND','ANDS','BIC','BICS',
        'EOR','EORS','ORN','ORNS','ORR','ORRS',
        'TEQ','TST','MOV','MOVS','MOVW','MOVT',
        'MVN','MVNS','LSL','LSLS','LSR','LSRS',
        'ASR','ASRS','ROR','RORS','RRX','RRXS',
        'CLZ','REV','REV16','REVSH','RBIT','ADR',
        'MUL','MULS','MLA','MLS','SDIV','UDIV',
        'SMULL','UMULL','SMLAL','UMLAL','UMAAL',
        'SMLAD','SMLADX','SMLABB','SMLABT','SMLATB','SMLATT',
        'QADD','QSUB','SSAT','USAT',
        'SXTB','SXTH','UXTB','UXTH','SBFX','UBFX'
    }

    load_store = {
        'LDR','LDRB','LDRH','LDRSB','LDRSH','LDRD','LDRT',
        'LDREX','LDREXB','LDREXH',
        'STR','STRB','STRH','STRD','STRT',
        'STREX','STREXB','STREXH',
        'LDM','LDMIA','LDMDB','LDMFD','LDMEA',
        'STM','STMIA','STMDB','STMFD','STMEA',
        'PUSH','POP'
    }

    branch_jump = {
        'B','BL','BX','BLX','CBZ','CBNZ','TBB','TBH',
        'BEQ','BNE','BCS','BCC','BMI','BPL',
        'BVS','BVC','BHI','BLS','BGE','BLT','BGT','BLE'
    }

    floating_point = {
        'VADD','VSUB','VMUL','VDIV','VABS','VCMP','VCMPE',
        'VCVT','VCVTR','VFMA','VFNMA','VFMS','VFNMS',
        'VLDR','VSTR','VLDM','VSTM','VMOV','VMRS','VMSR',
        'VNEG','VSQRT','VPOP','VPUSH'
    }

    system = {
        'BKPT','SVC','CPSID','CPSIE','DMB','DSB','ISB',
        'CLREX','MRS','MSR','NOP','SEV','WFE','WFI','IT'
    }

    if instr in arithmetic or instr_base in arithmetic:
        return "arithmetic"

    if instr in load_store or instr_base in load_store:
        return "load_store"

    if instr in branch_jump or instr_base in branch_jump:
        return "branch_jump"

    if instr in floating_point or instr_base in floating_point:
        return "floating_point"

    if instr in system or instr_base in system:
        return "system"

    return "other"

def HW(binary_string):
    """
    Computes the Hamming weight (number of 1s) in a binary string.
    """
    return binary_string.count('1')


def read_registers(s):
    """
    's' = sequence of registers from the log_file
    returns the split s
    """
    registers=s.split(',')
   
    rd=''
    op1=''
    op2=''
    if len(registers)== 3:
        rd=registers[0]
        op1=registers[1]
        op2=registers[1]
        return [rd, op1,op2]
    if len(registers)==0:
         return [rd, op1,op2]
    if len(registers)==1:
        rd=registers[0]
        return [rd, op1,op2]
    if len(registers)==2:
        rd=registers[0]
        if registers[1].startswith("-0x")or registers[1].startswith("0x"):
            op1=registers[1]
            return [rd, op1, op2]
        if registers[1].find('(')>0: 
            operands=registers[1].split('(')
            op1=operands[1][:2]
            return [rd, op1, op2]
        else:
            op1=registers[1]
            
            return [rd, op1, op2]
        
def process_line(line):
    """
    lines in a log file of an execution trace are strings
    this functions splits the string per distinct items
    """
    value=line.split('\t')
    type_value,extension_value= return_instruction_type(value[4].upper())
    reg=['','','']
    if len(value)>5:
        reg=read_registers(value[5])
        for index,r  in enumerate(reg):
            if r in list(riscv_registers.keys()):
                reg[index]=riscv_registers[reg[index]]
    
        row=[value[0],value[1].replace(' ',''), value[2],value[3],value[4],type_value,extension_value, reg[0],reg[1],reg[2],value[5], value[6]]
    else:
        row=[value[0],value[1].replace(' ',''), value[2],value[3],value[4],type_value,extension_value,reg[0],reg[1],reg[2],'','']
    return row

def translate_label(test):
    """
    pretty printing function translates 
    labels of the form 'x10,-36(x8)' into a0,-36(s0)
    """
    val=test.split(',')
    result=[]
    for v in val:
        if v in riscv_registers.keys():
            result.append(riscv_registers[v])
        elif v.find('(')>0: 
            temp=v[v.find('(')+1:v.find(')')]
            v=v[:v.find('(')+1]+riscv_registers[temp]+v[v.find(')'):]
            result.append(v)
        else:
             result.append(v)
    return ','.join(result)   


def add_index_column (df):
    df['Index']=range(0, len(df))
    return df   
def return_annoted_ins(bin_df, execution_trace_df):

    """
    Matches via the PC the function names in the binary file, with the executed instructions
    Parameters:
    - bin_df = the csv file corresponding to the elf file obtained with ACID
    - exection_trace_df= the csv file corresponding to the execution trace
    Returns:
    two lists, one with instruction number and second with the functions executed at these cycles
    """
    #part 1
    #use the bin_file_csv to identify the PC  for each function (basically splitting the values in the column "Selected")
    fct_label=[]
    fct_pc=[]
    function_pc=bin_df['Selected'].unique()
    for f in function_pc:
        temp=f.split('@')
        fct_label.append(temp[0])
        fct_pc.append(temp[1])
    
    #part 2 
    ins_annotation=[]
    label_annotation=[]
    for val, label in zip(fct_pc, fct_label):
        #print(val[7:])
        location_pc=execution_trace_df[execution_trace_df['PC']=='0x'+val[7:]]
        #print(location_pc)
        for l in location_pc['Index']:
            ins_annotation.append(l)
            label_annotation.append(label)
    s_index,s_data=sort_data_by_index(ins_annotation,label_annotation)
    return s_index,s_data
def sort_data_by_index(index_list, data_list):
    """
    Sorts the data_list based on the values of index_list.
    Parameters:
    - index_list: A list of indices based on which sorting should be performed.
    - data_list: A list of data corresponding to each index in index_list.

    Returns:
    - A list of data sorted based on index_list.
    """
    # Pair each index with the corresponding data and sort the pairs
    paired_sorted = sorted(zip(index_list, data_list), key=lambda x: x[0])

#     # Extract the sorted data from the sorted pairs
    sorted_data = [data for _, data in paired_sorted]
    sorted_index = [index for index, _ in paired_sorted]

    return  sorted_index,sorted_data

def add_index_column (df):
    df['Index']=range(1, len(df) + 1)
    return df

def search_value(df, column_name, value):
    """
    Search for a value in a DataFrame column and return the entire row(s) where the value appears.

    Parameters:
    - df (pd.DataFrame): The DataFrame to search in.
    - column_name (str): The name of the column to search the value in.
    - value: The value to search for in the column.

    Returns:
    - pd.DataFrame: A DataFrame containing the rows where the value was found.
    """
    # Use the boolean indexing to filter rows
    result_df = df[df[column_name] == value]
    return result_df

def search_intermediate(df, column_name, value, lower_bound, upper_bound):
    """
    Search for a value in a DataFrame column and return the entire row(s) where the value appears.

    Parameters:
    - df (pd.DataFrame): The DataFrame to search in.
    - column_name (str): The name of the column to search the value in.
    - value: The value to search for in the column.

    Returns:
    - pd.DataFrame: A DataFrame containing the rows where the value was found.
    """
    # Use the boolean indexing to filter rows
    result=search_value(df,column_name, value)  
    result_filter= result[(result['Index'] >= lower_bound) & (result['Index'] <= upper_bound)]
    return result_filter


def filter_data(data, value_to_search, columns_to_search): # Value to search for
    # Search across specific columns and return boolean mask
    result_mask = data[columns_to_search].apply(lambda row: row.isin([value_to_search]).any(), axis=1)

    # Filter DataFrame based on the mask to get only rows where the value is found in the specified columns
    filtered_df = data[result_mask]
    filtered_seq = filtered_df['Index'].tolist()
    return filtered_seq

def find_value_positions(df, value):
    positions = {}
    for col in df.columns:
        # Use `.eq()` for elementwise comparison and then check if any true exists in the column
        if df[col].eq(value).any():
            row_indices = df.index[df[col] == value].tolist()  # Get all row indices for value in column
            positions[col] = row_indices
    return positions
#find_value_positions(df_1, SB_1[1])

# def intersect_dicts(dict1, dict2):
#     # Use dictionary comprehension to find intersection
#     return {k: dict1[k] for k in dict1 if k in dict2 and dict1[k] == dict2[k]}

def intersection_lists(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3

def intersect_instruction_dict(dict1, dict2):
    intersect_dict={}
    for k in dict1.keys():
        #print('k1', k, dict1[k], '\n')
        if(k in dict2.keys()):
            #print(dict1[k], dict2[k])
            #print('k2', k, dict1[k], '\n')
            intersect_dict[k] = intersection_lists(dict1[k], dict2[k])
    return intersect_dict
    
def count_consecutive_values(lst):
    """
    This function returns the count of consecutive number ranges in a list.
    """
    if not lst:  # If list is empty, return 0
        return 0
    count = 1  # Initialize count with 1 for the first range
    for i in range(1, len(lst)):
        if lst[i] != lst[i-1] + 1:
#             print(lst[i])
            count += 1  # Increment count whenever a new range is identified
    return count
     
def count_consecutive_values_dict(dicti):
    """
    This function returns the count of consecutive number ranges in a list.
    """
    count=0
    for k in dicti.keys():
        count+=count_consecutive_values(dicti[k])
    return count

def add_index_column (df):
    df['Index']=range(0, len(df) + 0)
    return df
# def remove_ghost_values(TI1,TI2,TI3, trace_1, trace_2, trace_3, path, opt_level):
#     '''
#     TI1, TI2, TI3 are the computed values of the target intermediates
#     df1, df2, df3, are the dataframes which load the execution traces
#     opt_level and path determine the name of where we write to files
#     '''

#     df1 = pd.read_csv(trace_1)
#     add_index_column (df1)

#     add_index_column(df3)
#     N=len(M1)
#     for i in range(N):
#         instruction_dict_1 = find_value_positions(df1, TI1[i])
#         instruction_dict_2 = find_value_positions(df2, TI2[i])
#         instruction_dict_3 = find_value_positions(df3, TI3[i])    
    
#         filename_1 = path + opt_level + '_instruction_seq_byte-' + str(i) + '_1.pkl'
#         with open(filename_1, 'wb') as f:
#             pickle.dump(instruction_dict_1, f)

#         #filename_all = 'interim_values/MASKS/AES_M_' + opt_level + '_instruction_seq_byte-' + str(i) + '_masks_M2.pkl'
#         filename_2 = path + opt_level + '_instruction_seq_byte-' + str(i) + '_2.pkl'
#         with open(filename_2, 'wb') as f:
#             pickle.dump(instruction_dict_2, f)
        
#         filename_3 = path + opt_level + '_instruction_seq_byte-' + str(i) + '3_.pkl'
#         #filename_all = 'interim_values/MASKS/AES_M_' + opt_level + '_instruction_seq_byte-' + str(i) + '_masks_M3.pkl'
#         with open(filename_3, 'wb') as f:
#             pickle.dump(instruction_dict_3, f)
#         intersection_filename = path + opt_level + '_instruction_seq_byte-' + str(i) + '_all.pkl'
#         intersection_result = intersect_instruction_dict(instruction_dict_1, intersect_instruction_dict(instruction_dict_2, instruction_dict_3))
#         with open(intersection_filename, 'wb') as f:
#             pickle.dump(intersection_result, f)   df2 = pd.read_csv(trace_2)
#     add_index_column(df2)
    
#     df3 = pd.read_csv(trace_3)
 
def compute_persistance_byte(target_byte, dicti_result):
    sum_len = 0
    for k in dicti_result.keys():
        sum_len = sum_len + len(dicti_result[k])
    return sum_len
         
def compute_persistance_all(TI, path, opt_level):
    N=len(TI)
    for i in range(N):
        intersection_filename = path + opt_level + '_instruction_seq_byte-' + str(i) + '_all.pkl'
        with open(intersection_filename, 'rb') as f:
            intersection_result = pickle.load(f)
            p=compute_persistance_byte(i, intersection_result)
        print("byte", i, "persistance = ", p)



def remove_ghost_values(TI1,TI2,TI3, trace_1, trace_2, trace_3, path, opt_level):
    '''
    TI1, TI2, TI3 are the computed values of the target intermediates
    df1, df2, df3, are the dataframes which load the execution traces
    opt_level and path determine the name of where we write to files
    '''

    df1 = pd.read_csv(trace_1)
    add_index_column (df1)

    df2 = pd.read_csv(trace_2)
    add_index_column(df2)
    
    df3 = pd.read_csv(trace_3)
    add_index_column(df3)
    N=len(TI1)
    for i in range(N):
        instruction_dict_1 = find_value_positions(df1, TI1[i])
        instruction_dict_2 = find_value_positions(df2, TI2[i])
        instruction_dict_3 = find_value_positions(df3, TI3[i])    
    
        filename_1 = path + opt_level + '_instruction_seq_byte-' + str(i) + '_1.pkl'
        with open(filename_1, 'wb') as f:
            pickle.dump(instruction_dict_1, f)

        #filename_all = 'interim_values/MASKS/AES_M_' + opt_level + '_instruction_seq_byte-' + str(i) + '_masks_M2.pkl'
        filename_2 = path + opt_level + '_instruction_seq_byte-' + str(i) + '_2.pkl'
        with open(filename_2, 'wb') as f:
            pickle.dump(instruction_dict_2, f)
        
        filename_3 = path + opt_level + '_instruction_seq_byte-' + str(i) + '_3.pkl'
        #filename_all = 'interim_values/MASKS/AES_M_' + opt_level + '_instruction_seq_byte-' + str(i) + '_masks_M3.pkl'
        with open(filename_3, 'wb') as f:
            pickle.dump(instruction_dict_3, f)
        intersection_filename = path + opt_level + '_instruction_seq_byte-' + str(i) + '_all.pkl'
        intersection_result = intersect_instruction_dict(instruction_dict_1, intersect_instruction_dict(instruction_dict_2, instruction_dict_3))
        with open(intersection_filename, 'wb') as f:
            pickle.dump(intersection_result, f)

def compute_persistance_byte(target_byte, dicti_result):
    sum_len = 0
    for k in dicti_result.keys():
        sum_len = sum_len + len(dicti_result[k])
    return sum_len
         
def compute_persistance_all(TI, path, opt_level):
    N=len(TI)
    for i in range(N):
        intersection_filename = path + opt_level + '_instruction_seq_byte-' + str(i) + '_all.pkl'
        with open(intersection_filename, 'rb') as f:
            intersection_result = pickle.load(f)
            p=compute_persistance_byte(i, intersection_result)
        print("byte", i, "persistance = ", p)
def count_revive(M1, path, opt_level):
    N=len(M1)
    for i in range(N):
        intersection_filename = path + opt_level + '_instruction_seq_byte-' + str(i) + '_all.pkl'
        with open(intersection_filename, 'rb') as f:
            intersection_result = pickle.load(f)
            print("Byte ", i, " revive = ", count_consecutive_values_dict(intersection_result)) 
def print_TI_index_all(TI, path, opt_level):
    """
    a nice visualization index
    """
    N=len(TI)
    print(N)
    for i in range(N):
        intersection_filename = path + opt_level + '_instruction_seq_byte-' + str(i) + '_all.pkl'
        #print(intersection_filename)
        #print(" ", i, "\n-------")
        with open(intersection_filename, 'rb') as f:
            intersection_result = pickle.load(f)
            print( i, "Persistance: ", compute_persistance_byte(i, intersection_result))
            for k in intersection_result.keys():
                if len(intersection_result[k])>0:
                    print(" ", k, "index", intersection_result[k]) 
def print_TI_index(TI, path, opt_level, ending='_1'):
    """
    a nice visualization index
    """
    index=[]
    N=len(TI)
    for i in range(N):
        intermediate_filename = path + opt_level + '_instruction_seq_byte-' + str(i) + ending+'.pkl'
        #print(" ", i, "\n-------")
        with open(intermediate_filename, 'rb') as f:
            intersection_result = pickle.load(f)
            index.add(compute_persistance_byte(i, intersection_result))
    return index
            #print( i,"Persistance: ", )
            # for k in intersection_result.keys():
            #     if len(intersection_result[k])>0:
            #         print(" ", k, "index", intersection_result[k]) 
def hex2list (input_string):
    """
    Split the string into chunks of 2 characters, then prefix each with '0x'
    """
    return  [f'0x{input_string[i:i+2]}' for i in range(0, len(input_string), 2)]

def create_ID_trace(filename,cols):
      """
      reads an execution trace in csv format 
      returns 
      - the ID or the sum of  the content of all registers for each instruction
      - the total number of instructions

      """
      df = pd.read_csv(filename)
      df.fillna('', inplace=True)
      reg = df[cols]
      # convert hex register values to binary and decimal values
      reg_dec=[]
      for col in cols:
          reg_dec.append(reg[col].apply(lambda x: int(x,16)))
      number_instructions = len(reg_dec[0])# number of instructions
      ID_ref = np.zeros((number_instructions ,len(cols)))
      for col in range(len(cols)):
        for i in range(number_instructions ):
            ID_ref[i,col] = reg_dec[col][i]
      return  np.sum(ID_ref,axis=1)



def create_HW_trace(filename,cols):
      """
      reads an execution trace in csv format 
      returns 
      - the hamming weight of  the content of all registers for each instruction
      - the total number of instructions

      """
      df = pd.read_csv(filename)
      df.fillna('', inplace=True)
      #cols = ['zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1','t2', 's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 's2',
      #  's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 't3', 't4','t5', 't6']
     #cols = ['t1', 's0', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 't3']
      reg = df[cols]
      # convert hex register values to binary and decimal values
      reg_bin=[]
      for col in cols:
          reg_bin.append(reg[col].apply(lambda x: bin(int(x,16))[2:]))

      number_instructions = len(reg_bin[0])# number of instructions
      hw_ref = np.zeros((number_instructions ,len(cols)))
      for col in range(len(cols)):
        for i in range(number_instructions ):
            hw_ref[i,col] = HW(reg_bin[col][i])
      return  np.sum(hw_ref,axis=1)


def find_index(lst, item):
    """
    Returns the index of the first occurrence of `item` in `lst`.
    Raises ValueError if the item is not found.
    """
    return [i for i, x in enumerate(lst) if x == item]

def print_code(df, index_1, count, registers=['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr']):
    """
    select the rows between index_1 and index_2 from the 'filename' and print the PC, instruction and operands
    example usage:
        print_code(filename, 5000, 5010)
    """
    indices=range(index_1,index_1+count)
    #selected_rows = df.iloc[indices][['PC','Ins','Operands','r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr']]
    selected_rows = df.iloc[indices][registers]
    
    print(selected_rows)
    
def extract_row(df, index,registers=['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr']):
    pc_value = df.loc[index]['PC']
    list = df.loc[index][registers].tolist()
    return pc_value, list
def return_register_index(val,registers=['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr']):
    """
    This function returns the index of 'val' in the 'selected_registers_list
    example usage: return_register_index('a4')=14
    """
    count=0
    for elem in registers:
        if elem==val:
            return count
        count+=1
    #print('Register index:',count)
    return count
def extract_row_reg(df,index,reg,registers=['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr']):
    """
    This function extracts the value of the 'reg' row at the given 'index' from the 'filename'
    example usage:
        extract_row_reg(filename, 100, 'a4')
    """

    pc_value,list=extract_row(df,index)
    temp=return_register_index(reg)
    return pc_value,reg ,list[temp]