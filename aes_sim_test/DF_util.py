import pandas as pd


def print_code(df, index_1, count, registers=['PC','Ins','r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr']):
    """
    select the rows between index_1 and index_2 from the 'filename' and print the PC, instruction and operands
    example usage:
        print_code(filename, 5000, 5010)
    """
    indices=range(index_1,index_1+count)
    #selected_rows = df.iloc[indices][['PC','Ins','Operands','r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr']]
    selected_rows = df.iloc[indices][registers]
    
    print(selected_rows)
   


selected_registers = ['r0', 'r1', 'r2', 
                             'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9',
                             'r10', 'r11', 'r12', 'sp', 'lr', 'pc']
#***********************************************************    
def return_register_index(val,sr=selected_registers):
    """
    This function returns the index of 'val' in the 'selected_registers_list
    example usage: return_register_index('a4')=14
    """
    count=0
    for elem in sr:
        if elem==val:
            return count
        count+=1
    #print('Register index:',count)
    return count
#***********************************************************
def compare_registers(row_1, row_2, sr=selected_registers):
    """
    This function compares two lists and prints the registers that are different
    it returns the count of different registers and the list of different registers
    """
    count = 0
    diff_list = []
    for i, j,k in zip(row_1, row_2,range(len(row_1))):   
        if i != j:
            count+=1
            diff_list.append(sr[k])
    return count, diff_list
#***********************************************************  
def HW(x):
    return sum([x&(1<<i)>0 for i in range(32)])
#***********************************************************  
def HW_row(row1):
   """
   Computes the hamming distance between the values in two lists (the values in lists are in strings hex format, e.g., '0x12')
   """
   sum=0
   for i in row1:
    temp=HW(int(i,16))
    sum+=temp
   return sum
#***********************************************************
def return_HW_trace(df,index1,index2,sr=selected_registers):
    """Computes the HD trace, when given the dataframe of an execution file between two"""
    hw_trace=[]
    #pc_value = df['PC']
    for i in range(index1,index2):
        row_1=  df.loc[i][sr].tolist()
        hw=HW_row(row_1)
        hw_trace.append(hw)
    return hw_trace
#***********************************************************  
def myHD(a,b):
    """
    Computes the hamming distance between two integers
    """
    hd = 0
    diff = a^b
    while diff:
        hd += diff & 1
        diff >>= 1
    return hd
#***********************************************************
def HD_rows(row1, row2):
   """
   Computes the hamming distance between the values in two lists (the values in lists are in strings hex format, e.g., '0x12')
   """
   diff=[]
   for (i,j) in zip(row1,row2):
     temp=myHD(int(i,16),int(j,16))
     diff.append(temp)
   return sum(diff), diff
#***********************************************************
def return_HD_trace(df,index1,index2,sr=selected_registers):
    """Computes the HD trace, when given the dataframe of an execution file between two"""
    hd_trace=[]
    #pc_value = df['PC']
    for i in range(index1,index2):
        row_1=  df.loc[i][sr].tolist()
        row_2=  df.loc[i+1][sr].tolist()
        hd, _=HD_rows(row_1,row_2)
        hd_trace.append(hd)
    if index2==len(df)-1:
        hd_trace.append(0)
    return hd_trace
#***********************************************************
def extract_row(filename, index,sr=selected_registers ):
    """
    This function extracts the row at the given 'index' from the 'filename'
    returns the PC value and the content of the register values at this index
    example usage: 
        pc,list=extract_row(filename, 100)
        print(pc, list)
    """
    df=pd.read_csv(filename)
    pc_value = df.loc[index]['PC']
    list = df.loc[index][sr].tolist()
    return pc_value, list
#***********************************************************
def extract_row_reg(filename,index,reg,sr=selected_registers):
    """
    This function extracts the value of the 'reg' row at the given 'index' from the 'filename'
    example usage:
        extract_row_reg(filename, 100, 'a4')
    """
    # df=pd.read_csv(filename)
    # pc_value = df.loc[index]['PC']
    # list = df.loc[index][sr].tolist()
    pc_value,list=extract_row(filename,index,sr)
    temp=return_register_index(reg)
    #print(temp)
    return pc_value,reg ,list[temp]
#***********************************************************
def return_PC_index(filename, PC_value):
    """
    This function returns the index of the given 'PC_value' in 'filename'
    If the 'PC_value' is not found, it returns an empty list.
    example usage: 
        return_PC_index(ref_f_M0, '0xc84')
    """
    df_ref=pd.read_csv(filename)
    index_value=[]
    filtered_df = df_ref[df_ref['pc'] == PC_value]
    index_value = filtered_df.index
    return index_value
#***********************************************************
#def print_code(filename, index_1, index_2, HD=True, HW=True):
    # """
    # select the rows between index_1 and index_2 from the 'filename' and print the PC, instruction and operands
    # example usage:
    #     print_code(filename, 5000, 5010)
    # """
    # df=pd.read_csv(filename)
    # indices=range(index_1,index_2)
    # count_list=[]
    # count_list_reg=[]
    # selected_rows = df.iloc[indices][['PC','Ins','Operands']]
    # if HD:
    #     selected_rows['HD']=return_HD_trace(df, index_1, index_2)
    # if HW:
    #     selected_rows['HW']=return_HW_trace(df, index_1, index_2)
    # print(selected_rows)
#***********************************************************
def compare_rows(filename_1, filename_2, index, sr=selected_registers):
    """
    This function compares the row at 'index' in filename_1 and filename_2
    it returns the count of different registers and the list of different registers
    """
    row_1=extract_row(filename_1, index)
    row_2=extract_row(filename_2, index)
    # list_t1=return_register_values_index(trace_1, index)
    # list_t2=return_register_values_index(trace_2, index)
    return compare_registers(row_1, row_2,selected_registers)
#***********************************************************
def compare_code(filename_1, filename_2,index_1, index_2, sr=selected_registers):
    """
    Filename_1 and filename_2 are two execution traces generated for the same binary
    Compares the registers values of two files between instructions in the given range
    Returns a table which contains the 
        PC|instruction|operands|Updated_Reg|count|diff_list 
    """
    df_1=pd.read_csv(filename_1)
    df_2=pd.read_csv(filename_2)
    #df_tvla=pd.read_csv(tvla_file)
    indices=range(index_1,index_2)
    count_list=[]
    count_list_reg=[]
    diff_list=[]
    for index in indices:
        row_1=df_1.loc[index][sr].tolist()
        row_2=df_2.loc[index][sr].tolist()
        c,v_temp=compare_registers(row_1, row_2)
        count_list_reg.append(','.join(v_temp))
        count_list.append(c)
 
    selected_rows = df_1.iloc[indices][['PC','ins','operands']]
    #selected_rows = df_1.iloc[indices][['PC']]
    selected_rows['Updated_Reg']=count_list_reg # list of registers updated between two instructions
    selected_rows['count']=count_list
    #selected_rows['diff_list']=diff_list 
    #tvla_score=df_tvla.iloc[indices]['T-Score'].tolist()
    #selected_rows['tvla_score']=tvla_score
    print(selected_rows)
#***********************************************************
def return_PC_index(df_ref, PC_value):
    """
    This function returns the index of the given 'PC_value' in 'filename'
    If the 'PC_value' is not found, it returns an empty list.
    example usage: 
        return_PC_index(ref_f_M0, '0xc84')
    """
    #df_ref=pd.read_csv(filename)
    index_value=[]
    filtered_df = df_ref[df_ref['pc'] == PC_value]
    index_value = filtered_df.index
    return index_value
def read_params(filename):
    data = {}

    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if not line:          # skip empty lines
                continue

            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()

    return data
#***********************************************************
def strip_w_ext(instrs):
    return [ins.removesuffix(".w") for ins in instrs]
#***********************************************************
def save_list(filename, lst):
    """## save list of integers to a file

    ### Args:
        - `filename (_type_)`: _description_
        - `lst (_type_)`: _description_
    """
    with open(filename, "w") as f:
        f.write("\n".join(map(str, lst))) 
#***********************************************************
def load_list(filename):
    """## load list of integers from a file

    ### Args:
        - `filename (_type_)`: _description_
        - `lst (_type_)`: _description_
    """
    with open(filename) as f:
        return [int(line.strip()) for line in f]
    
#***********************************************************
def find_sequence(df, col, pattern):
    seq = strip_w_ext(df[col].tolist())
    m = len(pattern)

    return [
        i for i in range(len(seq) - m + 1)
        if seq[i:i+m] == pattern
    ]