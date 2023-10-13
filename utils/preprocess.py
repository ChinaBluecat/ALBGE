import re
import time
import copy
from tqdm.auto import tqdm, trange

# copy.deepcopy(dict)
#from datetime import datetime
# 32位与64位的一些小细节不同, 需要分别照顾
# 还需要对恶意实体进行标记, 特别做一个匹配函数调用一下
# 我觉得应该先建图再标记, 因为创建事件需要用进程ID来对应上创建者, 而不是程序名
# 或者先标记一部分, 另一部分再说
# D:\WorkSpace\写论文\Anti-IDS\复现实验\ATLAS\raw_logs
# None: {None: 1545382270}
# 4659 的删除操作有包含在上层的4656中, 因此可以考虑不要
event_num = 0   # 统计事件
#log_file_path = '../security_events.txt'#'../syslog.txt'
ret_pattern = {
    'Event_ID': None,           # 事件ID
    'Event_Date': None,         # 时间戳
    'Process_Name': None,       # 进程名
    'Process_ID': None,         # 进程ID
    'Application_Name': None,   # 这里日志中是相对路径, 需要注意
    'Direction': None,
    'New_Process_Name': None,
    'New_Process_ID': None,
    'S_IP': None,
    'S_Port': None,
    'D_IP': None,
    'D_Port': None,
    'Object_Name': None,
    'Object_Type': None,
    'Creator_Process_Name': None,
    'Creator_Process_ID': None,
    'Access_Mask': None,
    'Is_Malicious': False,
    }
malicious_labels = []
process_dict = {}   # 用于放Pid->process_name的字典, 预处理里对进程创建事件进行处理
#self_ip = '192.168.223.130' # 日志文件的主机
# 应当跳过ip是回环的地址吗
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def main(syslog_path):
    syslog = open(syslog_path, 'r', encoding='utf-8')
    #label = open(path + '/malicious_labels.txt', 'r', encoding='utf-8')
    #malicious_labels = [x.replace('\n','') for x in label.readlines()]
    logs = []
    single_block = []
    inside_block = False
    for line in tqdm(syslog, desc='[-] Reading {}'.format(syslog_path), unit=' lines', unit_scale=True):
        if len(line)<=1:
            continue
        if 'Audit' in line:
            inside_block = True
        elif '\"' == line[-2]:
            inside_block = False
            single_block.append(line.replace('\"', '')) # 把用于切分的冒号去掉
            logs.append(single_block)
            #input(single_block)
            single_block = []
            continue
        if inside_block:
            single_block.append(line)

    pattern = re.compile('\s(\d+)\s')
    output = []

    for log in tqdm(logs, desc='[-] Preprocessing logs', unit= 'logs', unit_scale=True):
        try:
            event_ID = int(pattern.findall(log[0])[0])
        except:
            continue
        Event_Others(log)
        # 由于部分日志时间顺序因导出不规范而不严格上下排列, 所以先快速全遍历一遍
    for log in tqdm(logs, desc='[-] Preprocessing logs', unit= 'logs', unit_scale=True):
        try:
            event_ID = int(pattern.findall(log[0])[0])
        except:
            continue
        if event_ID == 4656:
            output.append(Event_4656(log))
        # elif event_ID == 4659:
        #     output.append(Event_4659(log))
        elif event_ID == 4663:
            output.append(Event_4663(log))
        elif event_ID == 4688:
            output.append(Event_4688(log))
        elif event_ID == 5156:
            output.append(Event_5156(log))
        elif event_ID == 5158:
            output.append(Event_5158(log))

    return output
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def app_name_change(string):
    # 目前收集的没有2, 也就是d盘符
    if '\device\harddiskvolume1' in string:
        ret = string.replace('\device\harddiskvolume1', 'c:')
    else:
        ret = string
    return ret

def is_malicious(string):
    for label in malicious_labels:
        if label in string:
            return True
    return False

def get_date(line):
    # Audit Success	11/2/2018 10:39:59 PM	Microsoft-Windows-Security-Auditing	4656	SAM	"A handle to an object was requested.
    #12/21/2018 4:51:10 PM datetime.strptime(a, '%m/%d/%Y %I:%M:%S %p')
    time_pattern = re.compile('\s(\d+/\d+/\d+\s\d+:\d+:\d+\s.M)\s')
    event_date = time_pattern.findall(line)[0]
    event_date = time.mktime(time.strptime(event_date, '%m/%d/%Y %I:%M:%S %p'))
    event_date = str(int(event_date))
    return event_date

def add_process(Id, name, time, log):
    if Id==None or name==None:
        input('err?')
        input(name)
        input(Id)
        input(log)
        return False
    if Id not in process_dict.keys():
        process_dict[Id] = {}
        process_dict[Id][name] = int(time)
    elif name not in process_dict[Id].keys():
        process_dict[Id][name] = int(time)
    elif int(time) < process_dict[Id][name]:
        process_dict[Id][name] = int(time)
    return True

def find_process(Id, time):
    # 由于日志存储存在微秒级的时间偏差, 导致虽然记录文件有前后顺序, 但时间顺序可能不一定是对的(这也意味着正式处理时需要进行时间排序再做后续操作)
    ret = ''
    if Id not in process_dict.keys():
        ret = 'unknow_process'   # 因为日志截取区间不完善, 导致确实有部分找不到
        return ret
    #input(process_dict)
    #input(Id)
    for name in process_dict[Id].keys():
        if int(time) >= process_dict[Id][name]:
            ret = name.lower()
    if ret == '':
        # 否则找一格最接近的
        a = float('inf')
        for name in process_dict[Id].keys():
            b = abs(int(time)-process_dict[Id][name])
            if b < a:
                a = b
                ret = name
        process_dict[Id][ret] = int(time)
    return ret

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def Event_4656(log):
    # 这个是对文件夹的访问, 和4663一样的处理
    # 弃置
    ret = copy.deepcopy(ret_pattern)
    ret['Event_Date'] = get_date(log[0])
    ret['Event_ID'] = 4656

    for line in log:
        if 'Object Type' in line:
            ret['Object_Type'] = line.split()[-1].lower()
        elif 'Object Name' in line:
            ret['Object_Name'] = line.split('\t')[-1][:-1].lower()
        elif 'Process ID' in line:
            ret['Process_ID'] = str(int(line.split()[-1], 16))
        elif 'Process Name' in line:
            ret['Process_Name'] = line.split('\t')[-1][:-1].lower()
        elif 'Access Mask' in line:
            ret['Access_Mask'] = str(int(line.split()[-1], 16))

    add_process(ret['Process_ID'], ret['Process_Name'], ret['Event_Date'], log)
    if is_malicious(ret['Process_Name']): ret['Is_Malicious'] = True
    return ret

# def Event_4659(log):
#     # delete file
#     ret = copy.deepcopy(ret_pattern)
#     ret['Event_Date'] = get_date(log[0])
#     ret['Event_ID'] = 4659
#
#     for line in log:
#         if 'Object Type' in line:
#             ret['Object_Type'] = line.split()[-1].lower()
#         elif 'Object_Name' in line:
#             ret['Object_Name'] = line.split('\t')[-1][:-1].lower()
#         elif 'Process ID' in line:
#             ret['Process_ID'] = str(int(line.split()[-1], 16))
#         elif 'Process Name' in line:
#             ret['Process_Name'] = line.split('\t')[-1][:-1].lower()
#         elif 'Access Mask' in line:
#             ret['Access_Mask'] = str(int(line.split()[-1], 16))
#
#     add_process(ret['Process_ID'], ret['Process_Name'], ret['Event_Date'], log)
#     if is_malicious(ret['Process_Name']): ret['Is_Malicious'] = True
#     return ret

def Event_4663(log):
    # 文件系统访问
    # 不能用split切分, 还是得用一点表达式
    # time
    ret = copy.deepcopy(ret_pattern)
    ret['Event_Date'] = get_date(log[0])
    ret['Event_ID'] = 4663

    for line in log:
        if 'Object Type' in line:
            ret['Object_Type'] = line.split()[-1].lower()
        elif 'Object Name' in line:
            ret['Object_Name'] = line.split('\t')[-1][:-1].lower()
        elif 'Process ID' in line:
            ret['Process_ID'] = str(int(line.split()[-1], 16))
        elif 'Process Name' in line:
            ret['Process_Name'] = line.split('\t')[-1][:-1].lower()
        elif 'Access Mask' in line:
            ret['Access_Mask'] = str(int(line.split()[-1], 16))

    add_process(ret['Process_ID'], ret['Process_Name'], ret['Event_Date'], log)
    if is_malicious(ret['Process_Name']): ret['Is_Malicious'] = True
    return ret

def Event_4688(log):
    # 令牌提升类型需要注意一下, 可能需要查文档
    # 新的多了个Mandatory Label, 故修改, 可能和开启记录的东西有关, 或版本不同
    # 新版的直接带有创建进程名了, 呃啊, 旧版什么垃圾
    ret = copy.deepcopy(ret_pattern)
    ret['Event_Date'] = get_date(log[0])
    ret['Event_ID'] = 4688

    for line in log:
        if 'New Process ID' in line:
            ret['New_Process_ID'] = str(int(line.split()[-1], 16))
        elif 'New Process Name' in line:
            ret['New_Process_Name'] = line.split('\t')[-1][:-1].lower()
        elif 'Creator Process ID' in line:
            ret['Creator_Process_ID'] = str(int(line.split()[-1], 16))

    add_process(ret['New_Process_ID'], ret['New_Process_Name'], ret['Event_Date'], log)
    ret['Creator_Process_Name'] = find_process(ret['Creator_Process_ID'], ret['Event_Date'])

    if is_malicious(ret['New_Process_Name']): ret['Is_Malicious'] = True
    return ret

def Event_5156(log):
    # 网络链接建立
    ret = copy.deepcopy(ret_pattern)
    ret['Event_Date'] = get_date(log[0])
    ret['Event_ID'] = 5156

    for line in log:
        if 'Process ID' in line:
            ret['Process_ID'] = str(int(line.split()[-1], 16))
        elif 'Application Name' in line:
            ret['Application_Name'] = app_name_change(line.split('\t')[-1][:-1]).lower()
        elif 'Direction' in line:
            ret['Direction'] = line.split()[-1]
        elif 'Source Address' in line:
            ret['S_IP'] = line.split()[-1]
        elif 'Source Port' in line:
            ret['S_Port'] = line.split()[-1]
        elif 'Destination Address' in line:
            ret['D_IP'] = line.split()[-1]
        elif 'Destination Port' in line:
            ret['D_Port'] = line.split()[-1]
        elif 'Protocol' in line:
            ret['Protocol'] = line.split()[-1]

    if is_malicious(ret['Application_Name']): ret['Is_Malicious'] = True
    return ret

def Event_5158(log):
    # 绑定端口
    ret = copy.deepcopy(ret_pattern)
    ret['Event_Date'] = get_date(log[0])
    ret['Event_ID'] = 5158
    i = 0
    while i < len(log):
        # Application Information
        if 'Application Information:' in log[i]:
            ret['Process_ID'] = str(int(log[i+1].split()[-1], 16))
            ret['Application_Name'] = app_name_change(log[i+2].split('\t')[-1][:-1]).lower()
        if 'Network Information:' in log[i]:
            ret['S_IP'] = log[i+1].split()[-1]
            ret['S_Port'] = log[i+2].split()[-1]
            #ret['Protocol'] = log[i+3].split()[-1]
        i += 1

    for line in log:
        if 'Process ID' in line:
            ret['Process_ID'] = str(int(line.split()[-1], 16))
        elif 'Application Name' in line:
            ret['Application_Name'] = app_name_change(line.split('\t')[-1][:-1]).lower()
        elif 'Source Address' in line:
            ret['S_IP'] = line.split()[-1]
        elif 'Source Port' in line:
            ret['S_Port'] = line.split()[-1]
        elif 'Protocol' in line:
            ret['Protocol'] = line.split()[-1]

    if is_malicious(ret['Application_Name']): ret['Is_Malicious'] = True
    return ret

def Event_Others(log):
    ret = copy.deepcopy(ret_pattern)
    ret['Event_Date'] = get_date(log[0])

    for line in log:
        if 'Process ID' in line:
            ret['Process_ID'] = str(int(line.split()[-1], 16))
        elif 'Process Name' in line:
            ret['Process_Name'] = line.split('\t')[-1][:-1].lower()
    a = False
    if (ret['Process_ID'] != None) and (ret['Process_Name'] != None):
        a=add_process(ret['Process_ID'], ret['Process_Name'], ret['Event_Date'], log)
        if not a:
            input('[*] {}'.format(log))

    if is_malicious(ret['Process_Name']): ret['Is_Malicious'] = True
    return ret
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if __name__ == '__main__':
    main('./')
