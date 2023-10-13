#coding=utf-8
#from utils import preprocess_new as preprocess
from tqdm.auto import tqdm, trange
from utils import preprocess
import matplotlib.pyplot as plt
import networkx as nx
import argparse
import logging
import random
import math
import copy
import os



LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='./graph_generator.log', level=logging.DEBUG, format=LOG_FORMAT)
malicious_labels = []



#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def main_loop():
    data_path = './raw_data/auditlog'
    data_dir = os.listdir(data_path)
    #graph_list = []
    global malicious_labels

    for dir in data_dir:
        malicious_labels_path = os.path.join(data_path, dir, 'malicious_labels.txt')
        syslog_path = os.path.join(data_path, dir, 'security_events.txt')
        label = open(malicious_labels_path, 'r', encoding='utf-8')
        malicious_labels = [x.replace('\n','') for x in label.readlines()]

        output = preprocess.main(syslog_path)
        G = nx.DiGraph()
        Build_graph_log(G, output)
        logging.info('[*] G nodes/edges '+dir+' : {} / {}'.format(len(G.nodes()), len(G.edges())))
        match_nodes = [x[0] for x in list(G.nodes('is_malicious')) if x[1]==True]
        if match_nodes != []:
            G_subgraph = construct_G_subgraph(G, match_nodes)
            logging.info('[*] G_subgraph nodes/edges '+dir+' before merge: {} / {}'.format(len(G_subgraph.nodes()), len(G_subgraph.edges())))
            # S_IP_Port = '127.0.0.1_49190'
            # if G_subgraph.has_node(S_IP_Port):
            #     input(G.nodes(data=True)[S_IP_Port])
            fusion_hash(G_subgraph)
            logging.info('[*] G_subgraph nodes/edges '+dir+' after merge: {} / {}'.format(len(G_subgraph.nodes()), len(G_subgraph.edges())))
            # S_IP_Port = '127.0.0.1_49190'
            # if G_subgraph.has_node(S_IP_Port):
            #     input(G.nodes(data=True)[S_IP_Port])
            #input(G_subgraph.nodes)
            nx.write_gml(G_subgraph, os.path.join('./save/gml', dir+'.gml'))
            # 需要考虑是否进行合并, 保存哪一种图
            del G_subgraph
        else:
            fusion_hash(G)
            logging.info('[*] G nodes/edges '+dir+' after merge: {} / {}'.format(len(G.nodes()), len(G.edges())))
            nx.write_gml(G, os.path.join('./save/gml', dir+'.gml'))
        del G

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def is_malicious(string):
    global malicious_labels
    for label in malicious_labels:
        if label in string:
            return True
    return False

def draw_graph(G):
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True)
    plt.show()

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def Build_graph_4656(G, ret):

    #process_node = '{}_{}'.format(ret['Process_ID'], ret['Process_Name'])
    process_node = 'process_{}'.format(ret['Process_Name'])
    object_node = 'file_{}'.format(ret['Object_Name'])

    if not G.has_node(object_node):
        G.add_node(object_node, type='file', attr=ret['Object_Name'], is_malicious=is_malicious(object_node))
    if not G.has_node(process_node):
        G.add_node(process_node, type='process', attr=ret['Process_Name'], is_malicious=ret['Is_Malicious'])
        #, timestamp=ret['Event_Date'])  # 看情况
    G.add_edge(process_node, object_node, type='access', timestamp=ret['Event_Date'], access_mask=ret['Access_Mask'])

# def Build_graph_4659(G, ret):
#
#     #process_node = '{}_{}'.format(ret['Process_ID'], ret['Process_Name'])
#     process_node = 'process_{}'.format(ret['Process_Name'])
#     object_node = 'file_{}'.format(ret['Object_Name'])
#     if not G.has_node(object_node):
#         G.add_node(object_node, type='file', attr=ret['Object_Name'], is_malicious=is_malicious(object_node))
#     if not G.has_node(process_node):
#         G.add_node(process_node, type='process', attr=ret['Process_Name'], is_malicious=is_malicious(process_node))
#     G.add_edge(process_node, object_node, type='access', timestamp=ret['Event_Date'], access_mask=ret['Access_Mask'])
#     return

def Build_graph_4663(G, ret):

    process_node = 'process_{}'.format(ret['Process_Name'])
    object_node = 'file_{}'.format(ret['Object_Name'])
    if not G.has_node(object_node):
        G.add_node(object_node, type='file', attr=ret['Object_Name'], is_malicious=is_malicious(object_node))
    if not G.has_node(process_node):
        G.add_node(process_node, type='process', attr=ret['Process_Name'], is_malicious=is_malicious(process_node))
    G.add_edge(process_node, object_node, type='access', timestamp=ret['Event_Date'], access_mask=ret['Access_Mask'])
    return

def Build_graph_4688(G, ret):
    # 问题在这个函数里
    process_node = 'process_{}'.format(ret['Creator_Process_Name'])
    object_node = 'process_{}'.format(ret['New_Process_Name'])
    if not G.has_node(object_node):
        G.add_node(object_node, type='process', attr=ret['New_Process_Name'], is_malicious=is_malicious(object_node))
    if not G.has_node(process_node):
        G.add_node(process_node, type='process', attr=ret['Creator_Process_Name'], is_malicious=is_malicious(process_node))
    if G.has_node('file_{}'.format(ret['New_Process_Name'])):
        # 如果之前有以文件形式写这个东西
        # 那么将那个文件与该进程关联
        # 将文件类型修改为进程
        G.add_edge(object_node, 'file_{}'.format(ret['New_Process_Name']), type='same_as')  # 可能这里?
        #G.add_edge('file_{}'.format(ret['New_Process_Name']), object_node, type='same_as')
        #G.nodes[object_node]['type'] = 'process'
    G.add_edge(process_node, object_node, type='create', timestamp=ret['Event_Date'])
    return

def Build_graph_5156(G, ret):
    # 这里也是, session会非常多, 缩减需要合并大量的会话
    process_node = 'process_{}'.format(ret['Application_Name'])
    S_IP = ret['S_IP'].replace(':', '-')
    D_IP = ret['D_IP'].replace(':', '-')    # ipv6格式符号
    S_Port = ret['S_Port']
    D_Port = ret['D_Port']
    S_IP_Port = '{}_{}'.format(S_IP, S_Port)
    D_IP_Port = '{}_{}'.format(D_IP, D_Port)
    # if not G.has_node(D_IP):
    #     G.add_node(D_IP, type='facility', is_malicious=is_malicious(D_IP))
    if not G.has_node(D_IP_Port):
        G.add_node(D_IP_Port, type='port', attr=D_IP_Port, is_malicious=is_malicious(D_IP_Port))
    # if not G.has_node(S_IP):
    #     G.add_node(S_IP, type='facility', is_malicious=is_malicious(S_IP))
    if not G.has_node(S_IP_Port):
        G.add_node(S_IP_Port, type='port', attr=S_IP_Port, is_malicious=is_malicious(S_IP_Port))
    if not G.has_node(process_node):
        G.add_node(process_node, type='process', attr=ret['Application_Name'], is_malicious=is_malicious(process_node))
    G.add_edge(process_node, S_IP_Port, type='bind', timestamp=ret['Event_Date'])
    G.add_edge(S_IP_Port, D_IP_Port, type='session',timestamp=ret['Event_Date'], s_ip=S_IP, s_port=ret['S_Port'], d_ip=D_IP, d_port=ret['D_Port'])
    return

def Build_graph_5158(G, ret):
    # 端口绑定
    # 这里有非常多, 因为每次通信都会申请端口绑定, 因此这里需要做缩减处理
    process_node = 'process_{}'.format(ret['Application_Name'])
    S_IP = ret['S_IP'].replace(':', '-')
    S_IP_Port = '{}_{}'.format(S_IP, ret['S_Port'])
    if not G.has_node(S_IP_Port):
        G.add_node(S_IP_Port, type='port', attr=S_IP_Port, is_malicious=is_malicious(S_IP_Port))
    if not G.has_node(process_node):
        G.add_node(process_node, type='process', attr=ret['Application_Name'], is_malicious=ret['Is_Malicious'])
    G.add_edge(process_node, S_IP_Port, type='bind', timestamp=ret['Event_Date'])
    return

def Build_graph_log(G, output):
    for ret in tqdm(output, desc='[-] Building Graph', unit=' logs', unit_scale=True):
        event_ID = ret['Event_ID']
        if event_ID == 4656:
            Build_graph_4656(G, ret)
            pass
        # elif event_ID == 4659:
        #     Build_graph_4659(G, ret)
        #     pass
        elif event_ID == 4663:
            Build_graph_4663(G, ret)
            pass
        elif event_ID == 4688:
            Build_graph_4688(G, ret)
            pass
        elif event_ID == 5156:
            Build_graph_5156(G, ret)
            pass
        elif event_ID == 5158:
            Build_graph_5158(G, ret)
            pass
    return

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def construct_G_subgraph(G, nodes):
    # 给定节点集, 获取包含该节点集的子图
    # nodes: list
    # 这里似乎很耗时间, 在考虑优化掉这个步骤
    print('[-] Constructing subgraph')
    sub_nodes = nodes.copy()
    node_set = set(sub_nodes)
    FOUND_NEW_NODES = True

    while True:
        if FOUND_NEW_NODES:
            FOUND_NEW_NODES = False
        else:
            break

        for n in sub_nodes:
            successors = G.successors(n) # or neighbors
            predecessors = G.predecessors(n)
            before_union_size = len(node_set)
            node_set = node_set.union(successors)
            node_set = node_set.union(predecessors)
            after_union_size = len(node_set)

            if after_union_size > before_union_size:
                FOUND_NEW_NODES = True

        sub_nodes = list(node_set)

    G_subgraph = G.subgraph(sub_nodes).copy()
    for n in list(G_subgraph.nodes()):
        # 暂时先不需要这类IP地址, 代表本机
        if '0.0.0.0_' in n or '--_' in n or '255.255.255.255_' in n:
            G_subgraph.remove_node(n)
    return G_subgraph

def find_nodetree(G, node, deapth=3):
    # 这个看起来还不错, 追踪深度为3, 往前只找父节点, 往后只找子节点, 作为邻接子图
    tree = set([node])
    def loop_predecessors(G, node, deapth):
        ret = set([node])
        if deapth==0:
            return ret
        if len(list(G.predecessors(node))) > 0:
            for pre_node in list(G.predecessors(node)):
                ret = ret.union(loop_predecessors(G, pre_node, deapth-1))
        return ret
    def loop_successors(G, node, deapth):
        ret = set([node])
        if deapth==0:
            return ret
        if len(list(G.successors(node))) > 0:
            for pre_node in list(G.successors(node)):
                ret = ret.union(loop_successors(G, pre_node, deapth-1))
        return ret

    predecessors = loop_predecessors(G, node, deapth)
    successors = loop_successors(G, node, deapth)
    tree = tree.union(predecessors)
    tree = tree.union(successors)
    ret = G.subgraph(list(tree)).copy()
    return ret

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# 变异与过采样

access_pool = {1: 29542, 1048705: 1972, 6: 421, 1180063: 575, 1048704: 4693, 128: 5586, 65536: 732, 65664: 550, 1048577: 12591, 256: 438, 3: 106, 1179785: 15614, 131072: 895, 131200: 134, 1180054: 185, 1114241: 6, 262144: 65, 393344: 18, 2: 1881, 1048578: 144, 1114240: 130, 1245312: 1, 8: 30, 1245599: 15, 0: 20, 32: 3446, 1048609: 3292, 1048608: 555, 1179817: 99, 1048737: 120, 33: 55, 1245590: 29, 1507743: 25, 1245321: 25, 18022537: 25, 1179776: 20, 1180041: 3, 1179784: 5, 1048832: 19, 4: 426, 1048580: 12, 1245591: 392, 20: 80, 1179648: 1, 1179926: 6, 2032095: 1, 1179787: 3, 1245323: 1, 1179789: 1, 786432: 12, 1835136: 1, 1835008: 1, 131074: 1, 1442207: 1, 983103: 5} # 各种access_mask出现的频数

def oversampling(G, node, nodetree):
    # 需要实现过采样
    # 思路, 先设定好链接关系池, 然后随机采样文件类型的节点(未在子图中出现过的)
    # 然后从关系池中随机选定一个(主要是文件访问, 不同的access_mask)
    # 为图添加新链接
    # 突变量由随机值控制, 范围大概1-10吧?
    mutated_trees = []
    for i in range(random.choice(range(10,20))):
        mutated_trees.append(mutate(G, node, nodetree))
    return mutated_trees

def mutate(G, node, nodetree):
    # 用于样本突变
    add_node_num = random.choice(range(1,20))
    tree_file_nodes = [x for x in nodetree.nodes() if nodetree.nodes('type')[x]=='file']
    G_file_nodes = [x for x in G.nodes() if G.nodes('type')[x]=='file']
    new_tree = copy.deepcopy(nodetree)

    while(add_node_num):
        file = random.choice(G_file_nodes)
        file_node = G.nodes(data=True)[file]
        if file in tree_file_nodes:
            continue
        access_mask = random.choices(list(access_pool.keys()), weights=list(access_pool.values()), k=1)[0]
        # 节点信息忘了拷贝了
        new_tree.add_node(file, type='file', attr=file_node['attr'], is_malicious=file_node['is_malicious'])
        new_tree.add_edge(node, file,
            type='access',
            timestamp=0, # 暂时还没用, 后面上时域模型可能需要改动
            access_mask=access_mask)
        add_node_num -= 1
    return new_tree

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# 哈希合并算法
# 遍历节点, 计算它的<父节点+关系类型>-<子节点+关系类型> (两个都是set) 的哈希值

def cal_hash(string):
    import hashlib
    m = hashlib.sha256()
    m.update(string.encode())
    return int(m.hexdigest(), 16)

def fusion_hash(G):
    # 遍历所有非进程的节点, 计算其前置、后置、边
    # 用异或操作是因为可能能去掉顺序影响, 但也会引入不稳定碰撞因素
    # 考虑是否保留所有访问的文件, 因为具有一定使用价值
    nodes = list(G.nodes())
    fusion_dict = {}
    # 第一步, 遍历节点, 对结构进行hash异或
    for node in nodes:
        n = G.nodes(data=True)[node]
        n_type = n['type']
        if n_type != 'port':
            continue
        n_inedges = list(G.in_edges(node, data=True))
        n_outedges = list(G.out_edges(node, data=True))
        encode = cal_hash(n_type)
        for inedge in n_inedges:
            inedge_type = inedge[2]['type']
            predecessor = inedge[0]
            relationship = inedge_type
            if inedge_type == 'access':
                relationship += inedge[2]['access_mask']
            encode ^= cal_hash(predecessor+relationship)

        for outedge in n_outedges:
            outedge_type = outedge[2]['type']
            successor = outedge[1]
            relationship = outedge_type
            if outedge_type == 'access':
                relationship += outedge[2]['access_mask']
            encode ^= cal_hash(successor+relationship)

        if encode in fusion_dict.keys():
            fusion_dict[encode].append(node)
        else:
            fusion_dict[encode] = [node]
    #input(fusion_dict)
    # 第二步, 对字典内的每个key, 对其下的节点进行合并, 创建一个新节点, 关系继承, 保留时间区间和次数
    # 需要先对节点的每个边建立字典, 字典内存放需要保存的数据, 然后对比进行更新, 还有边的方向也需要
    fusion_no = 0   # 融合节点编号, 用来命名融合后的节点
    for key in fusion_dict.keys():
        if len(fusion_dict[key]) < 2:
            continue
        edge_dict = {}
        for node in fusion_dict[key]:
            n = G.nodes(data=True)[node]
            n_type = n['type']
            #s_type = n['source_type']
            n_inedges = list(G.in_edges(node, data=True))
            n_outedges = list(G.out_edges(node, data=True))
            for inedge in n_inedges:
                inedge_type = inedge[2]['type']
                predecessor = inedge[0]
                timestamp = inedge[2]['timestamp']
                if inedge_type == 'access':
                    access_mask = inedge[2]['access_mask']
                if predecessor not in edge_dict.keys():
                    edge_dict[predecessor] = {
                            'type': inedge_type,
                            'start_time': timestamp,
                            'end_time': timestamp,
                            'count': 1,
                            'direct': 0}    # 方向0为入, 1为出
                    if inedge_type == 'access':
                        edge_dict[predecessor]['access_mask'] = access_mask
                else:
                    if edge_dict[predecessor]['start_time'] > timestamp:
                        edge_dict[predecessor]['start_time'] = timestamp
                    elif edge_dict[predecessor]['end_time'] < timestamp:
                        edge_dict[predecessor]['end_time'] = timestamp
                    edge_dict[predecessor]['count'] += 1
            for outedge in n_outedges:
                outedge_type = outedge[2]['type']
                successor = outedge[1]
                timestamp = outedge[2]['timestamp']
                if outedge_type == 'access':
                    access_mask = outedge[2]['access_mask']
                if successor not in edge_dict.keys():
                    edge_dict[successor] = {
                            'type': outedge_type,
                            'start_time': timestamp,
                            'end_time': timestamp,
                            'count': 1,
                            'direct': 1}    # 方向0为入, 1为出
                    if outedge_type == 'access':
                        edge_dict[successor]['access_mask'] = access_mask
                else:
                    if edge_dict[successor]['start_time'] > timestamp:
                        edge_dict[successor]['start_time'] = timestamp
                    elif edge_dict[successor]['end_time'] < timestamp:
                        edge_dict[successor]['end_time'] = timestamp
                    edge_dict[successor]['count'] += 1
            G.remove_node(node)
        new_node = '{}_{}'.format(n_type, fusion_no)
        fusion_no += 1
        G.add_node(new_node, type=n_type, attr='port', is_malicious=is_malicious(new_node))
        for n in edge_dict.keys():
            if edge_dict[n]['direct'] == 0:
                G.add_edge(n, new_node,
                    type=edge_dict[n]['type'],
                    timestamp=edge_dict[n]['start_time'],
                    start_time=edge_dict[n]['start_time'],
                    end_time=edge_dict[n]['end_time'],
                    count=edge_dict[n]['count'])
            else:
                G.add_edge(new_node, n,
                    type=edge_dict[n]['type'],
                    timestamp=edge_dict[n]['start_time'],
                    start_time=edge_dict[n]['start_time'],
                    end_time=edge_dict[n]['end_time'],
                    count=edge_dict[n]['count'])

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def main():
    # 单独使用, 处理指定日志转为溯源图, 并同时清洗冗余数据
    output = preprocess.main(input_path)
    G = nx.DiGraph()
    Build_graph_log(G, output)
    fusion_hash(G)
    nx.write_gml(G, output_path)
    del G
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='graph_generator')
    parser.add_argument('--input', type=str, default=None, help='Path to input syslog file')
    parser.add_argument('--output', type=str, default=None, help='Path to save output .gml file')

    args = parser.parse_args()
    input_path = args.input
    output_path = args.output
    if not input_path:
        main_loop()
    else:
        main()