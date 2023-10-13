# coding=utf-8
from graph_generator import find_nodetree, oversampling
from utils.graph_to_tensor import G2tensor
from tqdm.auto import tqdm, trange
from utils.models import str2vec
import networkx as nx
import random
import torch
import os

'''
修改一下, 每个文件都生成对应的.pt文件, 然后手工搬运哪些作为训练集, 哪些作为测试集
然后在training那边, DataLoader再去读所有的
'''

#G = nx.read_gml(path)
def load_graph(path, mutate=False):
    G = nx.read_gml(path)
    ret = []
    process_nodes = [x for x in G.nodes() if G.nodes('type')[x]=='process']
    for process_node in tqdm(process_nodes, desc='[-] Building activate_graph', unit=' nodes', unit_scale=True):
        label = G.nodes(data=True)[process_node]['is_malicious']
        node_subgraph = find_nodetree(G, process_node)  # 找邻接图
        data = G2tensor(node_subgraph, label, process_node) # 擦除指定中心节点的文件路径特征
        process_name = process_node.split('\\')[-1]
        #input(process_name)
        match = False
        for p_name in p_dict.keys():
            if process_name.lower() in p_name.lower():
                data['des_encode'] = p_dict[p_name]
                data['process_name'] = p_name
                ret.append(data)
                match = True
                break
        if not match:
            #input(process_name)
            #input(process_node)
            # process_access request information: 这是什么东西
            data['des_encode'] = torch.zeros([384])
            # 这里的y=[1]指的是维度
        if label:   # 如果是恶意实体, 对其进行变异过采样
            if mutate:
                mutated_trees = oversampling(G, process_node, node_subgraph)
                for mutated_tree in mutated_trees:
                    data = G2tensor(mutated_tree, label, process_node)
                    match = False
                    for p_name in p_dict.keys():
                        if process_name.lower() in p_name.lower():
                            data['des_encode'] = p_dict[p_name]
                            data['process_name'] = p_name
                            ret.append(data)
                            match = True
                            break
                    if not match:
                        input(process_name)
                        data['des_encode'] = torch.zeros([384])
    del G
    return ret

def load_data(in_path, out_path, mutate=False):
    # 修改, 每一个都存成独立.pt
    ret = {}
    graph_dir = os.listdir(in_path)
    for filename in graph_dir:
        gml_path = os.path.join(in_path, filename)
        graph_list = load_graph(gml_path, mutate=mutate)
        torch.save(graph_list, os.path.join(out_path, filename[:-3]+'pt'))
        print('[*] end: {}'.format(filename))
    return ret

def main_loop():
    train_path = './save/gml/train'
    test_path = './save/gml/test'
    train_output_path = './save/data/train'
    test_output_path = './save/data/test'
    train_data_list = load_data(train_path, train_output_path, mutate=True)
    test_data_list = load_data(test_path, test_output_path, mutate=True)


if __name__ == '__main__':
    p_dict = torch.load('./save/data/p_dict.pt')
    input(p_dict)
    main_loop()
    # ret = load_graph('./save/gml/test.gml', mutate=False) # 处理正常系统进程日志
    # torch.save(ret, './save/data/test.pt')
