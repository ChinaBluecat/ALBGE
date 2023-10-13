#coding=utf-8
import torch
import networkx as nx
from torch_geometric.utils import from_networkx
from torch_geometric.data import HeteroData


'''
给定一个图G, 将其转换为HeteroData

Process={
    x=[process_num, dimension], # 进程名可能没有太大意义, 因为会被伪造, 但也不一定
    y=[is_malicious_label],     # 主要任务是对进程识别, 在做全图测试的时候会用到
    process_mask=[process_num], # 记录中心节点的mask, 用来最后输出
    #attr=[process_num, attr_num, attr_dimension]
}
File={
    x=[file_num, dimension], # 和上面那个维度应该是相同的
    y=[is_malicious_label],
    #attr=[file_num, attr_num, attr_dimension]
}
# Facility={
#     x=[facility_num, dimension]
#     y=[is_malicious_label]
# }
Port={
    x=[port_num, dimension],
    #attr=[port_num, attr_num, attr_dimension]
}
# relation
(process, access, file)={
    edge_index=[2, edge_num],
    edge_attr=[edge_num, dimension]
    }
(process, same_as, file)={edge_index=[2, edge_num]}
(process, create, process)={edge_index=[2, edge_num]}
(process, bind, port)={edge_index=[2, edge_num]}
(port, session, port)={edge_index=[2, edge_num]}    # 这个边做成双向的


目前路径嵌入直接用的斯坦福Transformer模型, 可能考虑换上bert模型自己训练
embedding维度384, 似乎不能改
'''
# ---------------------------------------------------------------------
def getinfo(process_name):
    KG = nx.read_gml('./data.gml')
    # 从知识库中查找该进程, 返回该进程对应本体的数据内容
    # 现有的内容:
    # process: path, app_type, developer, description
    # 不同的属性会用独特的encoder, 文本类的东西大部分会被用str2vec处理(现成的NLP模型), 不用送去训练, 而另一些可能会需要(如图片)
    # overview, type, developer
    # 我应该全都用str2vec吗, 又或者应该?
    # 用str2vec, 但是必须再网络中加计算映射的dense层, 或是别的映射, 因为不同属性应该被理解为不同的特征域, 需要把这些域分开讨论
    # 但是不定数量的属性, 该如何合到一起呢, 变成该节点的初始嵌入表示, 以及如何将多个特征域整合到同一个融合域?

    if KG.has_node(process_name):
        ret = KG.nodes(data=True)[process_name]
        for key in ret.keys():
            if ret[key] != None:
                ret[key] = '{}_{}'.format(key, ret[key])
    else:
        ret = {'Overview': None, 'Type': None, 'Developer': None}
    return ret


# ---------------------------------------------------------------------
def binary(x, bits):
    mask = 2**torch.arange(bits).to(x.device, x.dtype)
    # torch.arange(bits-1,-1,-1)
    return x.unsqueeze(-1).bitwise_and(mask).ne(0).byte()

def str2vec(string):
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer('paraphrase-MiniLM-L6-v2')
    string = [x.replace('/', ' ') for x in string]    # 去掉特殊符号试试
    #model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
    if isinstance(string, str):
        sentence = [string]
    else:
        sentence = string
    embeddings = model.encode(string)
    return torch.tensor(embeddings)

def G2tensor(G, label, node):
    # 增加node的标记与mask, 用作池化提取
    # 如果要用于全图处理, 需要把node参数和对应内容去掉, 记得复制一套函数用于另一个实验

    process_nodes = [x for x in G.nodes() if G.nodes('type')[x]=='process']
    process_is_malicious = torch.tensor([G.nodes(data=True)[x]['is_malicious'] for x in process_nodes])
    file_nodes = [x for x in G.nodes() if G.nodes('type')[x]=='file']
    port_nodes = [x for x in G.nodes() if G.nodes('type')[x]=='port']
    #input(port_nodes['127.0.0.1_49190'])
    #input(G.nodes(data=True))

    paf_edges = [(from_node, to_node, edge_attributes) for from_node,to_node,edge_attributes in G.edges(data=True) if edge_attributes['type']=='access']

    pcp_edges = [(from_node, to_node, edge_attributes) for from_node,to_node,edge_attributes in G.edges(data=True) if edge_attributes['type']=='create']

    pbp_edges = [(from_node, to_node, edge_attributes) for from_node,to_node,edge_attributes in G.edges(data=True) if edge_attributes['type']=='bind']

    psp_edges = [(from_node, to_node, edge_attributes) for from_node,to_node,edge_attributes in G.edges(data=True) if edge_attributes['type']=='session']
    #input(psp_edges)
    psf_edges = [(from_node, to_node, edge_attributes) for from_node,to_node,edge_attributes in G.edges(data=True) if edge_attributes['type']=='same_as']

    paf_edge_index = torch.zeros([2, len(paf_edges)], dtype=torch.long)
    paf_edge_attr = torch.zeros(len(paf_edges), dtype=torch.int)  # 暂时这样, 现在要修改成binary
    paf_edge_attr_binary = []

    pcp_edge_index = torch.zeros([2, len(pcp_edges)], dtype=torch.long)

    pbp_edge_index = torch.zeros([2, len(pbp_edges)], dtype=torch.long)

    psp_edge_index = torch.zeros([2, 2*len(psp_edges)], dtype=torch.long)

    psf_edge_index = torch.zeros([2, len(psf_edges)], dtype=torch.long)

    #size_ = 24 # 也许可以跳转
    for i in range(len(paf_edges)):
        from_node, to_node, edge_attributes = paf_edges[i]
        paf_edge_index[0][i] = process_nodes.index(from_node)
        paf_edge_index[1][i] = file_nodes.index(to_node)
        paf_edge_attr[i] = int(edge_attributes['access_mask'])  # 需要做成one-hot
        # if size_ < len(bin(int(edge_attributes['access_mask'])))-2:
        #     size_ = len(bin(int(edge_attributes['access_mask'])))-2
        #print(paf_edge_attr[i])
        paf_edge_attr_binary.append(binary(paf_edge_attr[i], 24))
    #input('[*] size: {}'.format(size_))
    if paf_edge_attr_binary != []:
        paf_edge_attr_binary = torch.stack(paf_edge_attr_binary)
    else:
        paf_edge_attr_binary = torch.zeros(24)
    #input('[*] binary: {}'.format(paf_edge_attr_binary))

    for i in range(len(pcp_edges)):
        from_node, to_node, edge_attributes = pcp_edges[i]
        pcp_edge_index[0][i] = process_nodes.index(from_node)
        pcp_edge_index[1][i] = process_nodes.index(to_node)

    for i in range(len(pbp_edges)):
        from_node, to_node, edge_attributes = pbp_edges[i]
        pbp_edge_index[0][i] = process_nodes.index(from_node)
        pbp_edge_index[1][i] = port_nodes.index(to_node)

    for i in range(len(psp_edges)):
        # 这个也需要加反向, 看看用reverse还是什么别的加
        from_node, to_node, edge_attributes = psp_edges[i]
        psp_edge_index[0][i] = port_nodes.index(from_node)
        psp_edge_index[1][i] = port_nodes.index(to_node)
        psp_edge_index[0][i+len(psp_edges)] = port_nodes.index(to_node)
        psp_edge_index[1][i+len(psp_edges)] = port_nodes.index(from_node)

    for i in range(len(psf_edges)):
        from_node, to_node, edge_attributes = psf_edges[i]
        psf_edge_index[0][i] = process_nodes.index(from_node)
        psf_edge_index[1][i] = file_nodes.index(to_node)
        # 好像比较麻烦直接加反向, 但是可以通过调用to_d什么那个函数来多创建一个


    file_nodes = str2vec(file_nodes) if len(file_nodes) > 0 else None
    port_nodes = str2vec(port_nodes) if len(port_nodes) > 0 else None

    data = HeteroData()

    if node:
        node_index = process_nodes.index(node)  # 中心节点的下标
        process_mask = torch.zeros(len(process_nodes), dtype=torch.bool)
        process_mask[node_index] = True
        data['Process'].process_mask = process_mask
        process_nodes = str2vec(process_nodes)
        process_nodes[node_index] = torch.zeros(process_nodes[0].shape)
    else:
        process_nodes = str2vec(process_nodes)

    data['Process'].x = process_nodes
    data['Process'].y = process_is_malicious

    #data['Process'].attr =
    if file_nodes != None:
        data['File'].x = file_nodes
        data['Process', 'access', 'File'].edge_index = paf_edge_index
        data['Process', 'access', 'File'].edge_attr = paf_edge_attr_binary
        data['Process', 'same_as', 'File'].edge_index = psf_edge_index
    #data['Facility'] =
    if port_nodes != None:
        data['Port'].x = port_nodes
        data['Process', 'bind', 'Port'].edge_index = pbp_edge_index
        data['Port', 'session', 'Port'].edge_index = psp_edge_index

    data['Process', 'create', 'Process'].edge_index = pcp_edge_index

    data['y'] = torch.tensor([label], dtype=torch.int64)
    #input(data['y'])
    return data

    # 这里的问题, 可能子图中不存在某类节点或边关系, 导致送入网络出错
    # 需要作处理

if __name__ == '__main__':
    path = './save/gml/M1h1.gml'
    G = nx.read_gml(path)
    data = G2tensor(G, True)
    print(data['Process']['x'])
    #print(data.num_classes)
    #print(data.x_dicte)
