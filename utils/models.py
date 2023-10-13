# coding=utf-8
from torch_geometric.nn import HeteroConv, GCNConv, SAGEConv, GATConv, Linear, HGTConv
from sentence_transformers import SentenceTransformer, util
from torch import Tensor
import torch.nn.functional as F
import torch.nn as nn
import argparse
import torch
import os
#sim = util.cos_sim(embeddings[0], embeddings[1])
#paraphrases = util.paraphrase_mining(model, sentences)

def str2vec(string):
    #model = SentenceTransformer('paraphrase-MiniLM-L6-v2')
    #model = SentenceTransformer('sentence-transformers/paraphrase-MiniLM-L6-v2')
    #model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
    model = SentenceTransformer('./save/model/pretraintrans/all-mpnet-base-v2')
    if isinstance(string, str):
        sentence = [string]
    else:
        sentence = string
    embeddings = model.encode(string)
    return torch.tensor(embeddings)

def select_pool(pool_type, x_dict, batch_dict, mask_dict):
    from torch_geometric.nn import global_add_pool, global_mean_pool, global_max_pool, GlobalAttention, Set2Set
    import torch_scatter.scatter as scatter
    if pool_type == 0:
        # 使用中心节点代替图嵌入
        p_mask = mask_dict['Process']
        p_mask = p_mask.reshape(len(p_mask), 1)
        p_x = x_dict['Process']
        p_batch = batch_dict['Process']
        ret = p_mask.repeat(1, p_x.shape[-1]) * p_x
        ret = scatter(ret, p_batch, dim=0, reduce='add')
        return ret
    x = [x_dict[key] for key in x_dict.keys()]
    x_batch = [batch_dict[key] for key in x_dict.keys()]
    x = torch.cat(x, dim=0)
    x_batch = torch.cat(x_batch, dim=0)
    if pool_type == 1:
        ret = global_add_pool(x, x_batch)
    elif pool_type == 2:
        ret = global_mean_pool(x, x_batch)
    elif pool_type == 3:
        ret = global_max_pool(x, x_batch)
    return ret

def select_model(name, num_layers=2, hidden_channels=64):

    convs = torch.nn.ModuleList()
    if name == 'hgt':
        from torch_geometric.nn import HGTConv
        metadata = (['Process', 'File', 'Port'], [('Process', 'access', 'File'), ('File', 'rev_access', 'Process'), ('Process', 'same_as', 'File'), ('File', 'rev_same_as', 'Process'), ('Process', 'bind', 'Port'), ('Port', 'rev_bind', 'Process'), ('Port', 'session', 'Port'), ('Port', 'rev_session', 'Port'), ('Process', 'create', 'Process'), ('Process', 'rev_create', 'Process')])

        for _ in range(num_layers):
            conv = HGTConv(-1, hidden_channels, metadata, 2, group='sum')
            convs.append(conv)

    elif name == 'han':
        from torch_geometric.nn import HANConv
        metadata = (['Process', 'File', 'Port'], [('Process', 'access', 'File'), ('File', 'rev_access', 'Process'), ('Process', 'same_as', 'File'), ('File', 'rev_same_as', 'Process'), ('Process', 'bind', 'Port'), ('Port', 'rev_bind', 'Process'), ('Port', 'session', 'Port'), ('Port', 'rev_session', 'Port'), ('Process', 'create', 'Process'), ('Process', 'rev_create', 'Process')])

        for _ in range(num_layers):
            conv = HANConv(-1, hidden_channels, metadata, 2)
            convs.append(conv)

    elif name == 'gat':
        from torch_geometric.nn import GATConv
        for _ in range(num_layers):
            gat = GATConv(-1, hidden_channels, add_self_loops=False)
            conv = HeteroConv({
                ('Process', 'access', 'File'): gat,
                ('File', 'rev_access', 'Process'): gat,
                ('Process', 'create', 'Process'): gat,
                ('Process', 'rev_create', 'Process'): gat,
                ('Process', 'same_as', 'File'): gat,
                ('File', 'rev_same_as', 'Process'): gat,
                ('Process', 'bind', 'Port'): gat,
                ('Port', 'rev_bind', 'Process'): gat,
                ('Port', 'session', 'Port'): gat,
                ('Port', 'rev_session', 'Port'): gat,
            }, aggr='mean')
            convs.append(conv)

    elif name == 'albge':
        from torch_geometric.nn import GATConv, GCNConv
        for _ in range(num_layers):
            gat_0 = GATConv(-1, hidden_channels, add_self_loops=False)
            #gat_00 = GATConv(-1, hidden_channels, add_self_loops=False)
            gat_1 = GATConv(-1, hidden_channels, add_self_loops=False)
            #gat_11 = GATConv(-1, hidden_channels, add_self_loops=False)
            gat_2 = GATConv(-1, hidden_channels, add_self_loops=False)
            #gat_22 = GATConv(-1, hidden_channels, add_self_loops=False)
            gcn_0 = GCNConv(-1, hidden_channels, add_self_loops=False)
            #gcn_00 = GCNConv(-1, hidden_channels, add_self_loops=False)
            gcn_1 = GCNConv(-1, hidden_channels, add_self_loops=False)
            #gcn_11 = GCNConv(-1, hidden_channels, add_self_loops=False)
            conv = HeteroConv({
                ('Process', 'access', 'File'): gat_0,
                ('File', 'rev_access', 'Process'): gat_0,
                ('Process', 'create', 'Process'): gcn_0,
                ('Process', 'rev_create', 'Process'): gcn_0,
                ('Process', 'same_as', 'File'): gat_1,
                ('File', 'rev_same_as', 'Process'): gat_1,
                ('Process', 'bind', 'Port'): gat_2,
                ('Port', 'rev_bind', 'Process'): gat_2,
                ('Port', 'session', 'Port'): gcn_1,
                ('Port', 'rev_session', 'Port'): gcn_1,
            }, aggr='sum')
            convs.append(conv)

    return convs


class HeteroGNN(torch.nn.Module):
    def __init__(self, hgnn, hidden_channels=128, out_channels=2, num_layers=3):
        super().__init__()
        self.hgnn = hgnn
        self.convs = select_model(hgnn, num_layers=num_layers, hidden_channels=hidden_channels)
        self.lin_1 = Linear(hidden_channels, hidden_channels)
        self.lin_2 = Linear(hidden_channels, out_channels)
        self.dropout = torch.nn.Dropout(p=0.5)
        self.pool_type = 1

    def forward(self, data, bilstm=False):
        x_dict = data.x_dict
        for conv in self.convs:
            if self.hgnn == 'gat':
                x_dict = conv(x_dict, data.edge_index_dict)
            else:
                x_dict = conv(x_dict, data.edge_index_dict, data.edge_attr_dict)
            x_dict = {key: F.leaky_relu(x) for key, x in x_dict.items()}
        ret = select_pool(self.pool_type, x_dict, data.batch_dict, data.process_mask_dict)
        ret = self.dropout(ret)
        ret = self.lin_1(ret)
        ret = self.lin_2(ret)
        return ret
    
    def load(self, model_name):
        path = './save/model/albge/{}.pt'.format(model_name)
        assert(os.path.exists(path))
        return self.load_state_dict(torch.load(path), strict=True)


class Classifier(torch.nn.Module):
    # 大概要被弃置
    def __init__(self, hidden_channels=128, out_channels=2, num_layers=3, emb_size=384):
        super().__init__()
        self.lin = torch.nn.ModuleList()
        self.input_emb = nn.Linear(emb_size, hidden_channels)
        for i in range(num_layers):
            self.lin.append(nn.Linear(hidden_channels, hidden_channels))
        self.dropout = nn.Dropout(p=0.5)
        self.out = nn.Linear(hidden_channels, out_channels)
        self.init_weights()

    def init_weights(self,):
        initrange = 0.1
        for lin in self.lin:
            nn.init.uniform_(lin.weight, -initrange, initrange)
            nn.init.zeros_(lin.bias)
        nn.init.uniform_(self.input_emb.weight, -initrange, initrange)
        nn.init.zeros_(self.input_emb.bias)
        nn.init.uniform_(self.out.weight, -initrange, initrange)
        nn.init.zeros_(self.out.bias)

    def forward(self, input_):
        # 用了个resnet结构优化一下, 另一边也可以加一下, 效果估计会好不少
        x = self.input_emb(input_)
        for lin in self.lin:
            x = lin(x)
            x = F.leaky_relu(x)
        x += self.input_emb(input_)
        x = F.leaky_relu(x)
        x = self.dropout(x)
        ret = self.out(x)
        return ret

    def load(self, model_name):
        path = './save/model/classifier/{}.pt'.format(model_name)
        assert(os.path.exists(path))
        return self.load_state_dict(torch.load(path), strict=True)

class HGNN_zs(nn.Module):
    def __init__(self, hgnn, hidden_channels=64, out_channels=384, num_layers=2): # 128, 384, 1
        super().__init__()
        self.hgnn = hgnn
        self.convs = select_model(hgnn, num_layers=num_layers, hidden_channels=2*hidden_channels)
        self.pool_type = 1

        self.lin = torch.nn.ModuleList()
        self.lin.append(Linear(2*hidden_channels, hidden_channels))
        self.lin.append(Linear(hidden_channels, 2*hidden_channels))
        #self.lin.append(Linear(2*hidden_channels, out_channels))
        self.out = Linear(2*hidden_channels, out_channels)
        self.dropout = torch.nn.Dropout(p=0.5)
        self.p_dict = torch.load('./save/data/p_dict.pt')
        self.p_des = [x[0].unsqueeze(dim=0) for x in self.p_dict.values()]
        self.p_des = torch.cat(self.p_des)
        self.p_label = [x[1].unsqueeze(dim=0) for x in self.p_dict.values()]
        self.p_label = torch.cat(self.p_label)
        self.init_weights()

    def init_weights(self,):
        initrange = 0.1
        for lin in self.lin:
            nn.init.uniform_(lin.weight, -initrange, initrange)
            nn.init.zeros_(lin.bias)
        nn.init.uniform_(self.out.weight, -initrange, initrange)
        nn.init.zeros_(self.out.bias)

    def forward(self, data):
        x_dict = data.x_dict
        for conv in self.convs:
            if self.hgnn == 'gat':
                x_dict = conv(x_dict, data.edge_index_dict)
            else:
                x_dict = conv(x_dict, data.edge_index_dict, data.edge_attr_dict)
            x_dict = {key: F.leaky_relu(x) for key, x in x_dict.items()}
        bge = select_pool(self.pool_type, x_dict, data.batch_dict, data.process_mask_dict)
        # 得到图编码, 尝试加了一个resnet结构
        ret = bge
        for lin in self.lin:
            ret = lin(ret)
            ret = F.leaky_relu(ret)

        ret += bge
        ret = self.dropout(ret)
        ret = self.out(ret)

        return ret

    def load(self, model_name):
        path = './save/model/albge/{}.pt'.format(model_name)
        assert(os.path.exists(path))
        return self.load_state_dict(torch.load(path), strict=True)
