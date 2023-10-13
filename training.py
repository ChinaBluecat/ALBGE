# coding=utf-8
from torch_geometric.nn import HeteroConv, GCNConv, SAGEConv, GATConv, Linear, HGTConv
from torch_geometric.loader import DataLoader
from utils.models import HeteroGNN
from typing import Optional
from tqdm import tqdm
import torch_geometric.transforms as T
import torch.nn.functional as F
import utils.config as config
import networkx as nx
import numpy as np
import torchmetrics
import torch
import os


# ---------------------------------------------------------------------
def load_dataset_from_folder(folder_path, batch_size=24):
    pt_dir = os.listdir(folder_path)
    data_list = []
    for filename in tqdm(pt_dir, desc='[-] Reading ptfiles', unit_scale=False):
        pt_path = os.path.join(folder_path, filename)
        data_list += torch.load(pt_path)
    for data in data_list:
        data = T.ToUndirected()(data)
        data = data.pin_memory()
        data = data.to('cuda:0', non_blocking=True)
    dataset = DataLoader(data_list, batch_size=batch_size, shuffle=True)
    return dataset

# ---------------------------------------------------------------------
def train(loader, epoch, num_epochs):
    model.train()
    loss_ = 0
    acc = torchmetrics.Accuracy(task="binary", average='none')
    tqdm_loop = tqdm((loader), total=len(loader))
    for data in tqdm_loop:
        optimizer.zero_grad()
        out = model(data)

        pred = F.softmax(out, dim=1).argmax(dim=1)
        loss = criterion(out, data['y'])
        loss.backward()
        optimizer.step()
        loss_ += loss
        acc(pred.cpu(), data['y'].cpu())

        tqdm_loop.set_description(f'Epoch [{epoch}/{num_epochs}]')
        tqdm_loop.set_postfix(loss=loss.item(), acc=acc.compute().item())
    return


def eval(loader, j):
    acc = torchmetrics.Accuracy(task="binary", average='none')
    recall = torchmetrics.Recall(task="binary", average='none')
    precision = torchmetrics.Precision(task="binary", average='none')
    auc = torchmetrics.AUROC(task="multiclass", average="macro", num_classes=2)
    f1 = torchmetrics.F1Score(task="binary")
    roc = torchmetrics.classification.BinaryROC()

    model.eval()

    loss = 0
    TP, TN, FP, FN = 0, 0, 0, 0

    with torch.no_grad():
        for data in loader:
            y = data['y'].cpu()
            out = model(data).cpu()
            pred = F.softmax(out, dim=1).argmax(dim=1)
            pred = pred.float()
            loss += criterion(out, y)

            tp = int(((pred == y)*pred).sum())
            tn = int((pred == y).sum()) - tp
            fp = int(((pred != y)*pred).sum())
            fn = int((pred != y).sum()) - fp

            TP += tp
            TN += tn
            FP += fp
            FN += fn

            auc.update(F.softmax(out, dim=1), y)
            acc(pred, y)
            recall(pred, y)
            precision(pred, y)
            f1(pred, y)
            roc.update(F.softmax(out, dim=1)[:, 1], y)
    fpr, tpr, thresholds = roc.compute()
    print('[*] {}_acc: {}'.format(j, acc.compute().item()))
    return [(TP, TN, FP, FN),
            auc.compute().item(),
            acc.compute().item(),
            recall.compute().item(),
            precision.compute().item(),
            f1.compute().item(),
            (fpr, tpr, thresholds)]

# ---------------------------------------------------------------------
def save_metrics(name, train_metrics, test_metrics):
    train_dict = {
        'TP_TN_FP_FN': [x[0] for x in train_metrics],
        'AUROC': [x[1] for x in train_metrics],
        'ACCURACY': [x[2] for x in train_metrics],
        'RECALL': [x[3] for x in train_metrics],
        'PRECISION': [x[4] for x in train_metrics],
        'F1': [x[5] for x in train_metrics],
        'ROC': train_metrics[-1][6]#[x[6] for x in train_metrics],
    }
    test_dict = {
        'TP_TN_FP_FN': [x[0] for x in test_metrics],
        'AUROC': [x[1] for x in test_metrics],
        'ACCURACY': [x[2] for x in test_metrics],
        'RECALL': [x[3] for x in test_metrics],
        'PRECISION': [x[4] for x in test_metrics],
        'F1': [x[5] for x in test_metrics],
        'ROC': test_metrics[-1][6]#[x[6] for x in test_metrics],
    }
    dic = {
        'train_metrics': train_dict,
        'test_metrics': test_dict
    }
    return np.save('./save/trace/{}_metrics.npy'.format(name), dic)

# ---------------------------------------------------------------------
if __name__ == '__main__':
    config.__init__()
    args = config.parser.parse_args()
    TRAIN = args.train
    EPOCHS = args.epochs
    BATCH = args.batch  # S1-4实验时, 必须设为1
    outfile_name = args.outname
    hgnn = args.hgnn
    hc = args.hc
    nl = args.nl

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model = HeteroGNN(hgnn, hidden_channels=hc, num_layers=nl).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=5e-3, weight_decay=1e-4)
    criterion = torch.nn.CrossEntropyLoss()

    train_dataset = load_dataset_from_folder('./save/data/train', batch_size=BATCH)
    test_dataset = load_dataset_from_folder('./save/data/test', batch_size=BATCH)
    # input(test_dataset.dataset[3])
    # for d in test_dataset:
    #     input(d)

    train_metrics = []
    test_metrics = []
    best_score = 0
    best_metrics = None

    # 这里需要调整一下, 因为很多次 1.0的得分, 导致没更新最优
    if TRAIN:
        for epoch in range(EPOCHS):
            train(train_dataset, epoch, EPOCHS)
            train_metrics.append(eval(train_dataset, 'train'))
            test_metrics.append(eval(test_dataset, 'test'))
            if test_metrics[-1][1] >= best_score:
                best_score = test_metrics[-1][1]
                best_metrics = test_metrics[-1]
                torch.save(model.state_dict(), './save/model/albge/{}.pt'.format(outfile_name))
        print('[*] Best result:')
        print(best_metrics)
        save_metrics(outfile_name, train_metrics, test_metrics)
    else:
        loadname = args.loadname
        model.load(loadname)
        test_metrics.append(eval(test_dataset, 'test'))
        print('[*] Eval result:')
        print(test_metrics)

