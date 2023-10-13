import matplotlib.pyplot as plt
import numpy as np
import os


'''
看看可以画ROC曲线, 是否要追加一下ROC指标记录, 或者直接用AUC画?

[(TP, TN, FP, FN),
        #(loss / len(loader)).item(),
        auc.compute().item(),
        acc.compute().item(),
        recall.compute().item(),
        precision.compute().item(),
        f1.compute().item(),
        (fpr, tpr, thresholds)]

各项数据都可以画了

'''

def load_metrics(file_name):
    dic = np.load('./save/output/{}_metrics.npy'.format(file_name), allow_pickle=True)
    #input(dic.item())
    #input(dic.item()['train_metrics']['TP_TN_FP_FN'])
    #input(dic.item()['test_metrics']['TP_TN_FP_FN'])
    #input(dic.item()['train_metrics'].keys())
    return dic.item()['train_metrics'], dic.item()['test_metrics']

def load_metrics_from_folder(folder_path):
    import os
    metrics = {}
    npy_dir = os.listdir(folder_path)
    for filename in tqdm(npy_dir, desc='[-] Reading npyfiles', unit_scale=False):
        npy_path = os.path.join(folder_path, filename)
        metrics[filename] = np.load(npy_path, allow_pickle=True)
    return metrics




def plot_(title_name, train_metrics, test_metrics):
    # 打印 auc, acc, recall, precision, f1
    fig, (ax1, ax2) = plt.subplots(2, 1)
    x = range(len(train_metrics['ACCURACY']))
    ax1.set_title(title_name)
    ax1.set_ylabel('num')
    ax2.set_ylabel('num')
    ax1.plot(x, train_metrics['PRECISION'], label='train_pre')
    ax2.plot(x, train_metrics['F1'], label='train_f1')
    ax1.plot(x, test_metrics['PRECISION'], label='test_pre')
    ax2.plot(x, test_metrics['F1'], label='test_f1')
    plt.xlabel('epochs')
    ax1.legend()
    ax2.legend()
    plt.show()
    return

def plot_roc(title_name, test_metrics):
    # 这个要把所有的内容都读入, 再画
    fig, ax = plt.subplots()
    ax.set_title('ROC Curve')
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    roc = test_metrics['ROC']
    input(roc)
    fpr = [x for x in roc[0]]
    tpr = [x for x in roc[1]]
    ax.plot(fpr, tpr, label='{}'.format(title_name))
    ax.legend()
    plt.show()

def plot_all_roc(path):
    import random
    linestyle_dic = ['-', ':', '--', '-.']
    fig, ax = plt.subplots()
    ax.set_title('ROC Curve(process entitity)')
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    metrics_dir = os.listdir(path)
    for filename in metrics_dir:
        metrics_path = os.path.join(path, filename)
        dic = np.load(metrics_path, allow_pickle=True)
        roc = dic.item()['test_metrics']['ROC']
        #input(dic.item()['test_metrics']['AUROC'])
        fpr = roc[0]#[x for x in roc[0]]
        tpr = roc[1]#[x for x in roc[1]]
        ax.plot(fpr, tpr, label='{}'.format(filename.split('_metrics')[0]), linestyle=random.choice(linestyle_dic), alpha=0.5,)# drawstyle='steps')
        ax.legend()
    plt.show()

def echo_precision_recall_f1(path):
    metrics_dir = os.listdir(path)
    format_ = '| {:3} | {:5} | {:5} | {:5} | {:5} | {:5.3f} | {:5.3f} | {:5.3f} |'
    format_1 = '| {:3} | {:5} | {:5} | {:5} | {:5} | {:5} | {:5} | {:5} |'
    print(format_1.format('ID', 'tp', 'tn', 'fp', 'fn', 'pre', 'rec', 'f1'))

    for filename in metrics_dir:
        metrics_path = os.path.join(path, filename)
        dic = np.load(metrics_path, allow_pickle=True)
        f1 = dic.item()['test_metrics']['F1']
        index_ = f1.index(max(f1))  # 取出效果最好的那些=。=
        precision = dic.item()['test_metrics']['PRECISION'][index_]
        recall = dic.item()['test_metrics']['RECALL'][index_]
        f1 = dic.item()['test_metrics']['F1'][index_]
        tp, tn, fp, fn = dic.item()['test_metrics']['TP_TN_FP_FN'][index_]
        # print('[-] {}'.format(filename))
        # print('[*] precision: {}'.format(precision))
        # print('[*] recall: {}'.format(recall))
        # print('[*] f1: {}'.format(f1))



        print(format_.format(filename.split('_metrics')[0], tp, tn, fp, fn, precision, recall, f1))

'''
[(TP, TN, FP, FN),
        auc.compute().item(),
        acc.compute().item(),
        recall.compute().item(),
        precision.compute().item(),
        f1.compute().item(),
        roc.compute().item()]
'''


if __name__ == '__main__':
    # input_name = input('[*] read file name: ')
    # load_score(input_name)
    # print(len(train_acc_list))
    # plot_(input_name)
    # #input('[*]')
    #train_metrics, test_metrics = load_metrics('M-6')
    #plot_('test_00', train_metrics, test_metrics)
    #plot_roc('test_00', test_metrics)
    #plot_all_roc('./save/output')
    #echo_precision_recall_f1('./save/output')
    #train_metrics, test_metrics = load_metrics('fix_0')
    #plot_roc('fix_0', test_metrics)
    #plot_('fix_0', train_metrics, test_metrics)

    plot_all_roc('../save/trace')
    echo_precision_recall_f1('../save/trace')

