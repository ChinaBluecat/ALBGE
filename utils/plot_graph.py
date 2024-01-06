import networkx as nx
import matplotlib.pyplot as plt


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



path = 'D:\\WorkSpace\\写论文\\Anti-IDS\\实验代码\\paper_experiment\\新建文件夹\\mycode\\整理\\save\\gml\\train\\M4H2.gml'#input('[*] path2gml')
G_ = nx.read_gml(path)
#input(list(G_.nodes(data=True))[:10])

mal_nodes = [x for x in G_.nodes() if G_.nodes('is_malicious')[x]==1]
input(mal_nodes)

for node in mal_nodes:
    G = find_nodetree(G_, node)
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True)
    #nx.draw(G, with_labels=True)
    plt.show()
