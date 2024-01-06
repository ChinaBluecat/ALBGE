### ALBGE

### 目录结构:

- root
  - raw_data
    - auditlog
      - M1H1
        - malicious_labels.txt
        - security_events.txt
      - M1H2
      - ...
  - save
    - data
      - train
      - test
    - gml
      - train
      - test
    - model
      - albge
    - trace
  - utils
  - tools


### 依赖

- Python 3                  3.8.13
- pytorch                   1.12.1
- networkx                  2.8.6
- torch-geometric           2.1.0
- matplotlib                3.5.3
- tqdm                      4.64.1

### 如何使用

1. 下载 ATLAS 数据集。地址: https://github.com/purseclab/ATLAS/tree/main/raw_logs
2. 将 raw_data 中的 security_events, malicious_labels 文件放至 ./raw_data/auditlog/... 路径下, 每一份攻击样本单独一个文件夹
3. 执行 "python graph_generator.py", 将原始日志处理为溯源图, 根据样本名存至./save/gml/ 路径下
4. 手工将作为训练集与测试集的日志分别放入 ./save/gml/train & ./save/gml/test.
5. 执行 "python train_data_generator.py", 将提取行为图并存至 ./save/data/train & ./save/data/test 路径
6. 执行 "python training.py -h" 可查看训练脚本帮助, 或直接执行 "python training.py" 使用默认参数进行训练。结果保存到 ./save/trace 路径下, 可以使用 ./utils/plot_.py 绘制图表

我们提供预处理后生成的 provenance_graph 与 behavior_graph 文件, 可直接用于复现实验。下载地址: https://drive.google.com/drive/folders/18PZz2wcsCKJN17gLiDLRJMltQ04bLi43?usp=drive_link
