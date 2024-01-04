### File Structure:

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

### Dependencies

- Python 3                  3.8.13
- pytorch                   1.12.1
- networkx                  2.8.6
- torch-geometric           2.1.0.post1
- matplotlib                3.5.3
- tqdm                      4.64.1

### How to use

The "./save/data" folder includes all generated .pt files. You can divide them into training_set and testing_set, and use them for model training. Thus you could skip steps 1-5.

1. Download ATLAS dataset from https://github.com/purseclab/ATLAS/tree/main/raw_logs .
2. Move "security_events.txt" and "malicious_labels.txt" from each ATLAS raw_logs into "./raw_data/auditlog/[folder_name]/" .
3. Execute the command "python graph_generator.py" to generate the provenance graph of each attack simulation. The generated graph will be saved in "./save/gml/*.gml" .
4. Divide those *.gml files into training_set and testing_set, place them in "./save/gml/train/" & "./save/gml/test/" .
5. Execute the command "python train_data_generator.py" to extract behavior graph of process entities. It will generate *.pt file in "./save/data/train/" and "./save/data/test/" respectively
6.
