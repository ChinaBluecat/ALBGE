### ALBGE

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
- torch-geometric           2.1.0
- matplotlib                3.5.3
- tqdm                      4.64.1

### How to use

- 1. Download ATLAS dataset from https://github.com/purseclab/ATLAS/tree/main/raw_logs .
- 2. Move "security_events.txt" and "malicious_labels.txt" from each ATLAS raw_logs into "./raw_data/auditlog/[folder_name]/" .
- 3. Execute the command "python graph_generator.py" to generate the provenance graph of each attack simulation. The generated graph will be saved in "./save/gml/*.gml" .
- 4. Divide those *.gml files into training_set and testing_set, move them into "./save/gml/train/" & "./save/gml/test/" folders respectively.
- 5. Execute the command "python train_data_generator.py" to extract behavior graph of process entities. It will generate *.pt file in "./save/data/train/" and "./save/data/test/" path respectively.
- 6. Execute the command "python training.py -h", you can change the parameters as your wish, or just execute the command "python training.py" with default setting. Training results output in "./save/trace", "./utils/plot_.py" can be used for diagram ploting.

We provide generated "provenance_graph" and "behavior_graph" dataset to reproduce our experiment. If you use them, you can skip the step 1 to 5. Download: https://drive.google.com/drive/folders/18PZz2wcsCKJN17gLiDLRJMltQ04bLi43?usp=drive_link
