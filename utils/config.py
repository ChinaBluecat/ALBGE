import argparse
import os

def welcome():
    welcome_ = '''
  ___ ___
 /   |   \_____  ______ ______ ___.__.
/    ~    \__  \ \____ \\____ <   |  |
\    Y    // __ \|  |_> >  |_> >___  |
 \___|_  /(____  /   __/|   __// ____|
       \/      \/|__|   |__|   \/
_________            .___.__              ._.
\_   ___ \  ____   __| _/|__| ____    ____| |
/    \  \/ /  _ \ / __ | |  |/    \  / ___\ |
\     \___(  <_> ) /_/ | |  |   |  \/ /_/  >|
 \______  /\____/\____ | |__|___|  /\___  /__
        \/            \/         \//_____/ \/
'''
    print(welcome_)
    if not os.path.exists('./save'):
        os.mkdir('./save')
    if not os.path.exists('./save/data'):
        os.mkdir('./save/data')
    if not os.path.exists('./save/data/train'):
        os.mkdir('./save/data/train')
    if not os.path.exists('./save/data/test'):
        os.mkdir('./save/data/test')
    if not os.path.exists('./save/gml'):
        os.mkdir('./save/gml')
    if not os.path.exists('./save/gml/train'):
        os.mkdir('./save/gml/train')
    if not os.path.exists('./save/gml/test'):
        os.mkdir('./save/gml/test')
    if not os.path.exists('./save/model'):
        os.mkdir('./save/model')
    if not os.path.exists('./save/model/albge'):
        os.mkdir('./save/model/albge')
    if not os.path.exists('./save/trace'):
        os.mkdir('./save/trace')
    return 'Happy Coding!'
parser = argparse.ArgumentParser(description=welcome())



def str2bool(x):
    if x.lower() in ('true'):
        return True
    elif x.lower() in ('false'):
        return False
    else:
        return None

def __init__():
    parser.add_argument('--epochs', type=int, default=100)
    parser.add_argument('--batch', type=int, default=20)
    parser.add_argument('--outname', type=str, default='MyTest00', help='output file name')
    parser.add_argument('--loadname', type=str, default='MyTest00', help='load model name')
    parser.add_argument('--train', type=str2bool, default=True, help='training or not ')

    parser.add_argument('--hgnn', type=str, default='albge', help='[hgt, han, gat, albge]')
    parser.add_argument('--hc', type=int, default=128, help='hidden channels')
    parser.add_argument('--nl', type=int, default=3, help='num layers')
    #parser.add_argument('--classifier')
    #args = parser.parse_args()
