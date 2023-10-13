import argparse


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
    parser.add_argument('--train', type=str2bool, default=True, help='training or not')

    parser.add_argument('--hgnn', type=str, default='albge', help='[hgt, han, gat, albge]')
    parser.add_argument('--hc', type=int, default=128, help='hidden channels')
    parser.add_argument('--nl', type=int, default=3, help='num layers')
    #parser.add_argument('--classifier')
    #args = parser.parse_args()
