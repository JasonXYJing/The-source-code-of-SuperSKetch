from detect import *
from supersketch import *
from superhost import *
import datetime


def test(n, p, u):
    start = datetime.datetime.now()
    ssketch = SuperSketch(n, p, u)
    filename = 'filename'
    experiment = Experiment(filename)
    experiment.ssketch = ssketch
    experiment.spreader_real = spreader[filename]
    experiment.changer_real = changer[filename]
    experiment.receiver_real = receiver[filename]
    experiment.step1()
    experiment.step2()
    end = datetime.datetime.now()
    print('Running time : {}'.format(end-start))  # running time


if __name__ == '__main__':
    test(5, [40009,40013,40031,40037,40039], [401, 409, 419, 421, 431])



'''
[10007, 10009, 10037, 10039, 10061, 10067, 10069]
[20011, 20021, 20023, 20029, 20047, 20051, 20063]
[30011, 30013, 30029, 30047, 30059, 30071, 30089]
[40009,40013,40031,40037,40039,40063,40087]
[50021,50023,50033,50047,50051,50053,50069]
[60013,60017,60029,60037,60041,60077,60083]



[211, 223 ,227 ,229, 233,  239, 241 ]
[401, 409, 419, 421, 431, 433, 439]
[601, 607, 613, 617 ,619 ,631 ,641]
[809 ,811, 821, 823, 827,829, 839]
[ 1009 ,1013 ,1019 ,1021, 1031, 1033 ,1039]


'''

