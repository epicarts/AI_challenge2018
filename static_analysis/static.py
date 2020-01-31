import sys
import subprocess
import glob
import os
import csv
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
from gensim.models.doc2vec import Doc2Vec,TaggedDocument
import numpy as np

def featureset_remove_fun(sentence,remove_features):
    '''
    sentence 문장, remove_features 제거할 특성들. 제거 된 상태로 나가게됨
    '''
    return [e for e in sentence if e not in (remove_features)]

def tscne_fun(model_name):
    '''
    model_name 으로 doc2vec 의 모델 이름을 넣어 주면됨.
    '''
    model = Doc2Vec.load(model_name)
    tags = list(model.docvecs.doctags.keys())#dpcvecs에서 태그 데이터 가져옴.
    software_idx = []
    malware_idx = []
    for i, tag in enumerate(tags):
        if tag.split('_')[0] == 'software':
            software_idx.append(i)#software의 배열 위치를 저장..
        if tag.split('_')[0] == 'malware':
            malware_idx.append(i)#software의 배열 위치를 저장.
    tsne = TSNE(n_components=2).fit(model.docvecs.doctag_syn0)#2차원으로 변환시킴
    datapoint = tsne.fit_transform(model.docvecs.doctag_syn0)
    fig = plt.figure()#특징 설정
    fig.set_size_inches(40, 20)# 크기 셋팅
    ax = fig.add_subplot(1, 1, 1) #subplot 생성

    #악성코드 그리기. datapoint[malware_idx,0] x좌표,  datapoint[malware_idx,1] y 좌표
    ax.scatter(datapoint[malware_idx,0], datapoint[malware_idx,1],c='r')
    #소프트웨어  그리기
    ax.scatter(datapoint[software_idx,0], datapoint[software_idx,1],c='b')
    fig.savefig(model_name+'.png')


os.chdir('D:\VM_virtualBox\software')
#소프트 웨어에서 모든 파일 추출
test = []
f = open('..\\software_string.csv', 'w', encoding='utf-8', newline='')
for input_file in glob.glob('*'):#현재 폴더의 모든 파일이름 추출
    test = []
    command = "D:\\VM_virtualBox\\Strings\\strings.exe -u D:\\VM_virtualBox\\software\\"
    bstrs = subprocess.check_output(command+input_file)
    for bstr in bstrs.split():
        string = bstr.decode()
        test.append(str(string))
    wr = csv.writer(f)
    wr.writerow(test)
f.close()


with open('../software_string.csv', 'r', encoding='utf-8') as f:
    lines = csv.reader(f)
    sentences = [line for line in lines]
len(sentences)


#악성코드 폴더 이동후 추출
os.chdir('D:\VM_virtualBox\malware')
test = []
f = open('..\\malware_string.csv', 'w', encoding='utf-8', newline='')
for input_file in glob.glob('*'):#현재 폴더의 모든 파일이름 추출
    test = []
    command = "D:\\VM_virtualBox\\Strings\\strings.exe -u D:\\VM_virtualBox\\malware\\"
    bstrs = subprocess.check_output(command+input_file)
    for bstr in bstrs.split():
        string = bstr.decode()
        test.append(str(string))
    wr = csv.writer(f)
    wr.writerow(test)
f.close()


with open('../software_string.csv', 'r', encoding='utf-8') as f:
    lines = csv.reader(f)
    software_sentences = [line for line in lines]
with open('../malware_string.csv', 'r', encoding='utf-8') as f:
    lines = csv.reader(f)
    malware_sentences = [line for line in lines]
len(software_sentences)
len(malware_sentences)


features=[]

tagged_data =[]
#word = ['word1', 'word2', 'word3', 'word4'....], tags = ['software_숫자'] 소프트웨어
for i,sentence in enumerate(software_sentences):
    tagged_data.append(TaggedDocument(words = featureset_remove_fun(sentence,features)
                                      , tags = ['software_'+str(i)]))
#word = ['word1', 'word2', 'word3', 'word4'....], tags = ['malware_숫자'] 악성코드
for i,sentence in enumerate(malware_sentences):
    tagged_data.append(TaggedDocument(words = featureset_remove_fun(sentence,features)
                                      , tags = ['malware_'+str(i)]))

#Doc2vec에 학습시킬 데이터 입력
vector_size = 100 #벡터 크기
min_count=1000# 최소 단어 숫자
window = 50#컨텍스트 자를 크기
dm =0# 학습 방식. 문장 => 단어  / 단어 문장
addition_string = "_" + "test3"# 추가로 적고 싶은 말
model = Doc2Vec(vector_size=vector_size,#300이엿음
                alpha=0.025,
                min_alpha=0.025,
                min_count=min_count,
                window = window,
                dm =dm,
                worker_count =6,
                train_lbls=False
                )
model.build_vocab(tagged_data) # 사전 빌드 하기.
model.train(tagged_data,total_examples=model.corpus_count, epochs=30)
doc2vec_model_name = "dm" +str(dm)+ "_mincount" + str(min_count)+ "_window" +str(window)+"_vector_size" +str(vector_size)+ str(addition_string) +".doc2vecmodel"
model.save(doc2vec_model_name)#학습 완료 후 저장.

#tscne 모델 생성
tscne_fun(doc2vec_model_name)


#xgboost로 학습
import xgboost as xgb
from xgboost import XGBClassifier
from xgboost import plot_importance
from matplotlib import pyplot
import pandas as pd

kf_test = KFold(n_splits = 5, shuffle = True)
for train_index, test_index in kf_test.split(arrays):
    # split train/validation
    train_data, test_data  = arrays[train_index], arrays[test_index]
    train_labels, test_labels = labels[train_index], labels[test_index]
len(train_data)
len(test_data)
