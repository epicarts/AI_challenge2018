import csv
import os
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
from gensim.models.doc2vec import Doc2Vec,TaggedDocument
import numpy as np

#이 함수는 API 시퀀스 순서는 보존하되 내가 원하는 API만 제거 후 반환.
def featureset_remove_fun(sentence,remove_features):
    '''
    sentence 문장, remove_features 제거할 특성들. 제거 된 상태로 나가게됨
    '''
    return [e for e in sentence if e not in (remove_features)]

#tscne 그리는 함수임.
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

'''
첫번째!!!!!!!!!!
Doc2vec 형태의 모델 만들기!!!!!!!!!
'''
#train할 모델을 만든뒤 tsne 로 시각화 시킨후 테스트를 할것이다.
os.chdir('D:\\AI_challenge\\trainmodel')#작업할 디렉토리 설정

#가장먼저 추출한 문자열 들을 가지고 옴
with open('../software_feature/behavior_api_order.csv', 'r', encoding='utf-8') as f:
    lines = csv.reader(f)
    software_sentences = [line for line in lines]
with open('../malware_feature/behavior_api_order.csv', 'r', encoding='utf-8') as f:
    lines = csv.reader(f)
    malware_sentences = [line for line in lines]
len(software_sentences) #2087개
len(malware_sentences)# 6056개


#여기는 onlymaware 와 onlysoftware 모델을 가져와서 빈도 수 순서대로 뽑아낼 수 있음. 전처리 가공.
features = []# 만약 추출할게 없다면 비워놔도 됨. 대신 생성은 해놓기.. 추후 수정.
software_model = Doc2Vec.load("dm1_mincount0_window10_vector_size50_onlysoftware.doc2vecmodel")
malware_model = Doc2Vec.load("dm1_mincount0_window10_vector_size50_onlymalware.doc2vecmodel")
soft_mal = Doc2Vec.load("dm1_mincount0_window10_vector_size50_soft_and_mal.doc2vecmodel")
#features = set(malware_model.wv.index2word[-50:]) - set(software_model.wv.index2word[-50:])
#features = set(software_model.wv.index2word[-50:]) - set(malware_model.wv.index2word[-50:])
features = set(software_model.wv.index2word[:100])&set(malware_model.wv.index2word[:100])#교집합.
features = soft_mal.wv.index2word[:100]#그냥 평범한 모델 API 빈도 순서


#doc2vec로 학습을 시키기 위해선 (words , tag 가 필요함)
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
vector_size = 50 #벡터 크기
min_count=0# 최소 단어 숫자
window = 10#컨텍스트 자를 크기
dm =1# 학습 방식. 문장 => 단어  / 단어 문장
addition_string = "_" + "soft_and_mal"# 추가로 적고 싶은 말
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

tscne_fun('dm1_mincount0_window10_vector_size50_onlysoftware.doc2vecmodel')
tscne_fun('dm1_mincount0_window10_vector_size50_soft_and_mal.doc2vecmodel')


'''
두번째!!!!!!!!!!!!!!!!!!!!!!!!!!
모델을 불러온 뒤 학습에 필요한 데이터를 변환함.

#모델을 만들었으니 학습 및 테스트를 해야함.
악성코드 6천개
소프트웨어 2800개 이므로 한번에 전부 다 학습하는건 악성코드쪽에 치우칠 과적합이 우려됨.
xgboost의 라벨에 가중치를 주는 방법으로 학습을 시킴
'''
#학습에 사용할 모델 load 시킴
doc2vec_model_name = "dm1_mincount0_window10_vector_size50_soft_and_mal.doc2vecmodel"
model = Doc2Vec.load(doc2vec_model_name)

#software문자열을 가져온뒤 학습 doc model에 넣고
software_vector = [model.infer_vector(sentence,alpha=0.025,min_alpha=0.025, epochs=30)
                 for sentence in software_sentences]
malware_vector = [model.infer_vector(sentence,alpha=0.025,min_alpha=0.025, epochs=30)
                 for sentence in malware_sentences]

#model.docvecs.most_similar([software_vector[8]])

software_arrays = np.array(software_vector)
software_labels = np.zeros(len(software_vector)) # 어처피 소프트웨어니까 0으로 초기화 시킬꺼임
software_arrays.shape
software_labels.shape

#malware_arrays = np.zeros((len(only_malware[:3000]), 100)) #여기서 50은 벡터 크기임
malware_arrays = np.array(malware_vector)
malware_labels = np.ones(len(malware_vector)) # 어처피 악성코드니까 1으로 초기화 시킬꺼임
malware_arrays.shape
malware_labels.shape

#데이터 셋 합치기.
arrays = np.vstack((software_arrays,malware_arrays))
labels = np.hstack((software_labels,malware_labels))

'''
세번째 !!!!!
여기서 부터는 본격적으로 xgboost 데이터 학습시킴
'''
import xgboost as xgb
from sklearn.model_selection import KFold
import collections
from sklearn.metrics import accuracy_score
from bayes_opt import BayesianOptimization


#학습을 튜닝하기전에 먼저 Kfold로 일부를 나누겟음.
kf_test = KFold(n_splits = 5, shuffle = True)
for train_index, test_index in kf_test.split(arrays):
    # split train/validation
    train_data, test_data  = arrays[train_index], arrays[test_index]
    train_labels, test_labels = labels[train_index], labels[test_index]
len(train_data)
len(test_data)

#밑에서 최적의 값을 가져와봤으므로 한번 kofld 에 넣어서 테스트 해보겠음.

'''
소스코드 출저는 여기
http://codingwiththomas.blogspot.com/2016/10/xgboost-bayesian-hyperparameter-tuning.html
kFoldValidation 수정좀 함.
'''

#kFold로 학습시킨후 평균을 내어 반환 하는 함수.
def kFoldValidation(train, features, xgbParams, numRounds, nFolds, target='loss'):#가장 마지막으로 호출됨.
    kf = KFold(n_splits = nFolds, shuffle = True)
    fold_score=[]
    for train_index, test_index in kf.split(train):
        # split train/validation
        X_train, X_valid = train[train_index], train[test_index]
        y_train, y_valid = features[train_index], features[test_index]
        dtrain = xgb.DMatrix(X_train, y_train)
        dvalid = xgb.DMatrix(X_valid, y_valid)
        watchlist = [(dtrain, 'train'), (dvalid, 'eval')]
        gbm = xgb.train(xgbParams, dtrain, numRounds, evals = watchlist,early_stopping_rounds = 50,verbose_eval=False)#verbose 옵션으로 나타나지 않게함
        score = gbm.best_score
        fold_score.append(score)
    return np.mean(fold_score)

def xgbCv(train, features, numRounds, eta, gamma, maxDepth, minChildWeight, subsample, colSample):
    # prepare xgb parameters
    params = {
        "objective": "reg:linear",
        "booster" : "gbtree",
        "eval_metric": "mae",
        "tree_method": 'auto',
        "silent": 1,
        "eta": eta,
        "max_depth": int(maxDepth),
        "min_child_weight" : minChildWeight,
        "subsample": subsample,
        "colsample_bytree": colSample,
        "gamma": gamma,
        "scale_pos_weight": 0.48#데이터 셋 비율  0/1 소프트웨어 / 악성코드
        }#적용할 파라미터들
    #순서대로 train 학습시킬 데이터, features 특징, 기준이 될 xgb 파라미터, numRounds 반복횟수, nFolds =
    cvScore = kFoldValidation(train, features, params, int(numRounds), nFolds = 5)
    print('CV score: {:.6f}'.format(cvScore))
    return -1.0 * cvScore   # invert the cv score to let bayopt maximize

def bayesOpt(train, features):#가장먼저 호출됨.
    train = train_data#테스트용 지울것
    features = train_labels#테스트용 지울것
    ranges = {
        'numRounds': (1000, 2000),
        'eta': (0.03, 0.1),
        'gamma': (0, 10),
        'maxDepth': (4, 10),
        'minChildWeight': (0, 10),
        'subsample': (0, 1),
        'colSample': (0, 1),
        }#학습에 따라 변경될 값들.
    # proxy through a lambda to be able to pass train and features
    optFunc = lambda numRounds, eta, gamma, maxDepth, minChildWeight, subsample, colSample: xgbCv(train, features, numRounds, eta, gamma, maxDepth, minChildWeight, subsample, colSample)
    bo = BayesianOptimization(optFunc, ranges)
    bo.maximize(init_points = 50, n_iter = 5, kappa = 2, acq = "ei", xi = 0.0)
    bestMAE = round((-1.0 * bo.res['max']['max_val']), 6)
    print("\n Best MAE found: %f" % bestMAE)
    print("\n Parameters: %s" % bo.res['max']['max_params'])#가장 최고의 파라미터 추출 나중에 리턴 받으면 될듯
    p = bo.res['max']['max_params']#가장 좋은 파라미터를 찾아서 p에 넣음.
    max_params = {
        'eta': float(p['eta']),
        'max_depth': int(p['maxDepth']),
        'subsample': max(min(p['subsample'], 1), 0),
        'objective': 'reg:linear',
        'silent': 1,
        'min_child_weight': int(p['minChildWeight']),
        'gamma': max(p['gamma'], 0),
        "objective": "reg:linear",
        "booster" : "gbtree",
        "eval_metric": "mae",
        "tree_method": 'auto',
        "silent": 1,
        "scale_pos_weight": 0.48
        }#가장 좋은 파라미터를 저장.

    with open(doc2vec_model_name+".txt", "w+") as f:
        numround = int(p['numRounds'])
        f.write(str(bestMAE) + 'numRounds: '+str(numround))
        f.write(str(max_params))
int(p['numRounds'])
p
max_params
#이런식으로 호출 하면됨.
#bayesOpt(arrays,labels)


max_params

dtrain = xgb.DMatrix(train_data, label=train_labels)
booster = xgb.train(max_params, dtrain, num_boost_round=1980)

dtest = xgb.DMatrix(test_data)
y_pred = booster.predict(dtest)
y_pred  = y_pred > 0.5
y_pred = y_pred.astype(int)
accuracy = accuracy_score(y_pred, test_labels)
print("Accuracy: %.2f%%" % (accuracy * 100.0))#예측률

import pickle
pickle.dump(booster,open("pima.pickle.dat","wb"))
loaded_model = pickle.load(open("pima.pickle.dat","rb"))
y_pred= loaded_model.predict(dtest)


booster.dump_model(doc2vec_model_name+'.xgboost')
xgb.load_model(doc2vec_model_name+'.xgboost')

#scale_pos_weight = len(software_arrays) / len(malware_arrays)## rate of 0/1 #
#xgboost 파라미터 설명 ..
'''
params = {
    #일반 파라미터
    'booster': 'gbtree',# gbtree : tree-based models #gblinear : linear models dart
    'n_jobs' : 'default', #멀티 쓰레드 개수 default가 가장 큼
    'silent': 0,#실행 메시지 출력 : 0 안하게 할라면 1

    #booster 파라미터
    'eta' : 0.02,# 학습률 . 일반적으로 0.01~ 0.2 가 사용. 부스팅 마다 변경 추천 과적합 방지
    'min_child_weight' : 1,# 기본값은 1 .
    'gamma' : 0 ,# 정보획득 값. 기본값 0
    'max_depth' : 6, #트리의 최대 깊이 기본값은 6
    'subsample':1,#기본값 1
    'lambda': 1 ,# 기본값 1 많이 사용안한다고 함
    'alpha':0,  # 기본값 0 # 한번 1넣어보는것도 ,,,>??
    'scale_pos_weight':scale_pos_weight,# 불균등한 클래스 . 여기선 사용할 예정

    #Task 파라미터
    'objective': 'multi:softmax', #목적 함수 기본은 reg:linear 여기서사용된건 예측클래스 반환
    'eval_metric': 'merror',#평가 함수
    'num_class': 2#multi:softmax' 를 사용하려면 정의해야됨. 클래스 수}
'''

'''
bayes_opt 공식 홈페이지에 있는 파라미터 튜닝 방법.
params = {
    'eta': 0.1,
    'silent': 1,
    'eval_metric': 'mae',
    'verbose_eval': True,
    'seed': random_state
    } # 약간 전역변수 같은 느낌..... 이값을 기준으로 추가
xgtrain = xgb.DMatrix(train_x, label = train_y)#얘도 약간 전역변수 같은 느낌 ..?
num_rounds = 100# 얘도 전역변수 같은 느낌 ??
random_state = 1234

xgb_range = {
    'min_child_weight': (1, 20),
    'colsample_bytree': (0.1, 1),
    'max_depth': (5, 15),
    'subsample': (0.5, 1),
    'gamma': (0, 10),
    'alpha': (0, 10),
    }#변경시킬 값들.

#파라미터 값이 자동으로 변경될 모델을 만듬.
def xgb_evaluate(min_child_weight,colsample_bytree,max_depth,subsample,gamma,alpha):
    params['min_child_weight'] = int(min_child_weight)
    params['cosample_bytree'] = max(min(colsample_bytree, 1), 0)
    params['max_depth'] = int(max_depth)
    params['subsample'] = max(min(subsample, 1), 0)
    params['gamma'] = max(gamma, 0)
    params['alpha'] = max(alpha, 0)
    #nfold = 5
    cv_result = xgb.cv(params, xgtrain, num_boost_round=num_rounds, nfold=5,
                       seed=random_state,callbacks=[xgb.callback.early_stop(50)])
    return -cv_result['test-mae-mean'].values[-1]
#BayesianOptimization함수에 각각 학습시킬 함수와 파라미터를 넣음 .. 더 깊은 이해 필요.
xgbBO = BayesianOptimization(xgb_evaluate, xgb_range)
num_iter = 25 #아직 무슨 값인지 모르겠음.
init_points = 5#아직 무슨 값인지 모르겠음.
xgbBO.maximize(init_points=init_points, n_iter=num_iter)#이거 실행하면 돌아감.





model = xgb.train(xgb_params, xgtrain, num_boost_round=1000, verbose_eval=False, maximize=True)
dtest = xgb.DMatrix(test_x)
y_pred = model.predict(dtest)
y_pred  = y_pred > 0.5
y_pred = y_pred.astype(int)
accuracy = accuracy_score(test_y, y_pred)
print("Accuracy: %.2f%%" % (accuracy * 100.0))#예측률



 def xgb_evaluate(min_child_weight,colsample_bytree,max_depth,subsample,gamma,alpha):
     params['min_child_weight'] = int(min_child_weight)
     params['cosample_bytree'] = max(min(colsample_bytree, 1), 0)
     params['max_depth'] = int(max_depth)
     params['subsample'] = max(min(subsample, 1), 0)
     params['gamma'] = max(gamma, 0)
     params['alpha'] = max(alpha, 0)
     cv_result = xgb.cv(params, xgtrain, num_boost_round=num_rounds, nfold=5,
                        seed=random_state,callbacks=[xgb.callback.early_stop(50)])
     return -cv_result['test-mae-mean'].values[-1]

'''


########################오로지 학습만을 위한 공간 지울것.
    os.chdir('D:\AI_challenge\\best')
    doc2vec_model_name = "docmodel_epoch30_vector100_mincount0_window40_sm_newtag"
    model = Doc2Vec.load(doc2vec_model_name)

    #software문자열을 가져온뒤 학습 doc model에 넣고
    software_vector = [model.infer_vector(sentence,alpha=0.025,min_alpha=0.025, epochs=30)
                     for sentence in software_sentences]
    malware_vector = [model.infer_vector(sentence,alpha=0.025,min_alpha=0.025, epochs=30)
                     for sentence in malware_sentences]

    #model.docvecs.most_similar([software_vector[8]])

    software_arrays = np.array(software_vector)
    software_labels = np.zeros(len(software_vector)) # 어처피 소프트웨어니까 0으로 초기화 시킬꺼임
    software_arrays.shape
    software_labels.shape

    #malware_arrays = np.zeros((len(only_malware[:3000]), 100)) #여기서 50은 벡터 크기임
    malware_arrays = np.array(malware_vector)
    malware_labels = np.ones(len(malware_vector)) # 어처피 악성코드니까 1으로 초기화 시킬꺼임
    malware_arrays.shape
    malware_labels.shape

    #데이터 셋 합치기.
    arrays = np.vstack((software_arrays,malware_arrays))
    labels = np.hstack((software_labels,malware_labels))
    bayesOpt(arrays,labels)
