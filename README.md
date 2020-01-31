# AI_challenge2018

> 정보보호 R&D 챌린지2018에 사용했던 머신러닝 기법들을 정리해 놓았다. 사이트 링크: http://datachallenge.kr/


- 언어는 python으로 되어있으며, 쥬피터 노트북을 이용하여 추후 사용하기 쉽게 정리해 놓았다.

- ipython으로 정리해놓았고, 일반 *.py 파일들은 사용했던 주요 코드를 모아놓았다.

- 추출된 String 데이터와 API 데이터는 암호화 되어있으며, 원본데이터는 올려놓지 않았다.


## dynamic_analysis/
- cuckoo 샌드박스로 API 를 추출하여 머신러닝 모델을 설계하였다
- malware_feature와 software_featrue 는 암호로 잠겨있다.


## static_analysis/
- 위의 동적 분석을 이용하여 진행하고 있었으나, 대회시간 안에 동적분석을 못 끝낼 거 같아 대회진행 도중에 만들었다.
- 파일 내의 유니코드 문자열을 추출하여 머신러닝 모델을 설계하였다.
- [string추출 소프트웨어](https://docs.microsoft.com/ko-kr/sysinternals/downloads/strings)


## tsne.ipynb
> 만들어진 모델을 T-SNE을 사용하여 2차원으로 표현

![tsne](https://user-images.githubusercontent.com/17478634/73534449-81018400-4464-11ea-8dfd-b14eac67eacf.png)
- 악성코드 = 빨강색, 소프트웨어 = 파랑색으로 2차원에 표현하였다.

![api_tsne](https://user-images.githubusercontent.com/17478634/73534487-970f4480-4464-11ea-9296-b1b536613278.png)
- API 관계를 2차원에 표현하였다.


## Hierachical Clustering.ipynb
> 데이터 군집화 방법 중 하나로 계층적으로 군집화를 시키는 방법이다. 가까운 데이터끼리 묶기 좋은 방법으로 vector화 시켰을 때 거리가 가까운 데이터끼리 묶인 후 2차로 분류 해볼까 하여 시도해보았다.

![캡처](https://user-images.githubusercontent.com/17478634/73538093-6b448c80-446d-11ea-8ce5-839382cbfc9c.PNG)
- ward옵션: 모든 클러스터 내의 분산을 가장 작게 증가시키는 두 클러스터를 합치는 방법
- Doc2Vec => Clustering => T-SNE를 사용
