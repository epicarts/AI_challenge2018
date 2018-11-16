# AI_challenge2018

정보보호 R&D 챌린지2018에 사용했던 머신러닝 기법들을 정리해 놓았다.
사이트 링크: http://datachallenge.kr/


언어는 python으로 되어있으며, 쥬피터 노트북을 이용하여 추후 사용하기 쉽게 정리해 놓았다.

ipython으로 정리해놓았고, 일반 .py 파일들은 사용했던 주요 코드를 모아놓았기 때문에 알아보기 힘들다.


# dynamic_analysis
cuckoo 샌드박스로 API 를 추출하여 머신러닝 모델을 설계하였다
malware_feature와 software_featrue 는 암호로 잠겨있다.



# static_analysis
위의 동적 분석을 이용하여 진행하고 있었으나, 대회시간 안에 동적분석을 못 끝낼 거 같아 만들었다.
파일 내의 유니코드 문자열을 추출하여 머신러닝 모델을 설계하였다.
