import csv
import os
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
from gensim.models.doc2vec import Doc2Vec,TaggedDocument
import numpy as np

doc2vec_model_name = "D:\AI_challenge_result\github\dynamic_analysis\Doc2vec_model_vector30_window15_dm0"
model = Doc2Vec.load(doc2vec_model_name)

vector = []
for i in range(10):
    vector.append(model.infer_vector(['a','d','v','asfsafasf'],alpha=0.1,min_alpha=0.1, epochs=10000))

model.docvecs.most_similar([vector[2]])

model.docvecs.most_similar([vector[2]])

vector

vector
