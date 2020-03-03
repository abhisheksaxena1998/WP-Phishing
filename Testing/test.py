def warn(*args, **kwargs):
    pass
import warnings
warnings.warn = warn
import warnings

warnings.filterwarnings(action = 'ignore')

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.metrics import classification_report
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix
import pandas as pd 
from sklearn.model_selection import train_test_split
import numpy as np
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
import pickle
from sklearn.externals import joblib 

import whois
import datetime
text=input()
aburl=-1
digits="0123456789"
if text[8] in digits:
    oneval=-1
else:
    oneval=1    
if len(text)>170:
    secval=-1
else:
    secval=1  
if "@" in text:
    thirdval=-1
else:
    thirdval=1    
k=text.count("//")          
if k>1:
    fourthval=-1
else:
    fourthval=1
      
if "-" in text:
    fifthval=-1
else:
    fifthval=1         
if "https" in text:
    sixthval=1
else:
    sixthval=-1
#subdomain ignored    

temp=text
temp=temp[6:]
k1=temp.count("https")

if k1 >=1:
    seventhval=-1
else:
    seventhval=1
if "about:blank" in text:
    eighthval=-1
else:
    eighthval=1
if "mail()" or "mailto:" in text:
    ninthval=-1
else:
    ninthval=1
re=text.count("//")          
if re>3:
    tenthval=-1
else:
    tenthval=1    

import whois
from datetime import datetime

url=text

try:
    res=whois.whois(url)
    #print (res)
    #print (len(res['creation_date']))
    try:
        a=res['creation_date'][0]
        b=datetime.now()
        c=b-a
        d=c.days
    except:
        a=res['creation_date']
        b=datetime.now()
        c=b-a
        d=c.days
    #print (d)
    if d>365:
        eleventhval=1
    else:
        eleventhval=-1
except:
    aburl=1
    eleventhval=-1   

if aburl==1:
    twelthval=-1
else:
    twelthval=1    


"""print (oneval) #having ip   
print (secval) #length
print (thirdval) #atvalue
print (fourthval) #double slash
print (fifthval) #prefix suffix
print (sixthval) #ssl
print (seventhval) #https token
print (eighthval) #sfh
print (ninthval) #submit to mail
print (tenthval) #redirect
print (eleventhval) #age of domain
print (twelthval) #abnormal url"""

filename = 'phish_trainedv0.sav'

loaded_model = joblib.load(filename)

arg=loaded_model.predict(([[oneval,secval,thirdval,fourthval,fifthval,sixthval,seventhval,eighthval,ninthval,tenthval,eleventhval,twelthval]]))
from json.encoder import JSONEncoder
final_entity = { "predicted_argument": [int(arg[0])]}
# directly called encode method of JSON
print (JSONEncoder().encode(final_entity))


