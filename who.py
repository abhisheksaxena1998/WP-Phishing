import whois
from datetime import datetime

url=input()

try:
    res=whois.whois(url)
    print (res)
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
    eleventhval=-1   

print (eleventhval)