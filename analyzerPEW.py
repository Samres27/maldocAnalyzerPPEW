import os
import requests
import hashlib
import webbrowser
import socket
class analyPEW:
    def SHA256_Checksum(self,ruta):
        h = hashlib.sha256()
        with open(ruta, 'rb', buffering=0) as f:
            for b in iter(lambda : f.read(128*1024), b''):
                h.update(b)
        return h.hexdigest()


    def Analyzer(self,doc):
        os.system("python .\oleid.py "+doc+ " >.\data.txt")
        self.sha256url=self.SHA256_Checksum(doc)


        archive=open(".\data.txt","r")
        newline=archive.readline()
        num=0
        listC=[]
        while newline != '':
            if num>4:
                if not('-----------' in newline):
                    listC.append(newline.split('|')) 
            num+=1;
            newline=archive.readline()
        featureList=["File format         ",'Encrypted           ' ,'VBA Macros          ','XLM Macros          ','External            ' ,'Relationships       ']
        newListAx=[]
        it=0
        for x in listC:
            if(len(featureList)>it and x[0]==featureList[it]):
                it+=1
                newListAx.append(x[2])
            
        risk=0
            
        for x in range(0,len(featureList)):
            if (str(newListAx[x]).strip()=="info"): risk+=0
            elif (str(newListAx[x]).strip()=="none"): risk+=0
            elif (str(newListAx[x]).strip()=="low"): risk+=1
            elif (str(newListAx[x]).strip()=="Medium"): risk+=2
            elif (str(newListAx[x]).strip()=="HIGH"): risk+=3
            elif (str(newListAx[x]).strip()=="Error"): return "error, format not supported"
        valuesRisk=["none", "low","medium","High"]
        if(risk>len(valuesRisk)): risk=3
        textAnalyzer="the document has a risk : "+ valuesRisk[risk]    
        
        return textAnalyzer
    def openVirusTotal(self,text):
        if self.checkInternetConnection():
            req=requests.get(url="https://www.virustotal.com/gui/search/")
            if(req):
                if text!="error, format not supported" and not("none" in text) :
                    webbrowser.open(
                    'https://www.virustotal.com/gui/search/'+self.sha256url
                    )
    def checkInternetConnection(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(("www.google.com", 80))
        except (socket.gaierror, socket.timeout):
            return False
        else:
            return True
        s.close()

if __name__=='__main__':
    prog=analyPEW()
    arc=input("doc File:    ")
    ls=prog.Analyzer(arc)
    print(ls)
    prog.openVirusTotal(ls)