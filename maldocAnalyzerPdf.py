import pandas
import os
class maldocAnalyzerPdf:
    def __init__(self):
        self.readCVS()
    def inserFileSearch(self,arch):
        textoutput=""
        listFile=self.extractData(arch)
        if(len(listFile)>50):
            vHeader=listFile[5]
            Vobj=listFile[7]
            Vendobj=listFile[9]
            Vstream=listFile[11]
            Vendstream=listFile[13]
            Vxref=listFile[15]
            Vtrailer=listFile[17]
            Vstartxref=listFile[19]
            Vpage=listFile[21]
            Vencrypt=listFile[23]
            VobjStm=listFile[25]
            vJS=listFile[27]
            VJavaScript=listFile[29]
            vAA=listFile[31]
            VopenAction=listFile[33]
            VAcroForm=listFile[35]
            VJBIG2Decode=listFile[37]
            VRichMedia=listFile[39]
            Vlaunch=listFile[41]
            VEmbeddedFile =listFile[43]
            vXFA=listFile[45]
            vURI=listFile[47]
            vColor=listFile[51]
            textoutput+=self.searchMalware(vHeader,Vobj,Vendobj,float(Vstream),Vendstream,Vxref,float(Vtrailer),Vstartxref,Vpage,float(Vencrypt),float(VobjStm),vJS,VJavaScript,vAA,VopenAction,VAcroForm,VJBIG2Decode,VRichMedia,Vlaunch,VEmbeddedFile,vXFA,float(vColor))
        else:
            textoutput+="document not found or format it not pdf"+"\n"
        return textoutput
    def extractData(self,filename):
        
        text="python3 .//necessaryPrograms//pdfid//pdfid.py "+filename+"  --output=pdfInfo.txt >end "
        os.system(text)



        archive=open("pdfInfo.txt",'r')
        ls=archive.read().split()
        return ls
    
    def readCVS(self):
        self.RCVS=pandas.read_csv('.//necessaryPrograms//pdfMalware2022.csv')
        self.df=pandas.DataFrame(self.RCVS)  
        
    
    def searchMalware(self,header,obj,endobj,stream,endstream,xref,trailer,startxref,pageno,encrypt,ObjStm,JS,Javascript,
                      AA,OpenAction,Acroform,JBIG2Decode,RichMedia,launch,EmbeddedFile,XFA,Colors):
        #in this part it is not necessary like this, but it is more understandable this way
        textOutput=""
        value=self.df[self.df["header"]=="\t"+header]
        value=value[value["obj"]==obj]
        value=value[value["endobj"]==endobj]
        value=value[value["stream"]==stream]
        value=value[value["endstream"]==endstream]
        value=value[value["xref"]==xref]
        
        value=value[value["trailer"]==trailer]
        value=value[value["startxref"]==startxref]
        
        value=value[value["pageno"]==pageno]
        value=value[value["encrypt"]==encrypt]
        value=value[value["ObjStm"]==ObjStm]
        value=value[value["JS"]==JS]
        value=value[value["Javascript"]==Javascript]
        value=value[value["AA"]==AA]
        value=value[value["OpenAction"]==OpenAction]
        value=value[value["Acroform"]==Acroform]
        value=value[value["JBIG2Decode"]==JBIG2Decode]
        value=value[value["RichMedia"]==RichMedia]
        value=value[value["launch"]==launch]
        value=value[value["EmbeddedFile"]==EmbeddedFile]
        value=value[value["XFA"]==XFA]
     
        
        value=value[value["Colors"]==Colors]
        
        if(value['Class'].empty):
            textOutput+="there are no matches the pdf file is in an insecure state"+"\n"
            textOutput+="reviewing structure to determine risk"+"\n"
            textOutput+=self.analizerPdf(OpenAction,AA,Javascript,JS,launch,RichMedia,ObjStm,JBIG2Decode,)
        else:
            textOutput+="the pdf documents is:  "+value["Class"].values[0]+"\n"
        return textOutput
    def analizerPdf(self,OpenAction,AA,Javascript,JS,launch,RichMedia,ObjStm,JBIG2Decode):
        textOutput=""
        OpenAction=float(OpenAction)
        AA=float(AA);JS=float(JS)
        Javascript=float(Javascript); launch=float(launch); RichMedia=float(RichMedia); JBIG2Decode=float(JBIG2Decode)
        vl=(OpenAction>0 or AA>0 or JBIG2Decode>0) 
        if(vl):
            textOutput+="the document is very suspicious, possibly it is maldoc"+"\n"
        elif(RichMedia>0 or ObjStm>0):
            textOutput+=" nothing directly malicious was found, but the document could be hiding its intentions in:"
            textOutput+="RichMedia=  "+str(RichMedia)+"  objStm=   "+str(ObjStm)+"\n"
        elif((Javascript>0 or JS>0 or launch>0 )):
            textOutput+=" the document is running some kind of javascript or JS, so we advise you to proceed carefully if it asks you to activate or open something"+"\n"
        else:
            textOutput+=" nothing suspicious in this document\n"
        return textOutput
    def cleanAuxFile(self):
        archive=open("pdfInfo.txt",'w')
        archive.write('')        
        
        
        
if  __name__=='__main__':
    pr=maldocAnalyzerPdf()
    arch=input("insert File:     ")
    print(pr.inserFileSearch(arch))
    pr.cleanAuxFile()
   

