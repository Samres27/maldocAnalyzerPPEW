from maldocAnalyzerPdf import maldocAnalyzerPdf
from tkinter import *
from tkinterdnd2 import *

class versionDND:
    def __init__(self):
        self.analyser=maldocAnalyzerPdf()
        self.analyser.readCVS()
        self.root = TkinterDnD.Tk()
        self.root.geometry("400x400")
        self.entry_sv = StringVar()
        self.entry_sv.set("drag and drop the PDF")
        self.images=PhotoImage(file="PDFIco.png")
        self.images2=PhotoImage(file="windowsOficceDocument.png")
        self.MgsText=StringVar()
        self.MgsText.set("")
        self.entry = Label(self.root,textvariable=self.entry_sv,width=300,fg="black")
        self.entry2=Label(self.root,textvariable=self.MgsText,width=300)
        self.entry2.place(x=30,y=200,width=350,height=200)
    #entry.pack(padx=10,pady=10)
        self.entry.place(x=75,y=50,width=250,height=200)

        self.entry.drop_target_register(DND_FILES)
        self.entry.dnd_bind('<<Drop>>', self.drop)
        

        self.root.mainloop()
    def drop(self,event):
        self.extractDoc(event.data)
    def extractDoc(self,vl):
        vl=str(vl)
        format=["docx","doc","docm","dot","dotx","dotm","xls","xlsx","xlsm","xlsb","xltm","xlam","xlr","xlw","xltx","xlt","pptm","ppam","ppa"]
        textParse=vl.split("/")
        if(".pdf" in textParse[-1]):
            self.entry=Label(self.root,image=self.images,width=200)
            self.entry.place(x=75,y=50,width=250,height=200)
            self.entry.bind("<Button-1>",self.restart)
            self.MetMaldocAnalyzerPdf(vl)
        elif (textParse[-1].split('.'))[-1] in format:
            self.entry=Label(self.root,image=self.images2,width=200)
            self.entry.place(x=75,y=50,width=250,height=200)
            self.entry.bind("<Button-1>",self.restart)
            self.MetMaldocAnalyzerPdf(vl)
        else:
            self.entry_sv.set("document is not pdf or windows Document")
    def MetMaldocAnalyzerPdf(self,direction):
        
        self.MgsText.set(self.analyser.inserFileSearch(direction) +"\n if you have another pdf that you want to analyze, click the icon")
        self.analyser.cleanAuxFile() 
   
    def restart(self,event):
        self.entry_sv.set("drag and drop the PDF")
        self.entry = Label(self.root,textvariable=self.entry_sv,width=200,fg="black")

        self.entry.place(x=75,y=50,width=250,height=200)
        self.entry.drop_target_register(DND_FILES)
        self.entry.dnd_bind('<<Drop>>', self.drop)
        self.MgsText.set(" ")
       
versionDND()