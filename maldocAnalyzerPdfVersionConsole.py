import optparse
from maldocAnalyzerPdf import maldocAnalyzerPdf
class versionConsole:
    def __init__(self):
        self.analizer=maldocAnalyzerPdf()
        self.parser=optparse.OptionParser()
        self.parser.add_option("-f","--Filename",dest='filename',type='string',help='the parameter to enter the document you want to analyze')
        (options,args)=self.parser.parse_args()
        if(options.filename != None):
            print(self.analizer.inserFileSearch(options.filename))
        else:
            print("error in document")




if __name__=='__main__':
    versionConsole()