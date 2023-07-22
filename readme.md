# maldocAnalyzerPPEW

## Usage

you have to open the program maldocAnalyzerPdf.py in this you have to put the URI of the document so that it proceeds to analyze it
in the add and drop version you have to open it with "python ./maldocAnalyzerPdf" drag and drop the document you want to analyze
To use the console version you have to use the "python3 maldocAnalyzerPdfVersionConsole.py" using the function "-f" or "--filename" with the address of the document to analyze

## Functioning

parses the document, and through a search in the data set, if it finds a match, it returns the file if it is malicious or benign, otherwise, it parses the document and returns the risk it has by parsing its structure, finally if found some worrying part, sent it to virustotal for analysis with different antivirus


## Requirements
* pdfid
* os
* hashlib
* oleid
* pandas
* requests(pip install requests)
* pdfMalware2022.csv (https://www.unb.ca/cic/datasets/pdfmal-2022.html)
* tkinter(version put and drop, pip install tk)
* tkinterDND2(version put and drop, pip install tkinterdnd2)
* webbrowser
* optparse(version console, pip install optparse-pretty)
* oletools(pip install oletools)

most of the requirements are in the python download manager "pip"
You may have problems when calling "python" so you may want to modify the code