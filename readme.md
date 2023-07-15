# maldocAnalyzerPdf

## Usage

you have to open the program maldocAnalyzerPdf.py in this you have to put the URI of the document so that it proceeds to analyze it
in the add and drop version you have to open it with "python ./maldocAnalyzerPdf" drag and drop the document you want to analyze
To use the console version you have to use the "python3 maldocAnalyzerPdfVersionConsole.py" using the function "-f" or "--filename" with the address of the document to analyze

## Functioning

analyzes the document, and through a search in the dataset, if a match is found, it returns the file if malicious or benign, otherwise it analyzes the document and returns the risk that it has by analyzing its structure 


## Requirements
* pdfid
* pandas
* os
* pdfMalware2022.csv (https://www.unb.ca/cic/datasets/pdfmal-2022.html)
* tkinter(version put and drop)
* tkinterDND2(version put and drop)
* import optparse(version console)

most of the requirements are in the python download manager "pip"
