AnalyzePDF.py
=============

Analyzes PDF files by looking at their characteristics in order to add some intelligence into the determination of them being malicious or benign.

Requirements
------------
	* pdfid
	* pandas
	* os
	* pdfMalware2022.cvs(https://www.unb.ca/cic/datasets/pdfmal-2022.html)
	
Usage
-----
you have to open the program maldocAnalyzerPdf.py in this you have to put the URI of the document so that it proceeds to analyze it

Functioning
-----------
analyzes the document, and through a search in the dataset, if a match is found, it returns the file if malicious or benign, otherwise it analyzes the document and returns the risk that it has by analyzing its structure					

Restrictions
------------
Free to use for non-commercial.  Give credit where credit is due.