# ILCIC
IP List Compromise Indicator Comprobation

This is a simple script to check the score of a list of IP addresses.

The purpose of this script is to quickly obtain the IP address information as well as the score by means of a CSV file.

The sites from which we obtain information are and for which it is necessary to have/create an account:
-VirusTotal
-AbuseDBIP
-IBM XForce

1- Add the API KEY of these three sites in the DEFINING section for each of the technologies.
2- Define the csv file from which we are going to read the IPs.
This file is intended to have IP,Events(the number of times that this IP has been repeated).
3- The output file will be defined when executing the script for example:
py.exe ILCICv2.py > ILCIC_results.csv

