Description:
=============

Blazescan results can be huge in size and handling all the files is very hectic in almost all the cases.
This is Bash script to auto clean the result from the blazescan with too many features as below:

 - Auto quarantine of malicious files to /root/quarantine-blazescan/ while maintaining the tree structure of the files and folders making it easier to handle them if needed
 - Shows the most 10 recent scan result files
 - You can append/remove the 'falsepatterncode' as well as the 'removepattern' variable contents within the script . (Where falsepatterncode means know false positive patterns and removepattern means the patterns that were found to be malicious files)
 - Removes known one line injections of the php files and include ico injections
 - Kills off the user in the server to kill any ongoing cached bad processes 
 - Provides you the crons of these bad users so that you can inspect manually.
 
 More info on balzescan : https://github.com/Hestat/blazescan

NOTE: This script was made on 2019-05-27 and the newer blazescan version might produce newer result patterns which should be handled manually. You can add the newer patterns to the script according to their nature.
