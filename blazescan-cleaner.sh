#!/bin/bash
###################################################
## Script name : all-in-one-blazescan.sh         ##
## Name: MELVIN ANTONY                           ##
## Last Edited : 2019-05-27                      ##
###################################################
RED='\033[0;31m'
NC='\033[0m' # No Color

ORG_IFS=$IFS;
IFS=$'\t\n';     
mkdir -p /root/quarantine-blazescan/`date +%F` &>/dev/null

echo
echo "Removing old Quarantined folders older than 20 days (if any):"
echo "--------------------------------------------------------------------"
find  /root/quarantine-blazescan/ -maxdepth 1 ! -path /root/quarantine-blazescan/ -mtime +20 -type d -printf '%p\n' -exec rm -rf {} \;
echo "--------------------------------------------------------------------"
mkdir /tmp/SUSPFILES_`date +%F` &>/dev/null
cd  /tmp/SUSPFILES_`date +%F`
rm -rf *.txt

echo
echo "Enter the exactpath to SCAN file Associated with `hostname`:"
echo "--------------------------------------------------------------------"
ls -l /usr/local/scan/*.txt -tr | tail |  awk -v OFS='\t' '{print $5 , $6" "$7" "$8, $9}'                # // List the last 10 scan result Files
echo "--------------------------------------------------------------------"
echo

read SCANFILE
cat ${SCANFILE} | grep -i FOUND | grep -v "\.zip" | grep -v "\.tar" | sed s/\{HEX\}/HEX_/g > File_Suspicious_blazescan.txt

for dom in `cat File_Suspicious_blazescan.txt | awk -F': ' '{print $2}'  | awk '{print $1}' | sed '/^[[:space:]]*$/d' | sort -nr  |uniq -c | sort -nr  | awk '{print $2}'`
do
        for z in $(grep ${dom} File_Suspicious_blazescan.txt | grep FOUND| cut -d: -f1) ; do printf '%q\n' "$z" >> file_${dom}.txt; done  # // escape special characters in file names as well
done
echo




falsepatterncode=$(echo "tar.gz|zip|spacer.gif-smartsheet-phishing.UNOFFICIAL|YARA.magecart_5.UNOFFICIAL|12|YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL|aol.png-docusign-phishing-0001.UNOFFICIAL|YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL|YARA.sig_7409295928_WSO_generic.UNOFFICIAL.tx YARA.infected_09_30_18_wp_load.UNOFFICIAL|HEX_php.base64.v23au.185.UNOFFICIAL|pwn.gif-hacker-tag.UNOFFICIAL|favicon.ico-Apple-phishing0001.UNOFFICIAL|alibaba-phishing0001.UNOFFICIAL|logo.svg-paypal-phishing.UNOFFICIAL|apple-touch-icon.png-paypal-phishing.UNOFFICIAL|t1.jpg-microsoft-phishing.UNOFFICIAL|m9.png-microsoft-phishing.UNOFFICIAL|m7.png-microsoft-phishing.UNOFFICIAL|m6.png-microsoft-phishing.UNOFFICIAL|m10.png-microsoft-phishing.UNOFFICIAL|loadingAnimation.gif-citiback-phishing.UNOFFICIAL|YARA.jquery_prettyphoto.UNOFFICIAL|loadingAnimation.gif-citiback-phishing.UNOFFICIAL|loadingAnimation.gif-citiback-phishing.UNOFFICIAL|YARA.php_in_image.UNOFFICIAL|YARA.eval_post.UNOFFICIAL|universal_language_settings-21.png-google-phishing-001.UNOFFICIAL|docusign.png-docusign-phishing-0001.UNOFFICIAL|checkmark.png-google-phishing-001.UNOFFICIAL|chevron-right-blue.png-wells-phishing0002.UNOFFICIAL|bg-fat-nav.png-wells-phishing0002.UNOFFICIAL|YARA.sig_7409295928_WSO_generic.UNOFFICIAL|HEX_php.exe.globals.412.UNOFFICIAL|msrc.gif-paypal-phishing.UNOFFICIAL|YARA.ninoseki_phishing_actor_emails|YARA.infected_09_25_18_index");   

echo  echo "Total infection: `grep FOUND ${SCANFILE} | wc  -l`"  
echo "False positive infection count: `grep FOUND ${SCANFILE} | egrep "(${falsepatterncode})"  | wc  -l`" 
echo "Valid infection count: `grep FOUND ${SCANFILE} | egrep -v "(${falsepatterncode})" | wc  -l`" 
echo




# // add/remove patterns accordingly 

falsepattern=$(echo "ninoseki_phishing_actor|file_spacer.gif-smartsheet-phishing.UNOFFICIAL.txt|file_YARA.magecart_5.UNOFFICIAL.txt|file_12.txt|file_YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL.txt|file_aol.png-docusign-phishing-0001.UNOFFICIAL.txt|file_YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL.txt|file_YARA.sig_7409295928_WSO_generic.UNOFFICIAL.tx file_YARA.infected_09_30_18_wp_load.UNOFFICIAL.txt|file_HEX_php.base64.v23au.185.UNOFFICIAL.txt|file_pwn.gif-hacker-tag.UNOFFICIAL.txt|file_favicon.ico-Apple-phishing0001.UNOFFICIAL.txt|file_alibaba-phishing0001.UNOFFICIAL.txt|file_logo.svg-paypal-phishing.UNOFFICIAL.txt|file_apple-touch-icon.png-paypal-phishing.UNOFFICIAL.txt|file_t1.jpg-microsoft-phishing.UNOFFICIAL.txt|file_m9.png-microsoft-phishing.UNOFFICIAL.txt|file_m7.png-microsoft-phishing.UNOFFICIAL.txt|file_m6.png-microsoft-phishing.UNOFFICIAL.txt|file_m10.png-microsoft-phishing.UNOFFICIAL.txt|file_loadingAnimation.gif-citiback-phishing.UNOFFICIAL.txt|file_YARA.jquery_prettyphoto.UNOFFICIAL.txt|file_loadingAnimation.gif-citiback-phishing.UNOFFICIAL.txt|file_loadingAnimation.gif-citiback-phishing.UNOFFICIAL.txt|file_YARA.php_in_image.UNOFFICIAL.txt|file_YARA.eval_post.UNOFFICIAL.txt|file_universal_language_settings-21.png-google-phishing-001.UNOFFICIAL.txt|file_docusign.png-docusign-phishing-0001.UNOFFICIAL.txt|file_checkmark.png-google-phishing-001.UNOFFICIAL.txt|file_chevron-right-blue.png-wells-phishing0002.UNOFFICIAL.txt|file_bg-fat-nav.png-wells-phishing0002.UNOFFICIAL.txt|file_YARA.sig_7409295928_WSO_generic.UNOFFICIAL.txt|file_HEX_php.exe.globals.412.UNOFFICIAL.txt|file_msrc.gif-paypal-phishing.UNOFFICIAL.txt");

removepattern=$(echo "file_HEX_php.cpanel.d0mains.372.UNOFFICIAL.txt|file_HEX_php.shell.black-id.582.UNOFFICIAL.txt|file_YARA.infected_107_175_218_241_2018_10_14a_shells_dc2.UNOFFICIAL.txt|file_YARA.tbl_status_webshell.UNOFFICIAL.txt|file_HEX_php.shell.black-id.701.UNOFFICIAL.txt|file_YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL.txt|file_YARA.generic_php_injection_1.UNOFFICIAL.txt|file_HEX_php.base64.v23au.185.UNOFFICIAL.txt|file_HEX_php.base64.v23au.185.UNOFFICIAL.txt|file_YARA.generic_php_injection_1.UNOFFICIAL.txt|file_YARA.infected_09_10_18_phishing_smartsheet_htaccess.UNOFFICIAL.txt|file_HEX_php.uploader.max.586.UNOFFICIAL.txt|file_YARA.infected_08_24_18_upload_shell_ubh.UNOFFICIAL.txt|file_YARA.infected_09_06_18_uploader.UNOFFICIAL.txt|file_YARA.infected_09_30_18_Marvins.UNOFFICIAL.txt|file_YARA._TryagFileManager3_shell_php_1.UNOFFICIAL.txt|file_YARA.infected_11_10_18_wp_cache.UNOFFICIAL.txt|file_YARA.infected_08_16_18_adobe_adobe2017_phishing_phone.UNOFFICIAL.txt|file_YARA.PAYPAL_PHISHING_001_infected_06_08_18_case127_files_Antibots_anti.UNOFFICIAL.txt|file_YARA.infected_09_10_18_phishing_smartsheet_htaccess.UNOFFICIAL.txt|file_YARA.infected_11_10_18_wp_cache.UNOFFICIAL.txt|file_HEX_php.gzbase64.inject.452.UNOFFICIAL.txt|file_HEX_php.cmdshell.generic.276.UNOFFICIAL.txt|file_YARA._TryagFileManager3_shell_php_1.UNOFFICIAL.txt|file_HEX_php.base64.v23au.187.UNOFFICIAL.txt|home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip")

echo
echo "######################################################################"
echo "     List of false positive patterns identified during the scan:    "
echo "######################################################################"
echo
ls file_*|  egrep "(${falsepattern})"

echo
echo "##################################################################################"
echo "  List of patterns with complete suspicious content (going to remove if present):"
echo "##################################################################################"
echo
ls file_* | egrep  "(${removepattern})"
echo
echo -e " ${RED} Trying to quarantine to /root/quarantine-blazescan/`date +%F` if there is enough disk space ${NC}";
echo

for i in $(echo ${removepattern} | tr "|" "\n");
do

      [ $(df | grep -w "\/" | awk '{print int($3/1024)}') -gt 3072 ] && [ -f $i ] && for j in `cat $i | sort | uniq `;
                do
                        j=$(echo ${j} | sed -e 's/\\//g' -e s/^/\"/g -e s/$/\"/g)
                        echo -p --parents ${j} /root/quarantine-blazescan/`date +%F` | xargs cp 2>/dev/null
                done
cat $i 2>/dev/null >> tmpusers.txt
cat $i 2>/dev/null | sort | uniq | xargs rm -rfv
done

echo
echo "##################################################################################"
echo " List of patterns for which suspicious code injection are identified in the page"
echo "##################################################################################"
echo
ls file_* | egrep "(file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt|file_YARA.generic_php_injection_0.UNOFFICIAL.txt|file_HEX_php.nested.base64.537.UNOFFICIAL.txt)"
echo
 [ -f file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt ] && for dom in `cat file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt| sort | uniq`; 
do
jw=$(echo ${dom} | sed -e 's/\\//g' -e s/^/\"/g -e s/$/\"/g)
echo -p --parents ${jw} /root/quarantine-blazescan/`date +%F` | xargs cp 2>/dev/null
 
sed '/^@include/d' -i ${dom} ; echo "Include Pattern removed from - ${dom} " ;
done

[ -f file_YARA.generic_php_injection_0.UNOFFICIAL.txt ] && for dom in $(cat file_YARA.generic_php_injection_0.UNOFFICIAL.txt); 
do
        [ -f $dom ] && if [ $(echo $dom |xargs grep -c GLOBALS) -eq 1 ] ; then
        echo ${dom} >> YARA.generic_php_injection_0.txt
        fi
done

echo
echo "################################################################################"
echo "Handling 1st line injections - Please check files parsing errors manually if any"
echo "################################################################################"
echo
 [ -f YARA.generic_php_injection_0.txt  ] && for dom in `cat YARA.generic_php_injection_0.txt| sort | uniq`;
do
jw=$(echo ${dom} | sed -e 's/\\//g' -e s/^/\"/g -e s/$/\"/g)
echo -p --parents ${jw} /root/quarantine-blazescan/`date +%F` | xargs cp 2>/dev/null

if [ $(echo $dom |xargs head -n1 | grep -c "><") -gt 0 ] ; then

pro=$( head -n1 $dom | awk -F"><" '{for(i=2;i<=NF;i++){printf "%s ", $i}; printf "\n"}');
echo $dom| xargs sed -i "1s/.*/<$pro/";
echo "Processed - ${dom}";

fi

k=$(echo $dom | sed s:/:"\\\/":g 2>/dev/null);
sed -i '/'$k'/d' file_YARA.generic_php_injection_0.UNOFFICIAL.txt;   #removing 1st line injected files from the main "file_YARA.generic_php_injection_0.UNOFFICIAL.txt" list

echo $dom| xargs  php -l 2>/dev/null | grep "Errors parsing" --color

done

 [ -f file_HEX_php.nested.base64.537.UNOFFICIAL.txt  ] && for dom in `cat file_HEX_php.nested.base64.537.UNOFFICIAL.txt| sort | uniq`;
do
jw=$(echo ${dom} | sed -e 's/\\//g' -e s/^/\"/g -e s/$/\"/g)
echo -p --parents ${jw} /root/quarantine-blazescan/`date +%F` | xargs cp 2>/dev/null

if [ $(echo $dom |xargs head -n1 | grep -c "><") -gt 0 ] ; then

pro=$( head -n1 $dom | awk -F"><" '{for(i=2;i<=NF;i++){printf "%s ", $i}; printf "\n"}');
echo $dom| xargs sed -i "1s/.*/<$pro/";
echo "Processed - ${dom}";
echo $dom| xargs  php -l 2>/dev/null | grep "Errors parsing"
echo
fi
done


echo
echo "---------------------- Done handling the files -------------------------"

cat file_YARA.generic_php_injection_0.UNOFFICIAL.txt 2>/dev/null >> tmpusers.txt

echo "---- Now killing the users to kill any ongoing cached bad processes ----"
echo

for w in $(cat tmpusers.txt  | awk -F'/' '{print $3}' | sort | uniq | grep -v root | grep -v virtfs |grep -v local);
do
        killall -9 -u $w 2>/dev/null;
        echo $w;

echo "Crontab of the user";
echo
crontab -u $w -l 
echo "+++++++++++++++++"
done
rm -rf tmpusers.txt;

echo
echo "#########################################################################"
echo "         List of patterns which need to be checked manually:             "
echo "#########################################################################"
echo "-------------------------------------------------------------------------"
echo

if [ $(wc -l file_YARA.generic_php_injection_0.UNOFFICIAL.txt 2>/dev/null | awk -F" "  '{print $1}') -eq 0 ];
then
ls file_* |  egrep -v "(${falsepattern})" | egrep -v "(file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt|file_YARA.generic_php_injection_0.UNOFFICIAL.txt)" | egrep -v  "(${removepattern})" | grep -v file_HEX_php.nested.base64.537.UNOFFICIAL.txt
else
ls file_* |  egrep -v "(${falsepattern})" | egrep -v "(file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt)" | egrep -v  "(${removepattern})" | grep -v file_HEX_php.nested.base64.537.UNOFFICIAL.txt
fi

echo
echo "-------------------------------------------------------------------------"
echo "--------------------------  END OF THE SCRIPT  --------------------------"
echo
echo -e " ${RED} /tmp/SUSPFILES_`date +%F` => The directory contains above splitted patterns ${NC} ";
echo#!/bin/bash
###################################################
## Script name : all-in-one-blazescan.sh         ##
## Name: MELVIN ANTONY                           ##
## Last Edited : 2019-05-27                      ##
###################################################
RED='\033[0;31m'
NC='\033[0m' # No Color

ORG_IFS=$IFS;
IFS=$'\t\n';     
mkdir -p /root/quarantine-blazescan/`date +%F` &>/dev/null

echo
echo "Removing old Quarantined folders older than 20 days (if any):"
echo "--------------------------------------------------------------------"
find  /root/quarantine-blazescan/ -maxdepth 1 ! -path /root/quarantine-blazescan/ -mtime +20 -type d -printf '%p\n' -exec rm -rf {} \;
echo "--------------------------------------------------------------------"
mkdir /tmp/SUSPFILES_`date +%F` &>/dev/null
cd  /tmp/SUSPFILES_`date +%F`
rm -rf *.txt

echo
echo "Enter the exactpath to SCAN file Associated with `hostname`:"
echo "--------------------------------------------------------------------"
ls -l /usr/local/scan/*.txt -tr | tail |  awk -v OFS='\t' '{print $5 , $6" "$7" "$8, $9}'                # // List the last 10 scan result Files
echo "--------------------------------------------------------------------"
echo

read SCANFILE
cat ${SCANFILE} | grep -i FOUND | grep -v "\.zip" | grep -v "\.tar" | sed s/\{HEX\}/HEX_/g > File_Suspicious_blazescan.txt

for dom in `cat File_Suspicious_blazescan.txt | awk -F': ' '{print $2}'  | awk '{print $1}' | sed '/^[[:space:]]*$/d' | sort -nr  |uniq -c | sort -nr  | awk '{print $2}'`
do
        for z in $(grep ${dom} File_Suspicious_blazescan.txt | grep FOUND| cut -d: -f1) ; do printf '%q\n' "$z" >> file_${dom}.txt; done  # // escape special characters in file names as well
done
echo




falsepatterncode=$(echo "tar.gz|zip|spacer.gif-smartsheet-phishing.UNOFFICIAL|YARA.magecart_5.UNOFFICIAL|12|YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL|aol.png-docusign-phishing-0001.UNOFFICIAL|YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL|YARA.sig_7409295928_WSO_generic.UNOFFICIAL.tx YARA.infected_09_30_18_wp_load.UNOFFICIAL|HEX_php.base64.v23au.185.UNOFFICIAL|pwn.gif-hacker-tag.UNOFFICIAL|favicon.ico-Apple-phishing0001.UNOFFICIAL|alibaba-phishing0001.UNOFFICIAL|logo.svg-paypal-phishing.UNOFFICIAL|apple-touch-icon.png-paypal-phishing.UNOFFICIAL|t1.jpg-microsoft-phishing.UNOFFICIAL|m9.png-microsoft-phishing.UNOFFICIAL|m7.png-microsoft-phishing.UNOFFICIAL|m6.png-microsoft-phishing.UNOFFICIAL|m10.png-microsoft-phishing.UNOFFICIAL|loadingAnimation.gif-citiback-phishing.UNOFFICIAL|YARA.jquery_prettyphoto.UNOFFICIAL|loadingAnimation.gif-citiback-phishing.UNOFFICIAL|loadingAnimation.gif-citiback-phishing.UNOFFICIAL|YARA.php_in_image.UNOFFICIAL|YARA.eval_post.UNOFFICIAL|universal_language_settings-21.png-google-phishing-001.UNOFFICIAL|docusign.png-docusign-phishing-0001.UNOFFICIAL|checkmark.png-google-phishing-001.UNOFFICIAL|chevron-right-blue.png-wells-phishing0002.UNOFFICIAL|bg-fat-nav.png-wells-phishing0002.UNOFFICIAL|YARA.sig_7409295928_WSO_generic.UNOFFICIAL|HEX_php.exe.globals.412.UNOFFICIAL|msrc.gif-paypal-phishing.UNOFFICIAL|YARA.ninoseki_phishing_actor_emails|YARA.infected_09_25_18_index");   

echo  echo "Total infection: `grep FOUND ${SCANFILE} | wc  -l`"  
echo "False positive infection count: `grep FOUND ${SCANFILE} | egrep "(${falsepatterncode})"  | wc  -l`" 
echo "Valid infection count: `grep FOUND ${SCANFILE} | egrep -v "(${falsepatterncode})" | wc  -l`" 
echo




# // add/remove patterns accordingly 

falsepattern=$(echo "ninoseki_phishing_actor|file_spacer.gif-smartsheet-phishing.UNOFFICIAL.txt|file_YARA.magecart_5.UNOFFICIAL.txt|file_12.txt|file_YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL.txt|file_aol.png-docusign-phishing-0001.UNOFFICIAL.txt|file_YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL.txt|file_YARA.sig_7409295928_WSO_generic.UNOFFICIAL.tx file_YARA.infected_09_30_18_wp_load.UNOFFICIAL.txt|file_HEX_php.base64.v23au.185.UNOFFICIAL.txt|file_pwn.gif-hacker-tag.UNOFFICIAL.txt|file_favicon.ico-Apple-phishing0001.UNOFFICIAL.txt|file_alibaba-phishing0001.UNOFFICIAL.txt|file_logo.svg-paypal-phishing.UNOFFICIAL.txt|file_apple-touch-icon.png-paypal-phishing.UNOFFICIAL.txt|file_t1.jpg-microsoft-phishing.UNOFFICIAL.txt|file_m9.png-microsoft-phishing.UNOFFICIAL.txt|file_m7.png-microsoft-phishing.UNOFFICIAL.txt|file_m6.png-microsoft-phishing.UNOFFICIAL.txt|file_m10.png-microsoft-phishing.UNOFFICIAL.txt|file_loadingAnimation.gif-citiback-phishing.UNOFFICIAL.txt|file_YARA.jquery_prettyphoto.UNOFFICIAL.txt|file_loadingAnimation.gif-citiback-phishing.UNOFFICIAL.txt|file_loadingAnimation.gif-citiback-phishing.UNOFFICIAL.txt|file_YARA.php_in_image.UNOFFICIAL.txt|file_YARA.eval_post.UNOFFICIAL.txt|file_universal_language_settings-21.png-google-phishing-001.UNOFFICIAL.txt|file_docusign.png-docusign-phishing-0001.UNOFFICIAL.txt|file_checkmark.png-google-phishing-001.UNOFFICIAL.txt|file_chevron-right-blue.png-wells-phishing0002.UNOFFICIAL.txt|file_bg-fat-nav.png-wells-phishing0002.UNOFFICIAL.txt|file_YARA.sig_7409295928_WSO_generic.UNOFFICIAL.txt|file_HEX_php.exe.globals.412.UNOFFICIAL.txt|file_msrc.gif-paypal-phishing.UNOFFICIAL.txt");

removepattern=$(echo "file_HEX_php.cpanel.d0mains.372.UNOFFICIAL.txt|file_HEX_php.shell.black-id.582.UNOFFICIAL.txt|file_YARA.infected_107_175_218_241_2018_10_14a_shells_dc2.UNOFFICIAL.txt|file_YARA.tbl_status_webshell.UNOFFICIAL.txt|file_HEX_php.shell.black-id.701.UNOFFICIAL.txt|file_YARA._home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip.UNOFFICIAL.txt|file_YARA.generic_php_injection_1.UNOFFICIAL.txt|file_HEX_php.base64.v23au.185.UNOFFICIAL.txt|file_HEX_php.base64.v23au.185.UNOFFICIAL.txt|file_YARA.generic_php_injection_1.UNOFFICIAL.txt|file_YARA.infected_09_10_18_phishing_smartsheet_htaccess.UNOFFICIAL.txt|file_HEX_php.uploader.max.586.UNOFFICIAL.txt|file_YARA.infected_08_24_18_upload_shell_ubh.UNOFFICIAL.txt|file_YARA.infected_09_06_18_uploader.UNOFFICIAL.txt|file_YARA.infected_09_30_18_Marvins.UNOFFICIAL.txt|file_YARA._TryagFileManager3_shell_php_1.UNOFFICIAL.txt|file_YARA.infected_11_10_18_wp_cache.UNOFFICIAL.txt|file_YARA.infected_08_16_18_adobe_adobe2017_phishing_phone.UNOFFICIAL.txt|file_YARA.PAYPAL_PHISHING_001_infected_06_08_18_case127_files_Antibots_anti.UNOFFICIAL.txt|file_YARA.infected_09_10_18_phishing_smartsheet_htaccess.UNOFFICIAL.txt|file_YARA.infected_11_10_18_wp_cache.UNOFFICIAL.txt|file_HEX_php.gzbase64.inject.452.UNOFFICIAL.txt|file_HEX_php.cmdshell.generic.276.UNOFFICIAL.txt|file_YARA._TryagFileManager3_shell_php_1.UNOFFICIAL.txt|file_HEX_php.base64.v23au.187.UNOFFICIAL.txt|home_hawk_infected_01_29_19_amadey_botnet_f_st_geo_ip")

echo
echo "######################################################################"
echo "     List of false positive patterns identified during the scan:    "
echo "######################################################################"
echo
ls file_*|  egrep "(${falsepattern})"

echo
echo "##################################################################################"
echo "  List of patterns with complete suspicious content (going to remove if present):"
echo "##################################################################################"
echo
ls file_* | egrep  "(${removepattern})"
echo
echo -e " ${RED} Trying to quarantine to /root/quarantine-blazescan/`date +%F` if there is enough disk space ${NC}";
echo

for i in $(echo ${removepattern} | tr "|" "\n");
do

      [ $(df | grep -w "\/" | awk '{print int($3/1024)}') -gt 3072 ] && [ -f $i ] && for j in `cat $i | sort | uniq `;
                do
                        j=$(echo ${j} | sed -e 's/\\//g' -e s/^/\"/g -e s/$/\"/g)
                        echo -p --parents ${j} /root/quarantine-blazescan/`date +%F` | xargs cp 2>/dev/null
                done
cat $i 2>/dev/null >> tmpusers.txt
cat $i 2>/dev/null | sort | uniq | xargs rm -rfv
done

echo
echo "##################################################################################"
echo " List of patterns for which suspicious code injection are identified in the page"
echo "##################################################################################"
echo
ls file_* | egrep "(file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt|file_YARA.generic_php_injection_0.UNOFFICIAL.txt|file_HEX_php.nested.base64.537.UNOFFICIAL.txt)"
echo
 [ -f file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt ] && for dom in `cat file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt| sort | uniq`; 
do
jw=$(echo ${dom} | sed -e 's/\\//g' -e s/^/\"/g -e s/$/\"/g)
echo -p --parents ${jw} /root/quarantine-blazescan/`date +%F` | xargs cp 2>/dev/null
 
sed '/^@include/d' -i ${dom} ; echo "Include Pattern removed from - ${dom} " ;
done

[ -f file_YARA.generic_php_injection_0.UNOFFICIAL.txt ] && for dom in $(cat file_YARA.generic_php_injection_0.UNOFFICIAL.txt); 
do
        [ -f $dom ] && if [ $(echo $dom |xargs grep -c GLOBALS) -eq 1 ] ; then
        echo ${dom} >> YARA.generic_php_injection_0.txt
        fi
done

echo
echo "################################################################################"
echo "Handling 1st line injections - Please check files parsing errors manually if any"
echo "################################################################################"
echo
 [ -f YARA.generic_php_injection_0.txt  ] && for dom in `cat YARA.generic_php_injection_0.txt| sort | uniq`;
do
jw=$(echo ${dom} | sed -e 's/\\//g' -e s/^/\"/g -e s/$/\"/g)
echo -p --parents ${jw} /root/quarantine-blazescan/`date +%F` | xargs cp 2>/dev/null

if [ $(echo $dom |xargs head -n1 | grep -c "><") -gt 0 ] ; then

pro=$( head -n1 $dom | awk -F"><" '{for(i=2;i<=NF;i++){printf "%s ", $i}; printf "\n"}');
echo $dom| xargs sed -i "1s/.*/<$pro/";
echo "Processed - ${dom}";

fi

k=$(echo $dom | sed s:/:"\\\/":g 2>/dev/null);
sed -i '/'$k'/d' file_YARA.generic_php_injection_0.UNOFFICIAL.txt;   #removing 1st line injected files from the main "file_YARA.generic_php_injection_0.UNOFFICIAL.txt" list

echo $dom| xargs  php -l 2>/dev/null | grep "Errors parsing" --color

done

 [ -f file_HEX_php.nested.base64.537.UNOFFICIAL.txt  ] && for dom in `cat file_HEX_php.nested.base64.537.UNOFFICIAL.txt| sort | uniq`;
do
jw=$(echo ${dom} | sed -e 's/\\//g' -e s/^/\"/g -e s/$/\"/g)
echo -p --parents ${jw} /root/quarantine-blazescan/`date +%F` | xargs cp 2>/dev/null

if [ $(echo $dom |xargs head -n1 | grep -c "><") -gt 0 ] ; then

pro=$( head -n1 $dom | awk -F"><" '{for(i=2;i<=NF;i++){printf "%s ", $i}; printf "\n"}');
echo $dom| xargs sed -i "1s/.*/<$pro/";
echo "Processed - ${dom}";
echo $dom| xargs  php -l 2>/dev/null | grep "Errors parsing"
echo
fi
done


echo
echo "---------------------- Done handling the files -------------------------"

cat file_YARA.generic_php_injection_0.UNOFFICIAL.txt 2>/dev/null >> tmpusers.txt

echo "---- Now killing the users to kill any ongoing cached bad processes ----"
echo

for w in $(cat tmpusers.txt  | awk -F'/' '{print $3}' | sort | uniq | grep -v root | grep -v virtfs |grep -v local);
do
        killall -9 -u $w 2>/dev/null;
        echo $w;

echo "Crontab of the user";
echo
crontab -u $w -l 
echo "+++++++++++++++++"
done
rm -rf tmpusers.txt;

echo
echo "#########################################################################"
echo "         List of patterns which need to be checked manually:             "
echo "#########################################################################"
echo "-------------------------------------------------------------------------"
echo

if [ $(wc -l file_YARA.generic_php_injection_0.UNOFFICIAL.txt 2>/dev/null | awk -F" "  '{print $1}') -eq 0 ];
then
ls file_* |  egrep -v "(${falsepattern})" | egrep -v "(file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt|file_YARA.generic_php_injection_0.UNOFFICIAL.txt)" | egrep -v  "(${removepattern})" | grep -v file_HEX_php.nested.base64.537.UNOFFICIAL.txt
else
ls file_* |  egrep -v "(${falsepattern})" | egrep -v "(file_YARA.wordpress2_ico_injection_detected.UNOFFICIAL.txt)" | egrep -v  "(${removepattern})" | grep -v file_HEX_php.nested.base64.537.UNOFFICIAL.txt
fi

echo
echo "-------------------------------------------------------------------------"
echo "--------------------------  END OF THE SCRIPT  --------------------------"
echo
echo -e " ${RED} /tmp/SUSPFILES_`date +%F` => The directory contains above splitted patterns ${NC} ";
echo
