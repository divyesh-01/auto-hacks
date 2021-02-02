#!/bin/sh
red='\e[1;31m'
grn='\e[1;32m'
blu='\e[1;34m'
mag='\e[1;35m'
cyn='\e[1;36m'
white='\e[0m'

echo "\n"	
echo  $red "\n		@@@@@  WELCOME U AMAZING HACKER  @@@@@ \n"$white

echo "$cyn	-----------------------------------------------------------------------"	
echo "\n   1 - Find only SUBDOMAINS of the target\n"						
echo  "   2 - Checking for SUBDOMAIN TAKEOVER\n"						
echo  "   3 - Find JS files from the target\n"		
echo  "   4 - Check for sqli , xss , ssti , cors , \n"
echo  "   5 - Check for parameters \n"
echo  "   6 - Check by nuclei  \n"
echo  "   7 - directory brute forcing  \n"		
echo "	-----------------------------------------------------------------------"	
echo $blu "\n		press what you want to find.	"$white
read  item

amass1()
{
	echo $grn"\n wait a while....\n"$white
	amass enum  -silent -d $1 -timeout 3 >> amass-$1.txt
	#echo $mag" subdomain found through amass\n"$white
}
subdomains () {
	echo $1 | subfinder -silent  -o subfinders-$1.txt
	#echo $mag" subomain found through subfinder \n"$white  
}

chaos1 ()
{
	chaos  -d $1 -key "chaos key here" -o chaos1-$1.txt
	#echo $mag" subomain found through chaos \n"$white  
}

gos (){
	xargs -P 500 -a $1 -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew | tee gospider-js.txt'
}

gau1 ()

{
	
	cat $1 | sed 's/https\?:\/\///' | gau | anew >>  gau_url.txt


}
linkfind ()
{
	python3 linkfinder.py -i https://marwadiuniversity.ac.in/ -o cli | tee dvs.txt

}

waybak ()
{
	cat $1 | waybackurls | anew | tee wayback.txt
}

assetfinders () 
{
	
	assetfinder --subs-only $1 >>  assets-$1.txt
	#echo $mag" subdomain found through assetfinder \n"$white
}

subjss ()
{
	cat $1 | httprobe | subjs | tee subjs.txt
}

sublister ()
{
	sublist3r -d $1 -o  sublister-$1.txt 
	#echo $mag" subdomain found through sublister \n"$white
}
jldc ()
{
	
	curl -s "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >>  jldcs-$1.txt
	echo $red"\n wait for a while "$white
	#echo $mag"subdomain found through jldc \n"$white
}
git_sub ()
 {
	
	python3 ~/Desktop/tool/github-search/github-subdomains.py -t "github-token-here" -d $1 >> git-subdomains.txt
	#echo $mag"subdomain found through github \n"$white
 }
 split ()
 {
	echo $1
	mkdir $ans/diff_urls;


    cat $ans-urls.txt | grep -P "\w+\.js(\?|$)" | httpx -silent -status-code | grep "200" | awk '{print $1}'   | anew | tee  $ans/diff_urls/jsurls.txt;
	cat $ans-urls.txt | grep -P "\w+\.jsp(\?|$)" | httpx -silent -status-code | grep "200" | awk '{print $1}'  | anew | tee  $ans/diff_urls/jspurls.txt;
	cat $ans-urls.txt | grep -P "\w+\.jsx(\?|$)" | httpx -silent -status-code | grep "200" | awk '{print $1}'  | anew | tee  $ans/diff_urls/jsxurls.txt;
	cat $ans-urls.txt | grep -P "\w+\.xml(\?|$)" | httpx -silent -status-code | grep "200" | awk '{print $1}'  | anew | tee  $ans/diff_urls/xmlurls.txt;
	cat $ans-urls.txt | grep -P "\w+\.json(\?|$)" | httpx -silent -status-code | grep "200" | awk '{print $1}' | anew | tee  $ans/diff_urls/jsonurls.txt;
	cat $ans-urls.txt | grep -P "\w+\.php(\?|$)" | httpx -silent -status-code | grep "200" | awk '{print $1}'  | anew | tee  $ans/diff_urls/phpurls.txt;
	cat $ans-urls.txt | grep -P "\w+\.aspx(\?|$)" | httpx -silent -status-code | grep "200" | awk '{print $1}' | anew | tee  $ans/diff_urls/aspxurls.txt; 	 
	

	

#[ -s man.txt ] || echo "empty"
#for i in {0..6};do if [[ -s ${file[$i]} ]]; then cp ${file[$i]} $ans/diff-urls/; else rm ${file[$i]}; fi ;done;



	 
 }
Done()
{
	echo $mag" subdomain found through amass, subfinder, github, chaos, sublister, assetfinder, jldc \n"$white
	echo $cyn" merging all subdomain found from above sources\n"$white
	ans=$(echo $target | cut -d "." -f 1 | cut -d "-" -f 2)
	cat amass-$1.txt subfinders-$1.txt assets-$1.txt jldcs-$1.txt chaos1-$1.txt git-subdomains.txt | anew >> subdomains-$ans.txt
	mkdir $ans
	cp subdomains-$ans.txt $ans
	rm amass-$1.txt subfinders-$1.txt assets-$1.txt  jldcs-$1.txt git-subdomains.txt chaos1-$1.txt
	echo $red"\nsubdomain saved to subdomains-$ans.txt in 
	$ans directory \n"$white

}

#openredirect (){
#	export LHOST="http://localhost"; cat $1 | grep "=" | qsreplace "$LHOST" | xargs  -I % -P 25 sh -c 'curl -Is "%" | grep -q "Location: $LHOST" && echo "VULN! %"' 2>/dev/null | tee /redirect/result.txt
#}


if [ $item -eq "1" ]
	then 
		echo $cyn "	ENTER THE DOMAIN NAME. \n "$white
		read target
	
	
		echo $red"\n Finding subdomains through amass, sublister, assetfinder, subfinder, chaos api, github, jldc."$white
		amass1 $target
		subdomains $target
		assetfinders $target				#calling functions for collecting subdomain.
		jldc $target
		git_sub $target
		chaos1 $target
		Done $target
elif [ $item -eq "2" ]
	then
		echo $blu"\nFile should be available in $red hack $blu directory"$white
		echo $cyn"enter the subdomains file name for finding subdomain takeover\n"$white	
		read takeover_file
		ans=$(echo $takeover_file | cut -d "." -f 1 | cut -d "-" -f 2)
		echo $red"\nwait a while, checking for subdomain takeover"$white
		subjack -w ~/hack/$takeover_file -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 | tee subjack-takeover.txt
		subzy -targets $takeover_file | tee subzy-takeover.txt 
		echo "\n---------------------------------------\n" >> subzy-takeover.txt
		echo "\n FROM HERE SHOWING RESULT OF SUBJACK\n" >> subzy-takeover.txt
		echo "\n---------------------------------------\n" >> subzy-takeover.txt
		cat subzy-takeover.txt subjack-takeover.txt >> takeover-$ans.txt

		cp takeover-$ans.txt $ans
		rm subzy-takeover.txt subjack-takeover.txt takeover-$ans.txt
		echo $mag"\nresult saved to takeover-$ans.txt"$white 


	elif [ $item -eq "3" ]		
		then
			echo "enter the file which contains subdomains "
			read name_file
			
			echo "\n finding js files\n"
			ans=$(echo $name_file | cut -d "." -f 1 | cut -d "-" -f 2)
			#gos $name_file
			gau1 $name_file
			waybak $name_file
			subjss $name_file
			cat wayback.txt gospider-js.txt subjs.txt gau_url.txt | anew >> $ans-urls.txt
			cp $ans-urls.txt $ans
			rm wayback.txt gospider-js.txt subjs.txt gau_url.txt 2>/dev/null
			split $ans-urls.txt
	elif [ $item -eq "4" ]		
		then
			echo $cyn"\ngive the urls file names\n"$white 

#------------------------------------------ open redirect ---------------------------------------#			
			read filename;
			#echo $mag"checking for openredirect"$white
			ans=$(echo $filename | cut -d "-" -f 1 )
			#cd $ans;
			#mkdir redirect;
			#cat $filename | gf redirect | qsreplace "http://localhost" | tee redirect/possible-url.txt
			#cat $filename | grep -a -i \=http | qsreplace "http://localhost" >> redirect/possible-url.txt 
			#cd redirect;
			#for i in $(cat possible-url.txt); do curl -s -L $i -I | grep "localhost" && echo $red"[vulnerable]"$white $i \n | tee result.txt ; done;
			#[ -s result.txt ] ||  rm result.txt ;
			#cd ../../;
			
#------------------------------------------ sql injection ---------------------------------------#
		
			echo $mag"\nchecking for sqli\n"$white
			cd $ans;
			mkdir sqli;
			cat $filename | gf sqli | qsreplace "1'" | uniq | httpx --silent --status-code | grep "200" | awk {'print $1'} | tee sqli/possible-sql.txt
			cd sqli;
			for i in $(cat possible-sql.txt); do curl -s $i| grep "Error" && echo $red"vulnerable url is "$white "$i\n" >> result.txt ;done;
			for i in $(cat possible-sql.txt); do curl -s $i| grep "line" && echo $red"vulnerable url is "$white "$i\n" >> result1.txt ;done;
			for i in $(cat possible-sql.txt); do curl -s $i| grep "Warning" && echo $red"vulnerable url is "$white "$i\n" >> result2.txt ;done;
			cat result1.txt result.txt result2.txt >> final-result.txt
			rm result1.txt result.txt result2.txt
			[ -s final-result.txt ] ||  rm final-result.txt
			cd ..
			


#------------------------------------------ xss ---------------------------------------#
			mkdir xss;
			cat $filename  | gf xss | qsreplace '"><script>confirm(1)</script>' > xss/xss-possible.txt 2>/dev/null
			echo $mag"\nchecking for xss\n"$white
			sleep 3s ;
			cat xss/xss-possible.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "confirm(1)" && echo $red"vulnerable\n"$white $host"\n" >> xss/ans1.txt ;done;
			cat $filename  | grep "=" | qsreplace '<style>%40keyframes%20x%7B%7D<%2Fstyle><xss%20style%3D"animation-name%3Ax"%20onanimationend%3D"alert%281%29"><%2Fxss>&context=html' > xss/xss-possible2.txt 2>/dev/null
			cat xss/xss-possible2.txt| while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "alert" &&  echo  $red"vulnerable\n"$white $host"\n" >> xss/ans2.txt ;done;
			cat xss/ans1.txt xss/ans2.txt >> xss/xss-ans.txt
			cd xss;
			cat xss-ans.txt
			[ -s xss-ans.txt ] ||  rm xss-ans.txt
			rm ans1.txt ans2.txt
			cd ..
						
			
#------------------------------------------dalfox and many other xss ---------------------------------------#
			mkdir auto-xss;
			cat $filename | kxss | sed 's/=.*/=/' | sed 's/URL: //' | anew |dalfox pipe -o auto-xss/dalfox.txt
			cat $filename | grep "=" | sed 's/=.*/=/' | sed 's/URL: //' |  httpx --status-code | grep "200" | anew | dalfox pipe -o auto-xss/dalfox1.txt
			
#------------------------------------------parameter and vuln  ---------------------------------------#
			elif [ $item -eq "5" ]
				then 
				
				echo "finding parametes and vulnerable parameters \n"
				echo "$mag enter the subdomains file $white"
				read filename
				ans=$(echo $filename | cut -d "." -f 1 | cut -d "-" -f 2)
				cd $ans
				mkdir parameters
				for i in $(cat $filename ); do python3 ~/Desktop/tool/parameter/paramspider/paramspider.py -d $i -o parameters/$i.txt 2>/dev/null;done;
				cat parameters/* | anew >> parameters/parameters.txt
				for i in $(cat $filename ); do rm parameters/$i.txt 2>/dev/null;done;
				clear
				echo " list of parametered urls are saved in parameters $red $ans/parameters $white "

			elif [ $item -eq "6" ]
				then 
				
				
				echo "\n$mag enter the subdomains file $white \n"
				read filename
				ans=$(echo $filename | cut -d "." -f 1 | cut -d "-" -f 2)
				cd $ans
				mkdir nuceli-ans
				
				echo "\n $red running  nuclei $white \n"
				cat $filename | httpx --silent --status-code | grep "200" | awk {'print $1'} | tee live-subdomains.txt
				cat live-subdomains.txt | nuclei -t ~/nuclei-templates/  -silent -c 50  -o nuceli-ans/subs.txt
				
				echo "\n$red -----------------finding live urls----------------- \n $white"	
				cat $ans-urls.txt | grep "=" | qsreplace "1" | anew | httpx -silent --status-code | grep "200" | awk {'print $1'} | anew >> live-urls.txt
				echo "\n $red live urls are saved in  live-urls.txt $white \n"

				echo "\n $red checking for files which should not be shown $white \n"

				cat live-urls.txt | nuclei -t ~/nuclei-templates/files/ -silent -c 50 -o nuceli-ans/file.txt
				
				echo "\n $red checking for cves $white \n"
				
				cat live-urls.txt | nuclei -t ~/nuclei-templates/cves/ -silent -c 50 -o nuceli-ans/cves.txt
				
				echo "\n $red checking for vulnerabilities $white \n"
				
				cat live-urls.txt | nuclei -t ~/nuclei-templates/vulnerabilities/ -silent -c 50 -o nuceli-ans/vulnerabilities.txt
				
				echo "\n $red checking for tokens such as api-keys and all $white \n"
				
				cat live-urls.txt | nuclei -t ~/nuclei-templates/tokens/ -silent -c 50 -o nuceli-ans/tokens.txt
				
				echo "\n $red checking for miss configuration $white \n"
				
				cat live-urls.txt | nuclei -t ~/nuclei-templates/security-misconfiguration/ -silent -c 50 -o nuceli-ans/security-misconfiguration.txt
				
				echo "\n $red checking for xss and all $white  \n"
				
				cat live-urls.txt | nuclei -t ~/nuclei-templates/generic-detections -silent -c 50 -o nuceli-ans/generic-detections.txt
				
				echo "\n $red checking for lfi and rfi etc $white \n"
				
				cat live-urls.txt | nuclei -t ~/nuclei-templates/fuzzing/ -silent -c 50 -o nuceli-ans/fuzzing.txt
			

			elif [ $item -eq "7" ]
				then 

			echo "\n$mag enter the subdomains file $white \n"
			read filename
			ans=$(echo $filename | cut -d "." -f 1 | cut -d "-" -f 2)
			cd $ans
			mkdir directory-bruteforce
			cat $filename | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u @/FUZZ -o '$ans/directory-bruteforce'/ans.txt'
			

fi
