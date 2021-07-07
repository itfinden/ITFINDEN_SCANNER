#!/bin/bash


# date process
DATE=$(date +%F)

# logging
TMPLOG=/var/log/malwares.txt
TMPLOG2=/var/log/malwares2.txt
LOGFILE=/var/log/imunifyav-$DATE.txt
LOGROTATE=5

# cpanel user contact email notification
# enabled
# disabled
SENDTO=disabled
 
# colours
red='\033[1;31m'
green='\033[1;32m'
yellow='\033[1;33m'
blue='\033[1;34m'
light_cyan='\033[1;96m'
reset='\033[0m'

##### <scan duration>
function scan_duration {
if [[ $DURATION -lt 60 ]];then
	DURATION=$(echo $DURATION second[s])
elif [[ $DURATION -ge 60 ]] && [[ $DURATION -lt 3600 ]];then
	DURATION=$(expr $DURATION / 60)
	DURATION=$(echo $DURATION minute[s])
elif [[ $DURATION -ge 3600 ]] && [[ $DURATION -lt 86400 ]];then
	DURATION=$(expr $DURATION / 3600)
	DURATION=$(echo $DURATION hour[s])
elif [[ $DURATION -ge 86400 ]] && [[ $DURATION -lt 604800 ]];then
	DURATION=$(expr $DURATION / 86400)
	DURATION=$(echo $DURATION day[s])
fi
}
##### </scan duration>

##### <status check>
function status_check {
i=1
bar="/-\|"
printf "ImunifyAV on-demand scan:${yellow} $STATUS ${reset}[ "
while [[ $STATUS == "running" ]];do
    printf "\b${bar:i++%${#bar}:1}"
    sleep 0.001s
    STATUS=$(imunify-antivirus malware on-demand status|grep status|awk '{print $2}')
done
printf "] ${red}$STATUS ${reset}\n"

# loading scan result
i=1
bar="/-\|"
DURATION=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $3}')
printf "ImunifyAV on-demand scan:${yellow} loading ${reset}[ "
while [[ $DURATION == "None" ]];do
    printf "\b${bar:i++%${#bar}:1}"
    sleep 0.001s
    DURATION=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $3}')
done
printf "] ${green}loaded ${reset}"
printf "\nImunifyAV on-demand scan:${green} completed ${reset}\n"
}
##### </status check>

##### <load scan result>
function load_scan_result {
	COMPLETED=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $1}')
	ERROR=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $4}')
	PATHSCAN=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $5}')
	SCAN_TYPE=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $7}')
	STARTED=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $9}')
	TOTAL=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $10}')
	TOTAL_FILES=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $11}')
    TOTAL_MALICIOUS=$(imunify-antivirus malware on-demand list|grep $SCANID|awk '{print $12}')
}
##### </load scan result>

##### <mailreporting>
# mailreport to mailadmin
function malware_report_to_mailadmin {
	if [[ ! -z $EMAIL ]];then
		mail -s "MALWARE SCAN REPORT [$HOSTNAME] $DATE" $EMAIL < $LOGFILE
	elif [[ -z $EMAIL ]];then
		printf "Please define your ${red}email address${reset} to recieve malware scan report\n"
		printf "$0 --email=${red}soporte@itfinden.com${reset}\n"
	fi
}

# mailreport to mail user
function malware_report_to_mailuser {
    # Send to contact email?
    if [[ $SENDTO == enabled ]];then
    printf "Enviando a${blue} $CONTACT${reset} por el usuario ${blue} $USERS${reset}:${green} $SENDTO ${reset}\n"
        mail -s "ITFINDEN MALWARE SCAN REPORT: $MAINDOMAIN $DATE" $CONTACT < $TMPLOG
    else
        printf "Enviando a${blue} $CONTACT${reset} por el usuario${blue} $USERS${reset}:${red} $SENDTO ${reset}\n"
    fi
}
##### </mailreporting>

##### <MODE option>
function mode_options {
case $MODE in
    1) # ls
		MODE=1
		MESSAGE="ls (listing only)"
		hostingpanel_check
    ;;
    2) # chmod ls
		MODE=2
		MESSAGE="chmod 000"
		hostingpanel_check
    ;;
    3) # chmod chattr ls
		MODE=3
		MESSAGE="chmod 000 && chattr +i"
		hostingpanel_check
    ;;
    *) echo "MODE Options: {1|2|3} ?"
    ;;
esac
}
##### </MODE option>

##### <hosting panel check>
function hostingpanel_check {
	if [[ $OPERATINGSYSTEM == 'CloudLinux' ]] || [[ $OPERATINGSYSTEM == 'CentOS' ]] || [[ $OPERATINGSYSTEM == 'Red' ]];then
		if [[ -f /usr/local/cpanel/version ]];then
			HOSTINGPANEL=$(echo "cPanel/WHM" $(cat /usr/local/cpanel/version))
			cpanel_mode_process
		else
			standalone_mode_process
		fi
	elif [[ $OPERATINGSYSTEM == 'Ubuntu' ]];then
		HOSTINGPANEL='Stand Alone'
		standalone_mode_process
	else
		HOSTINGPANEL='Stand Alone'
		standalone_mode_process
	fi
}
##### </hosting panel check>

##### <MODE process>
# standalone mode process
function standalone_mode_process {
	print_scan_result
	mode_action
	malware_report_to_mailadmin
	printf "Malware scan result logfile:${light_cyan} $LOGFILE ${reset}\n"
}

# cpanel mode process
function cpanel_mode_process {
print_scan_result
LIMIT=$TOTAL_MALICIOUS
imunify-antivirus malware malicious list|grep $SCANID|awk '{print $13}'|grep -Ev "USERNAME"|sort|uniq|while read USERS;do
        MAINDOMAIN=$(grep "/$USERS/" /etc/userdatadomains|grep "=main="|cut -d"=" -f7)
        OWNER=$(grep "/$USERS/" /etc/userdatadomains|grep "=main="|cut -d'=' -f3)
        CONTACT=$(grep CONTACTEMAIL /var/cpanel/users/$USERS|cut -d"=" -f2|head -n1)
        TOTALMAL=$(imunify-antivirus malware malicious list --limit $LIMIT|grep $SCANID |grep $USERS|wc -l)
        echo "Usuario        : $USERS" > $TMPLOG
        echo "Dueño       : $OWNER" >> $TMPLOG
        echo "Dominio     : $MAINDOMAIN" >> $TMPLOG
        echo "Email   : $CONTACT" >> $TMPLOG
        echo "Virus  : Se encontro $TOTALMAL archivos maliciosos" >> $TMPLOG
		echo "Como se Limpia : 1. Primero haga una copia de seguridad de sus datos antes de limpiar el malware" >> $TMPLOG
		echo "                 2. Revisa el código fuente" >> $TMPLOG
		echo "                     a. Si en un archivo completo hay una línea de programas maliciosos" >> $TMPLOG
		echo "                        puede eliminar el archivo inmediatamente." >> $TMPLOG
		echo "                     b. Si en un archivo hay una línea (infección) de un programa de malware," >> $TMPLOG
		echo "                        simplemente elimine la línea del programa sin tener que eliminar un" >> $TMPLOG
		echo "                        archivo o reemplazarlo con el archivo original del sitio oficial.." >> $TMPLOG
		echo "                 3. Coordine con el equipo de desarrolladores web con respecto a la eliminación de malware." >> $TMPLOG
		echo "                 4. Limpiar el malware está más allá de nuestro apoyo," >> $TMPLOG
		echo "                     a menos que tenga contratado el servicio." >> $TMPLOG
		echo "                 5. Sino cuenta con soporte para solucionar su problema," >> $TMPLOG
		echo "                     contactese con soporte@itfinden.com" >> $TMPLOG
		echo "Note            : El Firewall AntiVirus 'bloqueará el permiso de archivo' automáticamente" >> $TMPLOG
		echo "                  debera gestionar la eliminacion del malware o virus dentro de las 24 horas siguientes," >> $TMPLOG
		echo "                  sino su cuenta sera suspendida por proteccion de nuestra infraestructura," >> $TMPLOG
		echo "                  si desea ayuda favor contactarse a el sigueinte correo " >> $TMPLOG
		echo "                  $EMAIL y nos informa de su necesidad o gestion." >> $TMPLOG
        if [[ $MODE -eq 1 ]];then # ls
            echo -e "Ubicacion \t\t\t Tipo:" > $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}' |sort >> $TMPLOG2
        elif [[ $MODE -eq 2 ]];then # chmod ls
            echo -e "Ubicacion \t\t\t Tipo:" > $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}' |sort >> $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
            if [ -f $LIST ];then
                chmod 000 $LIST
            fi
            done
        elif [[ $MODE -eq 3 ]];then # chmod chattr ls
            echo -e "Ubicacion \t\t\t Tipo:" > $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}'|sort >> $TMPLOG2
            imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
            if [ -f $LIST ];then
                chmod 000 $LIST
                chattr +i $LIST
            fi
            done
        fi
        cat $TMPLOG >> $LOGFILE
		/usr/bin/column -t $TMPLOG2 >> $TMPLOG
		/usr/bin/column -t $TMPLOG2 >> $LOGFILE
        echo "" >> $TMPLOG
        echo "" >> $LOGFILE
		malware_report_to_mailuser
done
malware_report_to_mailadmin
printf "Malware scan result logfile:${light_cyan} $LOGFILE ${reset}\n"
}
##### </MODE process>

##### <printing>
# print scan result
function print_scan_result {
	echo "Hostname        : $HOSTNAME" > $LOGFILE
	echo "OS              : $OPERATINGSYSTEM" >> $LOGFILE
	echo "Panel Hosting   : $HOSTINGPANEL" >> $LOGFILE
	echo "Iniciado        : $(date --date=@$STARTED)" >> $LOGFILE
	echo "Completado      : $(date --date=@$COMPLETED)" >> $LOGFILE
	echo "Duracion        : $DURATION" >> $LOGFILE
	echo "Error           : $ERROR" >> $LOGFILE
	echo "Ruta            : $PATHSCAN" >> $LOGFILE
	echo "Tipo Scan       : $SCAN_TYPE" >> $LOGFILE
	echo "Scan ID         : $SCANID" >> $LOGFILE
	echo "Total Scaneo    : $TOTAL archivo(s)" >> $LOGFILE
	echo "Total Archivo   : $TOTAL_FILES archivo(s)" >> $LOGFILE
	echo "Total Virus     : Encontrados $TOTAL_MALICIOUS archivos infectados" >> $LOGFILE
	echo "Modo Action     : $MESSAGE" >> $LOGFILE
	echo "Log File        : $LOGFILE" >> $LOGFILE
	echo "" >> $LOGFILE
}
##### </printing>

##### <MODE action>
function mode_action {
	LIMIT=$TOTAL_MALICIOUS
	imunify-antivirus malware malicious list|grep $SCANID|awk '{print $13}'|grep -Ev "USERNAME"|sort|uniq|while read USERS;do
	echo "Usuario        : $USERS" > $TMPLOG
	message_tips
	if [[ $MODE -eq 1 ]];then # ls
		echo -e "Ubicacion \t\t\t Tipo:" > $TMPLOG2
		imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}' |sort >> $TMPLOG2
	elif [[ $MODE -eq 2 ]];then # chmod ls
		echo -e "Ubicacion: \t\t\t Tipo:" > $TMPLOG2
		imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}' |sort >> $TMPLOG2
		imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
			if [ -f $LIST ];then
				chmod 000 $LIST
			fi
		done
	elif [[ $MODE -eq 3 ]];then # chmod chattr ls
		echo -e "Ubicacion: \t\t\t Tipo:" > $TMPLOG2
		imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4"\t\t\t"$12}'|sort >> $TMPLOG2
		imunify-antivirus malware malicious list --user $USERS --limit $LIMIT|grep $SCANID|grep True|awk '{print $4}'|sort|uniq|while read LIST;do
			if [ -f $LIST ];then
				chmod 000 $LIST
				chattr +i $LIST
			fi
		done
	fi
	cat $TMPLOG >> $LOGFILE
	/usr/bin/column -t $TMPLOG2 >> $TMPLOG
	/usr/bin/column -t $TMPLOG2 >> $LOGFILE
	echo "" >> $TMPLOG
	echo "" >> $LOGFILE
	malware_report_to_mailuser
	done
}
##### </MODE action>

##### <usage>
function usage {
echo "USAGE: $0 --email=[EMAIL ADDRESS] --mode=[ACTION MODE] --path=[PATH]"
echo ""
echo "-e, --email=[EMAIL ADDRESS]        send malware scan report to email address"
echo "-m, --mode=[ACTION MODE]           default value is 1"
echo "     1 = ls                        only for print malicious file list"
echo "     2 = chmod 000                 change permission malicious files to 000"
echo "     3 = chmod 000 && chattr +i    change permission malicious files to 000 and change the attribute to immutable"
echo "-p, --path=[PATH]                  scan directory, default value is /home*/*"
echo "-h, --help                         show usage information"
echo ""
echo "Example:"
echo "$0 --email=soporte@itfinden.com --mode=1 --path=/home/"
echo "$0 -e=your@itfinden.com -m=1 -p=/home/"
}
##### </usage>

##### main
for i in "$@"
do
case $i in
    -e=*|--email=*)
        EMAIL="${i#*=}"
        shift
        ;;
    -m=*|--mode=*)
        MODE="${i#*=}"
        shift
        ;;
    -p=*|--path=*)
        SCANDIR="${i#*=}"
        shift
        ;;
	-h|--help)
		usage
		exit
		;;
    *)
        usage
        exit
        ;;
esac
done

if [ -z "$EMAIL" ];then
      EMAIL="alertas@itfinden.com";
fi


if [[ -z $MODE ]];then
	MODE=1
elif [[ $MODE -eq 0 ]];then
	MODE=1
elif [[ $MODE -gt 3 ]];then
	usage
	exit
fi

if [[ -z $SCANDIR ]];then
	SCANDIR='/home*/*'
elif [[ ! -d $SCANDIR ]];then
	printf "${red}$SCANDIR${reset}: not found\n"
	usage
	exit	
fi

##### <os validation check>
echo -n "Checking Operating System:"
if [[ -f /usr/bin/hostnamectl ]];then
	OPERATINGSYSTEM=$(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2|awk '{print $1}')
	if [[ $OPERATINGSYSTEM == 'CloudLinux' ]] || [[ $OPERATINGSYSTEM == 'CentOS' ]] || [[ $OPERATINGSYSTEM == 'Red' ]];then
		printf "${green} $(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2) ${reset}\n"
		PACKAGEMANAGER=/bin/rpm
	elif [[ $OPERATINGSYSTEM == 'Ubuntu' ]] || [[ $OPERATINGSYSTEM == 'Debian' ]];then
		PACKAGEMANAGER=/usr/bin/dpkg
		if [[ ! -d /etc/sysconfig/imunify360/ ]];then
			mkdir -p /etc/sysconfig/imunify360/
		fi
		if [[ ! -f /etc/sysconfig/imunify360/integration.conf ]];then
			echo "[paths]" > /etc/sysconfig/imunify360/integration.conf
			echo "ui_path = /var/www/html" >> /etc/sysconfig/imunify360/integration.conf
		fi
		printf "${green} $(/usr/bin/hostnamectl|grep "Operating System"|cut -d: -f2) ${reset}\n"
		
	fi
elif [[ -f /etc/redhat-release ]];then
	OPERATINGSYSTEM=$(cat /etc/redhat-release|awk '{print 1}')
	if [[ $OPERATINGSYSTEM == 'CloudLinux' ]] || [[ $OPERATINGSYSTEM == 'CentOS' ]];then
		printf "${green} $(cat /etc/redhat-release|awk '{print 1}') ${reset}\n"
		PACKAGEMANAGER=/bin/rpm
	fi
else
	printf "${red} $OPERATINGSYSTEM ${reset}\n"
	printf "ImunifyAVX: ${red}FAILED${reset}\n"
	echo "Unsupported yet"
	exit
fi
##### </os validation check>

##### <require mailx>
echo -n "Checking mailx: "
if [[ $OPERATINGSYSTEM == 'CloudLinux' ]] || [[ $OPERATINGSYSTEM == 'CentOS' ]] || [[ $OPERATINGSYSTEM == 'Red' ]];then
RPMMAILX=$($PACKAGEMANAGER -qa|grep mailx|cut -d- -f1|head -n1)
	if [[ $RPMMAILX != "mailx" ]];then
		printf "${red}FAILED ${reset}\n"
		printf "mail command not found:${yellow} installing mailx${reset}\n"
		yum install -y mailx
		printf "Checking mailx: ${green}OK ${reset}\n"
	else
		printf "${green}OK ${reset}\n"
	fi
elif [[ $OPERATINGSYSTEM == 'Ubuntu' ]] || [[ $OPERATINGSYSTEM == 'Debian' ]];then
RPMMAILX=$($PACKAGEMANAGER -l|grep mailx)
	if [[ -z $RPMMAILX ]];then
		printf "${red}FAILED ${reset}\n"
		printf "mail command not found:${yellow} installing mailx${reset}\n"
		apt install -y mailx
		printf "Checking mailx: ${green}OK ${reset}\n"
	else
		printf "${green}OK ${reset}\n"
	fi
fi
##### </require mailx>
 
##### <user check>
echo -n "Checking user: "
if [[ $(id -u) -ne 0 ]];then
    printf "${red}FAILED ${reset}\n"
    echo "Need root priviledge. Please try 'sudo su' or 'su -u root' and try again."
    exit
else
    printf "${green}OK ${reset}\n"
fi
##### </user check>

##### <imunifyav check>
echo -n "Checking imunifyav: "
if [[ ! -f /usr/bin/imunify-antivirus ]];then
    printf "${red}FAILED ${reset}\n"
    echo "ImunifyAV was not installed"
    echo "checking system requirement before imunifyav installation"
    FREESPACE=$(expr $(df /|awk 'NR==2 {print $4}') / 1000000)
    MEMORY=$(free -m|awk 'NR==2 {print $2}')
    if [[ ${FREESPACE/.*} -ge 21 ]] && [[ $MEMORY -ge 512 ]];then
        echo "starting imunifyav installation"
        wget https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh -O /root/imav-deploy.sh
        bash /root/imav-deploy.sh
        if [[ -f /usr/bin/imunify-antivirus ]];then
            printf "checking imunifyav:${green} OK${reset}\n"
        else
            printf "checking imunifyav:${red} FAILED${reset}\n"
            exit 
        fi
    else
        printf "ImunifyAV installation:${red} FAILED${reset}\n"
        printf "Hardware Requirements\n"
        printf "RAM:${green} 512 MB${reset}\n"
        printf "Storage:${green} 20 GB ${reset}available disk space\n\n"
        printf "Your $HOSTNAME server hardware\n"
        if [[ $MEMORY -lt 512 ]];then
            printf "RAM:${red} $MEMORY MB${reset}\n"
        elif [[ $MEMORY -ge 512 ]];then
            printf "RAM:${green} $MEMORY MB${reset}\n"
        fi
        if [[ ${FREESPACE/.*} -lt 21 ]];then
            printf "Storage:${red} $FREESPACE GB ${reset}available disk space\n"
        elif [[ ${FREESPACE/.*} -ge 21 ]];then
            printf "Storage:${green} $FREESPACE GB ${reset}available disk space\n"
        fi
        exit
    fi
elif [[ -f /usr/bin/imunify-antivirus ]];then
	if [[ -f /bin/systemctl ]];then
		SYSSTATUS=$(systemctl status imunify-antivirus|grep Active|cut -d: -f2|awk '{print $1}')
		if [[ $SYSSTATUS == "inactive" ]];then
			/bin/systemctl start imunify-antivirus
			printf "${green}OK ${reset}\n"
		elif [[ $SYSSTATUS == "active" ]];then
			printf "${green}OK ${reset}\n"
		fi
	elif [[ -f /sbin/service ]];then
		SYSSTATUS=$(/sbin/service imunify-antivirus status|cut -d. -f1|awk '{print $5}')
		if [[ $SYSSTATUS == "running" ]];then
			printf "${green}OK ${reset}\n"
		elif [[ $SYSSTATUS != "running" ]];then
			/sbin/service imunify-antivirus start
			printf "${green}OK ${reset}\n"
		fi
	fi
fi
##### </imunifyav check>

##### <signature update process>
printf "ImunifyAV signatures: ${yellow}updating ${reset}\n"
printf " geo:${green} $(imunify-antivirus update geo) ${reset}\n"
printf " rules:${green} $(imunify-antivirus update modsec-rules) ${reset}\n"
printf " sigs:${green} $(imunify-antivirus update sigs) ${reset}\n"
printf " static whitelist:${green} $(imunify-antivirus update static-whitelist) ${reset}\n"
printf " eula:${green} $(imunify-antivirus update eula) ${reset}\n"
printf " ip-record:${green} $(imunify-antivirus update ip-record) ${reset}\n"
#printf " sigs-php:${green} $(imunify-antivirus update sigs-php) ${reset}\n"
printf " ossecp:${green} $(imunify-antivirus update ossec) ${reset}\n"
printf "ImunifyAV signatures: ${green}update completed ${reset}\n"
##### </signature update process>

##### <scan process>
STATUS=$(imunify-antivirus malware on-demand status|grep status|awk '{print $2}')
if [[ $STATUS == "stopped" ]];then
	printf "ImunifyAV on-demand scan:${red} $STATUS ${reset}\n"
	printf "Starting ImunifyAV on-demand scan: ${green}"
    imunify-antivirus malware on-demand start --path=$SCANDIR
	printf "${reset}"
    SCANID=$(imunify-antivirus malware on-demand status|grep scanid|awk '{print $2}')
    STATUS=$(imunify-antivirus malware on-demand status|grep status|awk '{print $2}')
    status_check
	load_scan_result
    if [[ $TOTAL_MALICIOUS -gt "0" ]];then
		printf "Found ${red}$TOTAL_MALICIOUS${reset} malware file(s)\n"
		scan_duration
        mode_options
    else
		printf "${green}Clean${reset}: malware not found\n"
    fi
elif [[ $STATUS == "running" ]];then
	printf "${yellow}WARNING${reset}: On-demand scan is already ${yellow}running${reset}\n"
	exit
else
    echo "ImunifyAV on-demand scan: $STATUS"|mail -s "MALWARE SCAN FAILED: [$HOSTNAME] $DATE" $EMAIL
    exit
fi
##### </scan process>
 
##### <log rotate>
if [[ -f $LOGFILE ]];then
	TOTAL_LOG=$(ls /var/log/imunifyav-*.txt|wc -l)
	if [[ $TOTAL_LOG -gt $LOGROTATE ]];then
		DELETELOG=$(expr $TOTAL_LOG - $LOGROTATE)
		ls /var/log/imunifyav-*.txt|sort|head -n $DELETELOG|while read DELETE;do
			if [ -f $DELETE ];then
				rm -f $DELETE;
			fi
		done 
	fi
fi
##### </log rotate>
