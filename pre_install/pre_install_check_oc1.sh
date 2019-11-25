#!/bin/bash

#setup output file
OUTPUT="/tmp/preInstallCheckResult"
rm -f ${OUTPUT}

bash -n "$BASH_SOURCE" 2> /dev/null
syntax_result=$?

if [ $syntax_result != 0 ]; then
  echo "Finished with Syntax Error." | tee -a ${OUTPUT}
  exit 3
fi


function checkRAM(){
    local size="$1"
    local limit="$2"
    local message="$3"
    if [[ ${size} -lt ${limit} ]]; then
        if [[ "$NODETYPE" == "worker" ]]; then
	    eval "$message='ERROR: RAM is ${size}GB, while requirement is ${limit}GB'"
        else
	    eval "$message='WARNING: RAM is ${size}GB, while requirement is ${limit}GB'"
        fi
        return 1
    fi
}

function checkCPU(){
    local size="$1"
    local limit="$2"
    local message="$3"
    if [[ ${size} -lt ${limit} ]]; then
        if [[ "$NODETYPE" == "worker" ]]; then
            eval "$message='ERROR: CPU cores are ${size}, while requirement are ${limit}'"
        else
            eval "$message='WARNING: CPU cores are ${size}, while requirement are ${limit}'"
        fi
        return 1
    fi
}

function usage(){
    echo "This script checks if this node meets requirements for installation."
    echo "Arguments: "
    echo "--type=[master|worker|infra]     To specify a node type"
    echo "--help                                      To see help "
    echo ""
    echo "Example: "
    echo "./pre_install_check_oc.sh --type=master --installpath=/ibm/cpd --ocuser=ocadmin"
    echo "./pre_install_check_oc.sh --type=master --installpath=/ibm/cpd --ocuser=ocadmin --ocpassword=icp4dAdmin"
}


#Duplicate function also found in utils.sh
function binary_convert() {
    input=$1
    D2B=({0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1})
    if (( input >=0 )) && (( input <= 255 ))
    then
        echo $((10#${D2B[${input}]}))
    else
        (>&2 echo "number ${input} is out of range [0,255]")
    fi
}

# Test the if weave subnet overlaps with node subnets
# Example --> test_subnet_overlap 9.30.168.0/16 subnet
#          subnet IP is 9.30.168.0
#          mask is 255.255.0.0
#          takes the logical AND of the subnet IP with the mask
#          Result is 9.30.0.0
#          Minimum of subnet range is 9.30.0.1
#          Add the range which is 2^(32-masknumber) - 2
#          Maximum is 9.30.255.254
#          Creates the minimum and maximum for ip route subnets
#          Compares the weave subnet which is passed to the ip route subnets
#          If the subnets overlap will return 1 and the overlapping subnet
#          If we have a non-default subnet in ip route will return 2 and the non-default field
function test_subnet_overlap() {
    local err_subnet=$3
    # Create the overlay mask
    if [[ ! "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        eval $err_subnet="$1"
        return 3
    fi
    local weave_mask_num=($(echo $1 | cut -d'/' -f2))
    local weave_mask="$(head -c $weave_mask_num < /dev/zero | tr '\0' '1')$(head -c $((32 - $weave_mask_num)) < /dev/zero | tr '\0' '0')"
    # Calculate range difference
    local diff=$((2**(32-$weave_mask_num)))
    # Break the overlay subnet IP into it's components
    local weave_sub=($(echo $1 | cut -d'/' -f1 | sed 's/\./ /g'))
    local weave_bin=""
    # Convert the overlay subnet IP to binary
    for weave in ${weave_sub[@]}; do
        cur_bin="00000000$(binary_convert $weave)"
        local weave_bin="${weave_bin}${cur_bin: -8}"
    done
    # Bitwise AND of the mask and binary overlay IP
    # Develop the range (minimum to maximum) of the overlay subnet
    local weave_min=$(echo $((2#$weave_bin & 2#$weave_mask)) | tr -d -)
    weave_min=$((weave_min + 1))
    local weave_max=($(($weave_min + $diff - 2)))
    # Perform the same steps for node routing subnets
    local ips=($2)
    for ip in ${ips[@]}; do
        if [[ ! "${ip}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            eval $err_subnet="$ip"
            return 2
        fi
        local sub_ip=($(echo $ip | cut -d'/' -f1 | sed 's/\./ /g'))
        local sub_mask_num=($(echo $ip | cut -d'/' -f2))
        local sub_mask="$(head -c $sub_mask_num < /dev/zero | tr '\0' '1')$(head -c $((32 - $sub_mask_num)) < /dev/zero | tr '\0' '0')"
        local sub_diff=$((2**(32-$sub_mask_num)))
        local sub_bin=""
        for sub in ${sub_ip[@]}; do
            bin="00000000$(binary_convert $sub)"
            local sub_bin="${sub_bin}${bin: -8}"
        done
        local sub_min=$(echo $((2#$sub_bin & 2#$sub_mask)) | tr -d -)
        sub_min=$((sub_min + 1))
        local sub_max=($(($sub_min + $sub_diff - 2)))
    # Check for if the overlay subnet and node routing subnet overlaps
        if [[ ("$sub_min" -gt "$weave_min" && "$sub_min" -le "$weave_max") || ("$weave_min" -gt "$sub_min" && "$weave_min" -le "$sub_max") || ("$sub_min" == "$weave_min" || "$sub_max" == "$weave_max") ]]; then
            echo "The overlay network ${1} is in the node routing subnet ${ip}"
         # Define problem subnet
            eval $err_subnet="$ip"
            return 1
        else
            echo "The overlay network ${1} is not in the node routing subnet ${ip}"
        fi
    done
    return 0
}

function log() {
 
    if [[ "$1" =~ ^ERROR* ]]; then
        eval "$2='\033[91m\033[1m$1\033[0m'"
    elif [[ "$1" =~ ^Running* ]]; then
        eval "$2='\033[1m$1\033[0m'"
    elif [[ "$1" =~ ^WARNING* ]]; then
        eval "$2='\033[1m$1\033[0m'"
    else
        eval "$2='\033[92m\033[1m$1\033[0m'"
    fi
 
}

function logHeader() {
 
	log "$2. $1" msg
	printout "$msg"
 
}

function helper(){
    echo "##########################################################################################
   Help:
    ./$(basename $0) --type=[master|worker|management|proxy|va] --installpath=[installation file location]
                     --ocuser=[openshift user] --ocpassword=[password]

    Specify a node type, installation directory, Openshift user and password to start the validation.
    Use this preReq checking before Cloud Pak for Data installation.
    Please run this script in all the nodes of your cluster, as differnt node types have different RAM/CPU requirement.
##########################################################################################"
}

function checkpath(){
    local mypath="$1"
    if [[  "$mypath" = "/"  ]]; then
        echo "ERROR: Can not use root path / as path" | tee -a ${OUTPUT}
        usage
        exit 1
    fi
    if [ ! -d "$mypath" ]; then
        echo "ERROR: $mypath not found in node." | tee -a ${OUTPUT}
        usage
        exit 1
    fi
}

function printout() {
    echo -e "$1" | tee -a ${OUTPUT}
}

function become_cmd(){
    local BECOME_CMD="$1"
    if [[ "$(whoami)" != "root" && $pb_run -eq 0 ]]; then
        BECOME_CMD="sudo $BECOME_CMD"
    elif [[ "$(whoami)" != "root" && $pb_run -eq 1 ]]; then
        BECOME_CMD="pbrun bash -c \"$BECOME_CMD\""
    fi
    eval "$BECOME_CMD"
    return $?
}

function check_package_availability(){
    additional=""
    local error_return=$2
    # $1 - Dependency being checked
    # $2 - Parent of this dependency (if it is not a subdependency this will be "none")
    # $3 - Version of the dependency (if these is no specific version uses empty string)
    # $4 - Determines if we allow installed versions of the packages or not
    #      will be i if we want to check for installed packages otherwise it will be empty
    pack_name="$(echo $1 | cut -d'#' -f1)"
    parent="$(echo $1 | cut -d'#' -f2)"
    version="$(echo $1 | cut -d'#' -f3)"
    pre_installable="$(echo $1 | cut -d'#' -f4)"
    error=0
    INSTALLSTATE=""
    installed=0
    testInstalled=""
    testAvailable=""
    if [[ "$(whoami)" != "root" && ${pb_run} -eq 1 ]]; then
        testInstalled="$(${BECOME_CMD} \"yum list installed ${pack_name} 2> /dev/null\")"
    else
        testInstalled="$(${BECOME_CMD} yum list installed ${pack_name} 2> /dev/null)"
    fi
    installed=${PIPESTATUS[0]}
    package=0
    if [[ "$(whoami)" != "root" && ${pb_run} -eq 1 ]]; then
       testAvailable="$(${BECOME_CMD} \"yum list available ${pack_name} 2> /dev/null\")"
    else
        testAvailable="$(${BECOME_CMD} yum list available ${pack_name} 2> /dev/null)"
    fi
    package=${PIPESTATUS[0]}
    if [[ "$version" != "" ]]; then
        if [[ $installed -eq 0 ]]; then
            echo "$testInstalled" | grep "$version" > /dev/null
            installed=$?
        fi
        if [[ $package -eq 0 ]]; then
            echo "$testAvailable" | grep "$version" > /dev/null
            package=$?
        fi
    fi
    if [[ $installed -eq 0 ]]; then
        if [[ "${pre_installable}" != "i" ]]; then
            if [[ $package -eq 0 ]]; then
                INSTALLSTATE="already installed. Please uninstall and continue."
                error=1
            else
                INSTALLSTATE="already installed and not available from the yum repos. Please uninstall and add the package with it's dependencies to the yum repos."
                error=1
            fi
        fi
    else
        if [[ $package -ne 0 ]]; then
            if [[ "${pre_installable}" != "i" ]]; then
                INSTALLSTATE="not available from the yum repos. Please add the package with it's dependencies to the yum repos."
                error=1
            else
                INSTALLSTATE="not available from the yum repos and not installed. Please add the package with it's dependencies to the yum repos or install the package."
                error=1
            fi
        fi
    fi
    eval $error_return=""
    if [[ $error -eq 1 ]]; then
        if [[ "${version}" != "" ]]; then
            if [[ "$parent" == "none" ]]; then
                eval $error_return="ERROR: ${pack_name} with version ${version} is ${INSTALLSTATE}"
            else
                eval $error_return="ERROR: The ${pack_name} dependency with version ${version} for the $parent package is ${INSTALLSTATE}"
            fi
        else
            if [[ "$parent" == "none" ]]; then
                eval $error_return="ERROR: ${pack_name} is ${INSTALLSTATE}"
            else
                eval $error_return="ERROR: The ${pack_name} dependency for the $parent package is ${INSTALLSTATE}"
            fi
            
        fi
    fi
    return $error
}


#for internal usage
CPU=16
RAM=64
WEAVE=0
pb_run=0
centos_repo=0
root_size=50
install_path_size=200
data_path_size=200
CRIODOCKERINSTALLPATH=/var/lib/docker
#CRIOINSTALLPATH=/var/lib/container
CONTAINERHOMESIZE=200

#Global parameter

WARNING=0
ERROR=0
LOCALTEST=0

if [[ "$(whoami)" != "root" && $pb_run -eq 0 ]]; then
    BECOME_CMD="sudo "
elif [[ "$(whoami)" != "root" && $pb_run -eq 1 ]]; then
    BECOME_CMD="pbrun bash -c "
fi

#input check
if [[  $# -lt 1  ]]; then
    usage
    echo test
    exit 1
else
    for i in "$@"
    do
    case $i in

        --help)
            helper
            exit 1
            ;;

        --type=*)
            NODETYPE="${i#*=}"
            shift
            # Checks for CPU and RAM are here but we only care about worker nodes on OpenShift.
            if [[ "$NODETYPE" = "master" ]]; then       
                if [[ "${DATAPATH}" != "DATAPATH_PLACEHOLDER" ]]; then
                    CPU=16
                    RAM=32
                else 
                    CPU=8
                    RAM=16
                fi
            elif [[ "$NODETYPE" = "worker" ]]; then
                CPU=16
                RAM=64
            elif [[ "$NODETYPE" = "proxy" ]]; then
                CPU=2
                RAM=4
            elif [[ "$NODETYPE" = "management" ]]; then
                CPU=4
                RAM=8
            else
                echo "please only specify type among master/worker/proxy/management"
                exit 1
            fi
            ;;

        *)
            echo "Sorry the argument is invalid"
            usage
            exit 1
            ;;
    esac
    done
fi



echo "##########################################################################################" > ${OUTPUT} 2>&1



docker_home_exists()
{

logHeader "Checking if Docker folder is defined." $1
LOCALTEST=0


if [ -d "$CRIODOCKERINSTALLPATH" ] 
then
    log "WARNING: Directory "$CRIODOCKERINSTALLPATH" exists, some of the tests would be done assuming that this is the final location of docker storage " result 
    output+="$result"
	
else
    log "ERROR: Directory "$CRIODOCKERINSTALLPATH" does not exists. Please setup the directory and rerun the tests " result
    local output+="$result"
    STOPERROR=1

fi

printout "$output"


if [[ ${STOPERROR} -eq 1 ]]; then
    exit -1
fi
eval "$2='$LOCALTEST'"
eval "$3='$output'"

}



disk_latency()
{

logHeader "Checking Disk latency" $1
LOCALTEST=0

become_cmd "dd if=/dev/zero of=${CRIODOCKERINSTALLPATH}/testfile bs=512 count=1000 oflag=dsync &> output"

res=$(cat output | tail -n 1 | awk '{print $6}')
# writing this since bc may not be default support in customer environment
res_int=$(echo $res | grep -E -o "[0-9]+" | head -n 1)
if [[ $res_int -gt 60 ]]; then
    log "ERROR: Disk latency test failed. By copying 512 kB, the time must be shorter than 60s, recommended to be shorter than 10s, validation result is ${res_int}s " result
    local output+="$result"
    ERROR=1
    LOCALTEST=1
  
fi
eval "$2='$LOCALTEST'"
eval "$3='$output'"
}

disk_throughput()
{

logHeader "Checking Disk throughput" $1
LOCALTEST=0

become_cmd "dd if=/dev/zero of=${CRIODOCKERINSTALLPATH}/testfile bs=1G count=1 oflag=dsync &> output"

res=$(cat output | tail -n 1 | awk '{print $6}')
# writing this since bc may not be default support in customer environment
res_int=$(echo $res | grep -E -o "[0-9]+" | head -n 1)
if [[ $res_int -gt 35 ]]; then
    log "ERROR: Disk throughput test failed. By copying 1.1 GB, the time must be shorter than 35s, recommended to be shorter than 5s, validation result is ${res_int}s " result
    output+="$result"
    ERROR=1
    LOCALTEST=1
elif [[ $res_int -gt 5 ]]; then
    log "WARNING: Disk throughput test failed. By copying 1.1 GB, the time is recommended to be shorter than 5s, validation result is ${res_int}s " result
    output+="$result"
    WARNING=1
    LOCALTEST=1
fi


rm -f output > /dev/null 2>&1
rm -f ${INSTALLPATH}/testfile > /dev/null 2>&1

eval "$2='$LOCALTEST'"
eval "$3='$output'"
}


default_gateway()
{

logHeader "Checking Default Gateway" $1
LOCALTEST=0

become_cmd "ip route" | grep "default" > /dev/null 2>&1

if [[ $? -ne 0 ]]; then
    log "ERROR: default gateway is not setup " result
    output+="$result"
    ERROR=1
    LOCALTEST=1
fi

rm -f output > /dev/null 2>&1

eval "$2='$LOCALTEST'"
eval "$3='$output'"
}

dns_configuration()
{

logHeader "Checking DNS Configuration" $1
LOCALTEST=0

become_cmd "cat /etc/resolv.conf" | grep  -E "nameserver [0-9]+.[0-9]+.[0-9]+.[0-9]+" &> /dev/null

if [[ $? -ne 0 ]]; then
    log "ERROR: DNS is not properly setup. Could not find a proper nameserver in /etc/resolv.conf " result
    output+="$result"
    ERROR=1
    LOCALTEST=1
fi
eval "$2='$LOCALTEST'"
eval "$3='$output'"

}

dns_hostnameresolve()
{

logHeader "Resolving hostname via  DNS" $1
LOCALTEST=0

become_cmd "host $(hostname) &> /dev/null 2>&1"

if [[ $? -ne 0 ]]; then
    log "ERROR: $(hostname) is not resolved via the DNS. Check /etc/resolve.conf " result
    output+="$result"
    ERROR=1
    LOCALTEST=1
fi
eval "$2='$LOCALTEST'"
eval "$3='$output'"
}

firewall_check()
{
logHeader "Checking if firewall is started" $1
LOCALTEST=0

become_cmd "systemctl status firewalld > /dev/null 2>&1"

if [ $? -ne 0 ]; then         
    log "ERROR: firewalld is disabled, run systemctl enable firewalld;systemctl start firewalld" result
    output+="$result"
    LOCALTEST=1
    WARNING=1
fi
eval "$2='$LOCALTEST'"
eval "$3='$output'"
}

processor_type()
{
LOCALTEST=0
logHeader "Checking processor type" $1

PROCESSOR="$(${BECOME_CMD} uname -p 2>&1)"
if [[ "$PROCESSOR" != "x86_64" ]]; then
    log "ERROR: Processor type must be x86_64" result
    output+="$result"
    LOCALTEST=1
    ERROR=1
fi
eval "$2='$LOCALTEST'"
eval "$3='$output'"
}

sse42_check()
{

logHeader "Checking SSE4.2 instruction supported" $1
LOCALTEST=0

SSE2="$(${BECOME_CMD} cat /proc/cpuinfo | grep -i sse4_2 | wc -l 2>&1)"
if [[ "$SSE2" < 1 ]]; then
    log "WARNING: Streaming SIMD Extensions 4.2 is not supported on this node" result
    LOCALTEST=1
    ERROR=1
    output+="$result"
fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"

}


test_time_sync()
{

logHeader "Checking timesyn status" $1
LOCALTEST=0


become_cmd "ntpstat" &> /dev/null
if [[ $? -ne 0 ]] ; then
    log "ERROR: System clock is currently not synchronised, use ntpd or chrony to sync time" result
    LOCALTEST=1
    ERROR=1
    output+="$result"
fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"

}

test_seLinux()
{
logHeader "Checking SELinux is enforcing" $1
LOCALTEST=0
if [[ "$(whoami)" != "root" && ${pb_run} -eq 1 ]]; then
    selinux_res="$(${BECOME_CMD} \"getenforce\" 2>&1)"
else 
    selinux_res="$(${BECOME_CMD} getenforce 2>&1)"
fi


if [[ ! "${selinux_res}" =~ ("Enforcing"|"enforcing") ]]; then
    log "ERROR: SElinux is not in enforcing mode, but your node currently is ${selinux_res} " result

    output+="$result"
    LOCALTEST=1
    ERROR=1
fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"
}

test_cronJobs()
{

logHeader "Checking pre-existing cronjob" $1
become_cmd "crontab -l" | grep -E "*" &> /dev/null 2>&1

if [[ $? -eq 0 ]] ; then
    log "WARNING: Found cronjob set up in background. Please make sure cronjob will not change ip route, hosts file or firewall setting during installation" result
    output+="$result"
    LOCALTEST=1
    WARNING=1
fi

eval "$3='$output'"
eval "$2='$LOCALTEST'"

}

test_redhatregistryaccess()
{
logHeader "Checking connectivity to Redhat Artifactory server" $1
LOCALTEST=0

become_cmd "ping -c 1 1registry.redhat.io" &> /dev/null
LOCALTEST=0

if [[ $? -ne 0 ]] ; then
    log "WARNING: registry.redhat.io is not reachable. Please make sure the the server is reachable. Enabling proxy might fix this otherwise an offline installation needs to be performed" result
    output+="$result"
    LOCALTEST=1
    WARNING=1
fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"
}

test_ibmregistryaccess()
{
logHeader "Checking connectivity to IBM Artifactory server" $1
LOCALTEST=0

become_cmd "ping -c 1 cp.icr.io" &> /dev/null

if [[ $? -ne 0 ]] ; then
    log "WARNING: cp.icr.io is not reachable. Please make sure the the server is reachable. Enabling proxy might fix this otherwise an offline installation needs to be performed" result
    output+="$result"
    LOCALTEST=1
    WARNING=1
fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"
}

test_xfsftype()
{
logHeader "Checking XFS FTYPE for overlay2 drivers" $1
LOCALTEST=0


docker_part=$(df -P $CRIODOCKERINSTALLPATH | tail -1 | cut -d' ' -f 1)
lsblk -f "$docker_part" | grep xfs &> /dev/null
if [[ $? -eq 0 ]] ; then
mountpoint=$(lsblk -m "$docker_part" --output MOUNTPOINT --noheadings)
xfs_info "$mountpoint" | grep ftype=1 &> /dev/null
if [[ $? -ne 0 ]] ; then
    log "ERROR: Docker target filesystem must be formatted with ftype=1. The partition $docker_part does not seem to have been formatted with that flag. Please reformat or move the docker home location " result
    output+="$result"
    LOCALTEST=1
    WARNING=1
fi

fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"
}

test_containerstoragesize()
{
#docker storage

logHeader "Checking container storage size" $1
LOCALTEST=0

docker_part=$(df -P $CRIODOCKERINSTALLPATH | tail -1 | cut -d' ' -f 1)
available=$(df -h "$docker_part"  --output=avail | tail -1 | sed 's/G//g')

if [[ available -lt 200 ]] ; then
    log "ERROR: Docker target filesystem does not have enough storage. The minimum recommended is 200GB " result
    output+="$result"
    LOCALTEST=1
    WARNING=1
fi

eval "$3='$output'"
eval "$2='$LOCALTEST'"
}

test_kernelsema()
{

logHeader "Checking kernel semaphore parameter" $1
LOCALTEST=0

TARGET_SEM="250 1024000 32 4096"
CURRENT_SEM="$(${BECOME_CMD} cat /proc/sys/kernel/sem|sed -e "s/[[:space:]]\+/ /g" 2>&1)"
if [[ "$CURRENT_SEM" != "$TARGET_SEM" ]] ; then
    log "ERROR: Current semaphore setting ($CURRENT_SEM) is not compatible with Cloud Pak for Data" result
    LOCALTEST=1
    ERROR=1
    output+="$result"
fi

eval "$3='$output'"
eval "$2='$LOCALTEST'"
}


test_rootfilesystem()
{

logHeader "Checking size of root partition" $1
LOCALTEST=0


if [[ "$(whoami)" != "root" && ${pb_run} -eq 1 ]]; then
    actual_root_size=$(${BECOME_CMD} "df -k -BG \"/\" | awk '{print($4 \" \" $6)}' | grep \"/\" | cut -d' ' -f1 | sed 's/G//g'")
else
    actual_root_size=$(${BECOME_CMD} df -k -BG "/" | awk '{print($4 " " $6)}' | grep "/" | cut -d' ' -f1 | sed 's/G//g')
fi
if [[ $actual_root_size -lt $root_size ]] ; then
    log "WARNING: size of root partition is smaller than ${root_size}G, This should be fine as long as $CRIODOCKERINSTALLPATH, /var/lib/etcd, /var/log. /tmp are mounted on separate partitions" result
    output+="$result"
    LOCALTEST=1
    ERROR=1
fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"
}

# Check if hostnames are all in lowercase characters
test_hostnameformat()
{
logHeader "Checking size of root partition" $1
LOCALTEST=0

output="Checking if hostname is in lowercase characters\n"

if [[ "$(whoami)" != "root" && ${pb_run} -eq 1 ]]; then
    host_name=$(${BECOME_CMD} "hostname")
else
    host_name=$(${BECOME_CMD} hostname)
fi

if [[ "$host_name" =~ [A-Z] ]]; then
    log "ERROR: Only lowercase characters are supported in the hostname ${host_name}\n" result
    output+="$result"
    ERROR=1
    LOCALTEST=1
fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"
}

# Get CPU numbers and min frequency
test_cpuram()
{

LOCALTEST=0
logHeader "Checking CPU core numbers and RAM size" $1

if [[ "$(whoami)" != "root" && ${pb_run} -eq 1 ]]; then
    cpunum=$(${BECOME_CMD} "cat /proc/cpuinfo" | grep '^processor' |wc -l | xargs)
else
    cpunum=$(${BECOME_CMD} cat /proc/cpuinfo | grep '^processor' |wc -l | xargs)
fi
if [[ ! ${cpunum} =~ ^[0-9]+$ ]]; then
    log "ERROR: Invalid number of cpu cores ${cpunum}\n" result
    output+="$result"
else
    checkCPU ${cpunum} ${CPU} msg
    if [[ $? -eq 1 ]]; then
        log "${msg}\n" result
        output+="$result"
    LOCALTEST=1
    WARNING=1
    fi
fi
if [[ "$(whoami)" != "root" && ${pb_run} -eq 1 ]]; then
    mem=$(${BECOME_CMD} "cat /proc/meminfo" | grep MemTotal | awk '{print $2}')
else
    mem=$(${BECOME_CMD} cat /proc/meminfo | grep MemTotal | awk '{print $2}')
fi
# Get Memory info
mem=$(( $mem/1000000 ))
if [[ ! ${mem} =~ ^[0-9]+$ ]]; then
    log "ERROR: Invalid memory size ${mem}\n" result
    output+="$result"
else
    checkRAM ${mem} ${RAM} message
    if [[ $? -eq 1 ]]; then
        log "${message}\n" result
        output+="$result"
    LOCALTEST=1
    WARNING=1
    fi
fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"
}


# Get OS version
test_osversion()
{

LOCALTEST=0
logHeader "Checking if appropriate os and version" $1
 
osName=$(grep ^ID= /etc/os-release | cut -f2 -d'"')
if [[ "$osName" == "rhel" ]]; then
    osVer=$(grep ^VERSION_ID= /etc/os-release | cut -f2 -d'"')
    if [[ "$osVer" < "7.4" && "$osVer" > "7.7" ]]; then
        log "ERROR: The OS version must be between 7.4 and 7.7." result
        output+="$result"
        ERROR=1
        LOCALTEST=1
    fi
else
    log "ERROR: The OS must be Red Hat " result
    output+="$result"
    ERROR=1
    LOCALTEST=1
fi

eval "$3='$output'"
eval "$2='$LOCALTEST'"
}


test_ipforwarding()
{

LOCALTEST=0
logHeader "Ensuring the IPv4 IP Forwarding is set to enabled" $1

ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward)
if [[ $ipv4_forward -eq 0 ]]; then
    conf_check=$(sed -n -e 's/^net.ipv4.ip_forward//p' /etc/sysctl.conf | tr -d = |awk '{$1=$1};1')
    if [[ $conf_check -eq 1 ]]; then
        log "ERROR: The sysctl config file (/etc/sysctl.conf) has IPv4 IP forwarding set to enabled (net.ipv4.ip_forward = 1) but the file is not loaded. Please run the following command to load the file: sysctl -p." result
        output+="$result"
    else
        log "ERROR: The sysctl config has IPv4 IP forwarding set to disabled (net.ipv4.ip_forward = 0). IPv4 forwarding needs to be enabled (net.ipv4.ip_forward = 1). To enable IPv4 forwarding we recommend use of the following commands: \"sysctl -w net.ipv4.ip_forward=1\" or \"echo 1 > /proc/sys/net/ipv4/ip_forward\"." result
        output+="$result"
    fi
    ERROR=1
    LOCALTEST=1
fi
if [[ ${LOCALTEST} -eq 1 ]]; then
    printout "$output"
fi

if [[ "$NODETYPE" == "master" ]]; then
    LOCALTEST=0
    
    output="Ensuring the vm.max_map_count under sysctl is at least 262144\n"
    vm_max_count=$(sysctl vm.max_map_count | cut -d "=" -f2)
    if [[ $vm_max_count -lt 262144 ]]; then
        log "ERROR: The sysctl configuration for vm.max_map_count is not at least 262144. Please run the following command to set it to 262144 \"sysctl -w vm.max_map_count=262144\"." result
        output+="$result"
        ERROR=1
        LOCALTEST=1
    fi
    if [[ ${LOCALTEST} -eq 1 ]]; then
        printout "$output"
    fi
        

    LOCALTEST=0
    
    output="Ensuring the net.ipv4.ip_local_port_range under sysctl starts at 10240\n" 
    port_lower=$(sysctl net.ipv4.ip_local_port_range | cut -d "=" -f2 | awk '{print $1}')

    port_higher=$(sysctl net.ipv4.ip_local_port_range | cut -d "=" -f2 | awk '{print $2}')
    if [[ $port_lower -lt 10240 ]]; then
        log "ERROR: The sysctl configuration for net.ipv4.ip_local_port_range does not start with 10240. Please run the following command to set the lower end of the range to 10240: sysctl -w net.ipv4.ip_local_port_range=\"10240  $port_higher\"" result


        output+="$result"
        ERROR=1
        LOCALTEST=1
    fi

fi
eval "$3='$output'"
eval "$2='$LOCALTEST'"
}


funcs_to_test=( docker_home_exists disk_latency disk_throughput default_gateway dns_configuration dns_hostnameresolve firewall_check processor_type sse42_check test_kernelsema test_containerstoragesize test_xfsftype test_ibmregistryaccess test_redhatregistryaccess test_cronJobs test_seLinux test_time_sync test_rootfilesystem test_hostnameformat test_cpuram test_osversion test_ipforwarding)
i=1
for testPrereq in "${funcs_to_test[@]}"
do
    LOCALTEST=1
        output=""
        $testPrereq $i myresult myerror

        if [[ ${myresult} -eq 0 ]]; then
    log "   [Passed]\n" status
    printout "$status"
        else
    printout "   $myerror\n"
    fi
        i=$(($i+1))
done



#log result
if [[ ${ERROR} -eq 1 ]]; then
    echo "Finished with ERROR, please check ${OUTPUT}"
    exit 2
elif [[ ${WARNING} -eq 1 ]]; then
    echo "Finished with WARNING, please check ${OUTPUT}"
    exit 1
else
    echo "Finished successfully! This node meets the requirement" | tee -a ${OUTPUT}
    exit 0
fi
