#!/bin/bash

#

#
# parses the argument list
# when it finds a --var=name or -v or -v name
# it creates a variable _ICP_{VAR} and sets its value to {NAME}
# note that the created variable is in uppercase.
# in your shell script, use:
# . $ROOT/bin/get_params.sh
# Short forms of arguments supported with the help of $INI_FILE map. 
# A map (below $INI_FILE) is provided where shorts forms are mapped to the long forms.
# . $ROOT/bin/get_params.sh icp4dsupport
# [--var=yes] can be written as -v [assuming the INIT_FILE this map is provided]
# which is translated to _ICP_VAL=yes
# [-v val] would be translated to _ICP_VAL_=val
#
# ex: get_params.sh --confirm_db=yes --name=acme
#     sets 2 variables: _ICP_CONFIRM_DB=yes, _ICP_NAME=acme
#     get_params.sh -v val -c sectionkey [assume in map v=expanedV, c=expandedC]
#     sets 2 varables : _ICP_EXPANDEDV=val, _ICP_EXPANDEDC=yes
# use --debug=yes to see some debugging info
if [ -f $UTIL_DIR/conf/param_maps.ini ]
then
        INI_FILE=$UTIL_DIR/conf/param_maps.ini
else
        
                echo ""
                echo "Please check whether environment is installed and setup correctly."
                echo "File param_maps.ini does not exist in $TOP/bin/conf"
                echo ""
                exit 1
       
fi

args=( "$@" )
cnt="${#args[@]}"
ptr=0

for _VAR in "$@"; do
flag=0
case ${_VAR} in
        --*=* )
            _VALUE=`echo ${_VAR}|cut -f2 -d "="`
            #_NAME=`echo ${_VAR}|cut -f1 -d "="|cut -f3 -d "-"|tr '[:lower:]' '[:upper:]'` 
            #_NAME=`echo ${_VAR}|cut -f1 -d "="|cut -f3 -d "-"|tr '[a-z]' '[A-Z]'`
            _NAME=`echo ${_VAR}|cut -f1 -d "="|cut -f3 -d "-"|tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`
            _NEW_NAME="_ICP_${_NAME}"
            flag=1
            ptr=$((ptr+1))
   ;; 
       --* )
            _NAME=`echo ${_VAR}|cut -f3 -d "-"|tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`
            _NEW_NAME="_ICP_${_NAME}"
            _VALUE="yes"
            flag=1
            ptr=$((ptr+1)) 
   ;;
       -[^-]* )
            _NAME=`echo ${_VAR}|cut -f2 -d "-"`
            INI_SECTION="${args[$((cnt-1))]}"
            eval `sed -e 's/[[:space:]]*\=[[:space:]]*/=/g' \
                          -e 's/;.*$//' \
                          -e 's/[[:space:]]*$//' \
                          -e 's/^[[:space:]]*//' \
                          -e "s/^\(.*\)=\([^\"']*\)$/\1=\"\2\"/" \
                          < $INI_FILE`  
            _NAME=`eval echo \\$${_NAME}|tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`
            _NEW_NAME="_ICP_${_NAME}"
            ptr=$((ptr+1))
            _VALUE="${args[$((ptr))]}"
            if [ `echo ${_VALUE} | grep -e "-"` ] || [[ -z ${_VALUE} ]] ; then
            _VALUE="yes"
            else
              ptr=$((ptr+1))
            fi
            flag=1
            #echo $_NEW_NAME=$_VALUE
    
   ;;
  esac
           # do not assign value twice (debug mode looks nicer with nested calls :-)
            if [ ! "`eval echo \\$${_NEW_NAME}`" = "${_VALUE}" -a $flag -eq 1 ]; then
                if [ "${_ICP_DEBUG}" = "yes" ]; then
                    echo "[setting ${_NEW_NAME}=${_VALUE}]"
                fi
                eval "${_NEW_NAME}=\"${_VALUE}\""
            fi
done
