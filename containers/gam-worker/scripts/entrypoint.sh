#!/bin/bash
#Entrypoint startup script for gam-worker container

shopt -s nocasematch

#Set up HTTP user auth configuration
if [ ! -z "$APIUSERNAME" ]; then
  echo "Setting API username and password from ENV"
  echo "REST.Username=\"$APIUSERNAME\"" > /gam/gam-user.conf
  echo "REST.Password=\"$APIUSERPASSWORD\"" >> /gam/gam-user.conf
fi

#Set up air-gapped option
if [ -z "${AIRGAPPED}" ]; then
  #Air gap not set
  AIRGAPPED_PARAM=''
else
  #Air gap set, set parameter if set to true
  if [ $AIRGAPPED=='true' ]; then
    AIRGAPPED_PARAM='--air-gapped'
  else
    AIRGAPPED_PARAM=''
  fi
fi

/gam/gamserver --updates /updates --server http://0.0.0.0:8080 --daemon --stdout $AIRGAPPED_PARAM

exit 0
