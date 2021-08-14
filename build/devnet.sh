#!/bin/sh


echo "--------------------------1"
echo -ne "${SSH_KEY}"
echo "--------------------------2"

echo -ne "${SSH_KEY}" > tem.pem && chmod 400 tem.pem
# Trigger upgrade to a specific commit
cat tem.pem

ssh -o "StrictHostKeyChecking no" -i tem.pem root@45.77.243.22 -p $DEVNET_PORT 'cd XinFin/Local_DPoS_Setup && ls'
# clean up
rm -rf tem.pem