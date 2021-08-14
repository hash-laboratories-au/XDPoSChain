#!/bin/sh

echo "${ABC}" > banana.txt
cat banana.txt
echo "${SSH_KEY}" > tem.pem && chmod 400 tem.pem
# Trigger upgrade to a specific commit
ls -ln
ssh -o "StrictHostKeyChecking no" -i tem.pem root@45.77.243.22 -p $DEVNET_PORT 'cd XinFin/Local_DPoS_Setup && ls'
# clean up
rm -rf tem.pem