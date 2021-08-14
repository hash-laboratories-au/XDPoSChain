#!/bin/sh

echo "${SSH_KEY}" > tem.pem && chmod 400 tem.pem
# Trigger upgrade to a specific commit

ssh -o "StrictHostKeyChecking no" -i tem.pem $SSH_USER@$SSH_ADDRESS -p $DEVNET_PORT 'cd XinFin/Local_DPoS_Setup && ls'

# clean up
rm -rf tem.pem