#!/bin/sh

echo "${SSH_KEY}" > tem.pem && chmod 400 tem.pem
# Trigger upgrade to a specific commit
echo "Upgrade devnet to commit $1"
ssh -o "StrictHostKeyChecking no" -i tem.pem $SSH_USER@$SSH_ADDRESS -p $DEVNET_PORT "cd XinFin/Local_DPoS_Setup && ./devnet/deployment.sh $1"

# clean up
rm -rf tem.pem