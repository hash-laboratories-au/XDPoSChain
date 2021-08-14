#!/bin/sh


echo "--------------------------1"
echo "${SSH_KEY}"
echo "--------------------------2"

echo "${SSH_KEY}" > tem.pem && chmod 400 tem.pem
# Trigger upgrade to a specific commit
cat tem.pem


# clean up
rm -rf tem.pem