#!/bin/bash
# reset ataka database (fresh start)

# ask the user for confirmation
echo "This will reset the ataka database. Are you sure? (y/n)"
read answer

if [ "$answer" != "y" ]; then
    echo "Reset cancelled."
    exit 0
fi

# wait 3 seconds before proceeding so the user can cancel, animate appearing dots
WAIT=3
echo -n "Waiting $WAIT seconds"
for i in $(seq 1 $WAIT); do
    echo -n "."
    sleep 1
done
echo ""
. .env

echo "Proceeding with reset..."
rm -rf data/exploits/*
rm -rf data/exploits-valkey/*
rm -rf data/persist/*
rm -rf data/shared/*
rm -rf data/postgres/*
rm -rf data/rabbitmq/*
mkdir -p data/shared/exploits

# check if the user is root
ROOT_CHECK=$(id -u)
if [ "$ROOT_CHECK" -ne 0 ]; then
    echo -n "Need root permissions to run:"
    echo " sudo chown -R $USERID data/"
fi
sudo chown -R $USERID data/