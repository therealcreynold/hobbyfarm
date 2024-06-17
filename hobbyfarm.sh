#!/usr/bin/env bash
# https://github.com/zackbradys/rgs-hobbyfarm/tree/main/examples
# script to build a single vm with k3s and hobby-farm

password=Pa22word
domain=rgs.training

######  NO MOAR EDITS #######
export RED='\x1b[0;31m'
export GREEN='\x1b[32m'
export BLUE='\x1b[34m'
export YELLOW='\x1b[33m'
export NO_COLOR='\x1b[0m'

# builds a vm list
#function dolist () { doctl compute droplet list --no-header|grep hobbyfarm |sort -k 2; }
function awslist () { aws ec2 describe-instances --profile creynold-hf --filters Name=tag:Name,Values=creynold_hobbyfarm --query 'Reservations[*].Instances[*].PublicIpAddress' --output text; }

################################# up ################################
function up () {

echo -e -n " building hobbyfarm vm "
# do
#doctl compute droplet create hobbyfarm --region nyc3 --image rockylinux-9-x64 --size s-8vcpu-16gb-amd --ssh-keys 30:98:4f:c5:47:c2:88:28:fe:3c:23:cd:52:49:51:01 --wait --droplet-agent=false > /dev/null 2>&1

#aws
aws ec2 run-instances --profile creynold-hf --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=creynold_hobbyfarm},{Key=KeepRunning,Value=true}]' --image-id ami-051a0f669bb174783 --count 1 --instance-type m7a.4xlarge --key-name creynold-hobbyfarm --security-group-ids sg-00541c4abe118f2b5 --subnet-id subnet-0c976e0b3a97d866b --ebs-optimized --block-device-mapping "[ { \"DeviceName\": \"/dev/sda1\", \"Ebs\": { \"VolumeSize\": 100 } } ]" --user-data $'#!/bin/bash\necho "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDAuAJDGb9xqrptXNLXQbScfnw409MeRk8ZxQpVCfqtbd9d3qAEnnSefWXoLPhBJgB6HZopPANOa5IR7sTzTem0pzJFzzyH0p+4pm7Pb5VDGJQ2nbgVWNlFpHGYyVp2jnI3CuQaOlyl0sJX8x8P9e1dru2IzhjRXD/DIpSuDbe5hxGgTyK/ZiQjwYfZmxrH88SP42YoFe9xjKP457sRBMVe77vdPv0rg/9FRi60gNI7p2nxWA9B+7NSvmrKYYAw8GABlExOp7IUhLAy22tiLN0XTDP9eETUPdQIWGgtoOtaYh+y+9AWSHR/eNmLcdIdPlLpWwyRLes+0VJIyu6fx4Bgol4WkscPK36VxYrzV5l56cR9HCs0dvkEnx1gfgrUGOC9hyQN7Ak8P8JzfeeRLAKX2SJ3mwtbIfZfv/fvLGBtv+gBgAoZxwtTGXpGwAFdJtL7EdbCV/5sXNg4ppIIOJLNKAIV+hVWw0N716AZkxmWDFjdb5nEySE6d8MTAa8fYhU= rgs-creynold@creynold-rgs.local" > /root/.ssh/authorized_keys\nyum install epel-release -y; yum install htop -y; curl -L -o /etc/sysctl.conf https://raw.githubusercontent.com/therealcreynold/hobbyfarm/main/kernel_tuning.txt ; sysctl -p' > /dev/null 2>&1

aws ec2 wait instance-running --profile creynold-hf --filters Name=tag:Name,Values=creynold_hobbyfarm

echo -e "$GREEN" "ok" "$NO_COLOR"

#check for SSH
echo -e -n " checking for ssh "

server=$(awslist)

until [ $(ssh -i "~/.ssh/creynold-hobbyfarm.pem" -o ConnectTimeout=1 root@$server 'exit' 2>&1 | grep 'timed out\|refused' | wc -l) = 0 ]; do echo -e -n "." ; sleep 5; done
echo -e "$GREEN" "ok" "$NO_COLOR"

#update DNS
echo -e -n " updating dns"
doctl compute domain records create $domain --record-type A --record-name hobbyfarm --record-ttl 60 --record-data $server > /dev/null 2>&1
doctl compute domain records create $domain --record-type CNAME --record-name hobby-admin --record-ttl 60 --record-data hobbyfarm.$domain. > /dev/null 2>&1
doctl compute domain records create $domain --record-type CNAME --record-name hobby-backend --record-ttl 60 --record-data hobbyfarm.$domain. > /dev/null 2>&1
doctl compute domain records create $domain --record-type CNAME --record-name hobby-shell --record-ttl 60 --record-data hobbyfarm.$domain. > /dev/null 2>&1
echo -e "$GREEN" "ok" "$NO_COLOR"

sleep 20

echo -e -n " installing rke2"

ssh root@$server 'mkdir -p /etc/rancher/rke2/; useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U; echo -e "\ntls-san:\n- "'$server'"\nkube-controller-manager-arg:\n- bind-address=127.0.0.1\n- use-service-account-credentials=true\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\nkube-scheduler-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\nkube-apiserver-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n- authorization-mode=RBAC,Node\n- anonymous-auth=false\nkubelet-arg:\n- max-pods=400" > /etc/rancher/rke2/config.yaml; curl -sfL https://get.rke2.io | sh - ; systemctl enable --now rke2-server.service' > /dev/null 2>&1

sleep 10

ssh -i "~/.ssh/creynold-hobbyfarm.pem" root@$server cat /etc/rancher/rke2/rke2.yaml | sed  -e "s/127.0.0.1/$server/g" > ~/.kube/config 
chmod 0600 ~/.kube/config

echo -e "$GREEN" "ok" "$NO_COLOR"

echo -e -n " - rke2 active "
sleep 5
until [ $(kubectl get node|grep NotReady|wc -l) = 0 ]; do echo -e -n "."; sleep 2; done
echo -e "$GREEN" "ok" "$NO_COLOR"


############   hobbyfarm install   ############
### Add Helm Repo
echo -e -n " - deploying hobbyfarm "
helm repo add hobbyfarm https://hobbyfarm.github.io/hobbyfarm --force-update > /dev/null 2>&1

### Create Namespace
kubectl create namespace hobbyfarm > /dev/null 2>&1

### Create Certificates
kubectl -n hobbyfarm create secret generic tls-ca --from-file=/Users/rgs-creynold/src/certs/rgs.training/chain.pem  > /dev/null 2>&1
kubectl -n hobbyfarm create secret tls tls-hobbyfarm-certs  --cert=/Users/rgs-creynold/src/certs/rgs.training/cert.pem --key=/Users/rgs-creynold/src/certs/rgs.training/privkey.pem > /dev/null 2>&1

### adding logos
kubectl create configmap rgs-logo -n hobbyfarm --from-file=rancher-labs-stacked-color.svg=images/RGS_Vertical.svg > /dev/null 2>&1

### add creds - set the variables on the shell
# set export ACCESS_KEY=...
# set export SECRET_KEY=...
# set export DO_TOKEN=...
kubectl create secret -n hobbyfarm generic aws-creds --from-literal=access_key=$HF_ACCESS_KEY --from-literal=secret_key=$HF_SECRET_KEY > /dev/null 2>&1
kubectl create secret -n hobbyfarm generic do-token --from-literal=token=$DO_TOKEN > /dev/null 2>&1

### Install Hobbyfarm
helm upgrade -i hobbyfarm hobbyfarm/hobbyfarm -n hobbyfarm --set ingress.enabled=true --set ingress.tls.enabled=true --set ingress.tls.secrets.backend=tls-hobbyfarm-certs --set ingress.tls.secrets.admin=tls-hobbyfarm-certs --set ingress.tls.secrets.ui=tls-hobbyfarm-certs --set ingress.tls.secrets.shell=tls-hobbyfarm-certs --set ingress.hostnames.backend=hobby-backend.$domain --set ingress.hostnames.admin=hobby-admin.$domain --set ingress.hostnames.ui=hobbyfarm.$domain --set ingress.hostnames.shell=hobby-shell.$domain  --set ui.config.title="RGS - Workshop"  --set ui.config.login.logo=https://raw.githubusercontent.com/therealcreynold/hobbyfarm/main/images/RGS_Vertical.svg --set terraform.enabled=true --set shell.replicas=16 --set gargantua.dynamicBaseNamePrefix="clem-" --set gargantua.scheduledBaseNamePrefix="clem-" --set admin.config.title="RGS - Workshop" --set admin.config.login.customlogo=rgs-logo  > /dev/null 2>&1

#--set users.admin.enabled=true --set users.admin.password='$2a$10$QkpisIWlrq/uA/BWcOX0/uYWinHcbbtbPMomY6tp3Gals0LbuFEDO'

# https://github.com/hobbyfarm/hf-provisioner-digitalocean
# --set gargantua.image=ebauman/gargantua:pr-154-3
# helm install hf-provisioner-digitalocean provisioner-digitalocean/chart/hf-provisioner-digitalocean --namespace hobbyfarm > /dev/null 2>&1

sleep 60

echo -e "$GREEN" "ok" "$NO_COLOR"

echo -e -n " - adding settings "
### add users
kubectl apply -f settings.yaml > /dev/null 2>&1
kubectl apply -f users.yaml > /dev/null 2>&1

## add content
hfcli -k ~/.kube/config -n hobbyfarm apply scenario workshop workshop/ > /dev/null 2>&1

############  end hobbyfarm install  ############

echo -e "$GREEN" "ok" "$NO_COLOR"
}

############################## kill ################################
#remove the vms
function kill () {

# for do
#if [ ! -z $(dolist | awk '{printf $3","}' | sed 's/,$//') ]; then
#  echo -e -n " killing it all "
#  for i in $(dolist | awk '{print $2}'); do doctl compute droplet delete --force $i; done
#  for i in $(dolist | awk '{print $3}'); do ssh-keygen -q -R $i > /dev/null 2>&1; done
#  for i in $(doctl compute domain records list $domain|grep hobbyfarm |awk '{print $1}'); do doctl compute domain records delete -f $domain $i; done
#  until [ $(dolist | wc -l | sed 's/ //g') == 0 ]; do echo -e -n "."; sleep 2; done

# for aws
if [ $(awslist | wc -l) = 1 ]; then
  echo -e -n " killing hobbyfarm"
#  for i in $(dolist | awk '{print $2}'); do doctl compute droplet delete --force $i; done
  aws ec2 terminate-instances --profile creynold-hf --instance-ids $(aws ec2 describe-instances --profile creynold-hf --filters Name=tag:Name,Values=creynold_hobbyfarm --query 'Reservations[*].Instances[*].InstanceId' --output text) > /dev/null 2>&1
  for i in $(awslist); do ssh-keygen -q -R $i > /dev/null 2>&1; done
  for i in $(doctl compute domain records list $domain|grep hobby |awk '{print $1}'); do doctl compute domain records delete -f $domain $i; done

  rm -rf ~/.kube/config 

else
  echo -e -n " no cluster found "
fi

echo -e "$GREEN" "ok" "$NO_COLOR"
}

case "$1" in
        up) up;;
        kill) kill;;
        *) echo -e "$RED" " no clue what you are trying to do..." "$NO_COLOR" ; exit 1 ;;
esac
