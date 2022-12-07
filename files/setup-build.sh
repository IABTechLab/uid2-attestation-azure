set -ex

apt-get update
apt-get remove -y libsgx-dcap-default-qpl
apt-get install -y dkms linux-headers-$(uname -r) less az-dcap-client wget openjdk-11-jdk-headless net-tools telnet
wget https://download.01.org/intel-sgx/latest/dcap-latest/linux/distro/ubuntu20.04-server/sgx_linux_x64_driver_1.41.bin -O sgx_linux_x64_driver.bin
chmod a+x sgx_linux_x64_driver.bin
./sgx_linux_x64_driver.bin
