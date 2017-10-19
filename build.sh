# we build nmap from source. get over it.
wget https://nmap.org/dist/nmap-7.60.tar.bz2
bzip2 -cd nmap-7.60.tar.bz2 | tar xvf -
cd nmap-7.60
./configure
make
su root
make install
exit
cd ..