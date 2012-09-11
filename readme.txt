Temp readme file...

sudo apt-get install build-essential


Need to install libelf

  340  wget http://ftp.br.debian.org/debian/pool/main/e/elfutils/libelf-dev_0.153-1_i386.deb
  341  wget http://ftp.br.debian.org/debian/pool/main/e/elfutils/libelf1_0.153-1_i386.deb
  342  sudo dpkg -i libelf-dev_0.153-1_i386.deb libelf1_0.153-1_i386.deb
  343  locate libelf
  344  cd /usr/lib/x86_64-linux-gnu/
  345  ln -s libelf.a /usr/lib/libelf.so
  346  sudo ln -s libelf.a /usr/lib/libelf.so
  347  sudo ln -s libelf.a /usr/lib32/libelf.so


Execute "ldconfig"
Need to install libbsd-dev

Make sure to create a symbolic link of libelf to /usr/lib and /usr/lib32 and /usr/lib64
