#!/bin/bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCY1NDvUHj12s6KrU5UQdgL4LmsZEzedRWNwo0EpBHqWr9NO6nZu18wXQ8b0aKHglR4/EHYs8xUZwe5KWX6UCGPfZoczg3mx9Cr5Q7yLaIwzv0ZpeM0fjV2OZgqfvSqZ+NKiz7KhKBowPsKyNyLEAUT3rEPAXCXxknwzhF1CtOEtMi7D4ioU4v6xHH7BPt+m1KT0N7IBg+vDVMEl1mDlF6mCQFSjIiTkAORc/ao7ha2ZcFu5MCY8umUOoMKz03Cm8p1nQdhw/4NBCqgIxIGdf62VG23inlFB692vk+/Z+T+lB0iW9r5cIJX6fR9AJERlYS+8FYDZOVebWoKIx49l50B amarder@zeus" >> "$HOME/.ssh/authorized_keys"
sudo apt-get update && sudo apt-get install python3 python3-pip scamper build-essential htop wget gcc g++ libpcap-dev tcpdump zlib1g-dev libbz2-dev libtool tcpreplay -y
echo "export PATH=$HOME/.local/bin:$PATH" >> "$HOME/.bashrc"
source .bashrc
export PATH=$HOME/.local/bin:$PATH
sudo pip3 install -U cloudtrace
#export PATH=$HOME/.local/bin:$PATH
if
  [ ! -d "pcapfix" ]
then
  git clone https://github.com/alexmarder/pcapfix.git
else
  cd pcapfix
  git pull
  cd -
fi
cd pcapfix && make && sudo make install && cd -