#!/bin/bash
sudo apt-get update && sudo apt-get install python3 python3-pip scamper -y
echo 'export PATH=$HOME/.local/bin:$PATH' >> $HOME/.bashrc
pip3 install -U cloudtrace
source .bashrc
export PATH=$HOME/.local/bin:$PATH
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCY1NDvUHj12s6KrU5UQdgL4LmsZEzedRWNwo0EpBHqWr9NO6nZu18wXQ8b0aKHglR4/EHYs8xUZwe5KWX6UCGPfZoczg3mx9Cr5Q7yLaIwzv0ZpeM0fjV2OZgqfvSqZ+NKiz7KhKBowPsKyNyLEAUT3rEPAXCXxknwzhF1CtOEtMi7D4ioU4v6xHH7BPt+m1KT0N7IBg+vDVMEl1mDlF6mCQFSjIiTkAORc/ao7ha2ZcFu5MCY8umUOoMKz03Cm8p1nQdhw/4NBCqgIxIGdf62VG23inlFB692vk+/Z+T+lB0iW9r5cIJX6fR9AJERlYS+8FYDZOVebWoKIx49l50B amarder@zeus" >> "/home/amarder/.ssh/authorized_keys"
