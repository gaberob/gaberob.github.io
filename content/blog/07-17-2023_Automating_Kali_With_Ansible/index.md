---
title: "Automating Kali Configuration With Ansible"
date: 2023-07-17
tags: ["Homelab","Security","Automation"]
description: "How I started automating configuration of new kali deployments."
draft: false
type: page
---

# Automating the configuration of new Kali VM's

As I frequently use virtual machines, specifically Kali Linux, for various capture the flags and courses, it is always a hassle to reinstall on a new computer, or if something breaks. I have had a bit of experience with `ansible` in the past, and have talked with people who have made their own scripts to automate configuring new installations but never got around to doing it myself.

Security youtuber Ippsec released [this](https://www.youtube.com/playlist?list=PLidcsTyj9JXJVIFqyHBHzrRYKPpZYFjM8), series of videos in which he automated the configuration of a fresh install of his Parrot VM. I decided that this would be a great opportunity to fork the repository and configure it to my needs. Ippsec's videos are a much better source of truth for what is going on here than I am. This is just a high-level summary and some use-cases, as well as my changes. 

## What the playbook does

The ansible playbook leverages 4 main roles:

- configure-logging
- configure-tmux
- configure-browser
- customize-terminal
- install-tools

The idea is to have to do as little manual work as possible and have the tools and settings I need to be successful.

### configure-logging

This role is one that I left largely unchanged. It turns on logging to detect incoming connections, via UFW.  This will add logs that we can query via rsylog.

The logs for incoming connections are prefixed via `[UFW-SYN-LOG]` and can be queried via `sudo cat rsyslog | grep -i UFW-SYN-LOG`.

It also configures `auditd` rules, based on [these](https://github.com/gaberob/kali-ansible/blob/master/roles/configure-logging/files/audit.rules). We can look through `audit.log` for these. We can use `aureport` and `ausearch` to search through these. `ausearch -sv no`.

Laurel, is a plugin that gives us the ability to more easily search through these logs.

Logs are output in `/var/log/laurel` in `audit.log` in json. We can use something like `gron` and `jq` to parse through them now.

Find events that were denied: 

`cat /var/log/laurel/audit.log | grep 'success":"no' | jq . | less `

Find other events ran by that same parent process:
 
`cat /var/log/laurel/audit.log | grep 'ppid":<ppid>' | jq . | less`

`ausearch -pp <ppid>`

Other examples:

`ps -ef | grep python`

`ausearch -p <pid>`

### configure-tmux

This task is pretty self explanatory. It installs tmux and copies `.tmux.conf` to the user's home folder.

### customize-browser

This task configures Firefox to proxy https traffic via burpsuite and installs some useful extensions like FoxyProxy, DarkReader, and Wappalyzer.

### customize-terminal

This copies my zsh config into the user's home folder, my .vimrc into the users home folder, and uses dconf to import gnome-shell keybindings.

The `gnome-shell` task that is included in the main task here can be commented out if not using a gnome install, this is just what I prefer.

### install-tools

This installs a pretty robust set of missing tools from apt, cargo, gem, go, pipx, and github.

My additions here are breaking out a task specifically for go packages and adding a task for cargo packes for stuff written in rust.

These tasks are designed where each package delivery system are separated out and can be modified as needed. Suppose a new binary from github, or even a whole repository becomes a standard part of your workflow, it just needs to be added.


You can use my playbook [here](https://github.com/gaberob/kali-ansible), like I said earlier, my desktop enviroment of choice is gnome so it has some gnome specific tasks that can easily be removed. Add or remove tools specific to your needs and you should be good to go!
