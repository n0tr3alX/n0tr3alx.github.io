# Cobalt Strike shellcode and config extraction



### Overview 

[Cobalt Strike](https://www.cobaltstrike.com/) is a commercial red team and adversary simulation tool. It is widely used by security professionals to assess the security of networks and systems by simulating advanced persistent threats (APTs). As everything, due to its powerful capabilities, it has also been misused by cybercriminals and threat actors.

<!--more-->

### Analysis

No suspicious entropy

<img src="/static/CobaltStrike/Pasted_image_20250303171709.png" alt="drawing" width="700"/>

Only two imports

<img src="/static/CobaltStrike/Pasted_image_20250303171943.png" alt="drawing" width="700"/>

Virtual alloc import

<img src="/static/CobaltStrike/Pasted_image_20250303171819.png" alt="drawing" width="700"/>

Bp VirtualAlloc


After stop at the break point use the option exec till return

<img src="/static/CobaltStrike/exec_return.png" alt="drawing" width="700"/>

in rax we can see the memory location that is being allocated

<img src="/static/CobaltStrike/memory_allocation.png" alt="drawing" width="700"/>

Fallowing in dump the address

<img src="/static/CobaltStrike/Pasted_image_20250303174504.png" alt="drawing" width="600"/>

and it is empty for now.....

<img src="/static/CobaltStrike/Pasted_image_20250303174442.png" alt="drawing" width="600"/>


Lets monitor any content that will be written to this address using a hardware access breaking point in the firts byte of the dump

<img src="/static/CobaltStrike/Pasted_image_20250303174630.png" alt="drawing" width="600"/>

After resuming the execution we can see in dump 1 the first change in the allocated memory, 

![Pasted_image_20250303174846.png]<img src="/static/CobaltStrike/Pasted_image_20250303174846.png" alt="drawing" width="600"/>

In the instructions we can see that we are in a loop (For the shellcode by written in memory), lets add a break point where the jge points to

<img src="/static/CobaltStrike/Pasted_image_20250303175118.png" alt="drawing" width="600"/>

dump 1 we can see that now we have a lot of stuff writen in the allocked space

<img src="/static/CobaltStrike/shellcode_start.png" alt="drawing" width="600"/>

<img src="/static/CobaltStrike/Pasted_image_20250303175311.png" alt="drawing" width="600"/>

<img src="/static/CobaltStrike/Pasted_image_20250303175324.png" alt="drawing" width="600"/>

righ clicking in the content of the dump we can use the disassembly function and see that the content became valid assembly instructions

<img src="/static/CobaltStrike/Pasted_image_20250303172738.png" alt="drawing" width="600"/>

<img src="/static/CobaltStrike/Pasted_image_20250303172911.png" alt="drawing" width="600"/>



To extract the shellcode

Righ clicking again in the content of the dump and use "Follow in Memory Map"

<img src="/static/CobaltStrike/Pasted_image_20250303172952.png" alt="drawing" width="600"/>

<img src="/static/CobaltStrike/dump_memory.png" alt="drawing" width="600"/>

<img src="/static/CobaltStrike/emulation.png" alt="drawing" width="600"/>

AND.....The ip dont respond to any connections anymore so no more stages = no connfig extraction for this sample, but lets analysis a stageless cobalt strike artifcat, intead of using a shellcode to download and execute the next stage this sample execute has the beacon and execute in memory in another thread

The process is the same, so just extract the binary after bein allocated in memory lets dump to a file

<img src="/static/CobaltStrike/Pasted_image_20250303185708.png" alt="drawing" width="600"/>

After that lets use the tool https://github.com/Sentinel-One/CobaltStrikeParser created by sentinel One team to extract the configs!

<img src="/static/CobaltStrike/Pasted_image_20250303190001.png" alt="drawing" width="600"/>

