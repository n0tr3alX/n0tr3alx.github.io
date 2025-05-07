# Zero2Auto: Custom Sample


### Overview

This is an analysis of a custom sample from Zero2Auto, my objective was to develop a script that automates the decryption process for the first stage of the malware. After that, I dive into a more in-depth analysis of its behavior and structure. Hope you enjoy the process and find it insightful!

<img src="/static/Zero2auto/Pasted image 20250507173734.png" alt="drawing" width="1000"/>

### The Case
> During an ongoing investigation, one of our IR team members managed to locate an unknown sample on an infected machine belonging to one of our clients. We cannot pass that sample onto you currently as we are still analyzing it to determine what data was exfilatrated. However, one of our backend analysts developed a YARA rule based on the malware packer, and we were able to locate a similar binary that seemed to be an earlier version of the sample we're dealing with. Would you be able to take a look at it? We're all hands on deck here, dealing with this situation, and so we are unable to take a look at it ourselves.
We're not too sure how much the binary has changed, though developing some automation tools might be a good idea, in case the threat actors behind it start utilizing something like Cutwail to push their samples.

### Analysis

To start, let's take a look at the sample in DiE. All sections appear normal, except .rsrc, which has very high entropy.

<img src="/static/Zero2auto/Pasted image 20250427094242.png" alt="drawing" width="700"/>

Looking at the imports, we only see kernel32.dll and a few suspicious functions

<img src="/static/Zero2auto/Pasted image 20250427094316.png" alt="drawing" width="700"/>

This raises suspicion that functions may be imported dynamically using LoadLibrary and GetProcAddress. Let’s jump to IDA Pro for a closer look.

<img src="/static/Zero2auto/main_dec.png" alt="drawing" width="700"/>

First, we see strange strings being pushed before calling sub_401300. After that, LoadLibrary and GetProcAddress are called. This suggests dynamic API resolution after decrypting the function names. Let’s analyze sub_401300.

The function implements ROT-13, shifting each character by **13** positions in a fixed alphabet:

<img src="/static/Zero2auto/Pasted image 20250427101829.png" alt="drawing" width="700"/>

With that in mind, here are the decoded strings observed during execution:

| Before             | After              |
| ------------------ | ------------------ |
| .5ea5/QPY4//       | kernel32.dll       |
| yb14E5fbhe35       | LoadResource       |
| F5gG8e514pbag5kg   | SetThreadContext   |
| pe51g5Ceb35ffn     | CreateProcessA     |
| I9egh1/n//b3rk     | VirtualAllocEx     |
| E5fh=5G8e514       | ResumeThread       |
| t5gG8e514pbag5kg   | GetThreadContext   |
| Je9g5Ceb35ffz5=bel | WriteProcessMemory |
| I9egh1/n//b3       | VirtualAlloc       |
| E514Ceb35ffz5=bel  | ReadProcessMemory  |
| F9m5b6E5fbhe35     | SizeofResource     |
| s9a4E5fbhe35n      | FindResourceA      |
| yb3.E5fbhe35       | LockResource       |


There’s a lot happening in each function, so to summarize:

This sample creates a suspended copy of itself using CreateProcessA with the 4th parameter set to 0x00000004. This is confirmed via debugging.

<img src="/static/Zero2auto/Pasted image 20250427112501.png" alt="drawing" width="700"/>

<img src="/static/Zero2auto/Pasted image 20250427112517.png" alt="drawing" width="700"/>

Next, it locates the .rsrc section (with high entropy) and loads it.

<img src="/static/Zero2auto/Pasted image 20250427104515.png" alt="drawing" width="1000"/>

Then it retrieves the size using SizeofResource, which is 0x0001541C.

<img src="/static/Zero2auto/Pasted image 20250427104707.png" alt="drawing" width="1000"/>

It then calls VirtualAlloc, but with size 0x00015400

<img src="/static/Zero2auto/Pasted image 20250503125041.png" alt="drawing" width="700"/>

This is slightly suspicious, and with the next piece of code, everything starts to make sense:

<img src="/static/Zero2auto/Pasted image 20250427111607.png" alt="drawing" width="700"/>

Its a RC4 decryption routine, so what is probably happen is that it is considering only the content of .rsrc after 0x1C bytes from the start and maybe before that is the key for decryption

<img src="/static/Zero2auto/Pasted image 20250503134553.png" alt="drawing" width="700"/>

Let's debug until we find something related to the decryption key in the routine, and... there it is! The key is kkd5YdPM24VBXmi, and it's located right before the encrypted content. Nice!

<img src="/static/Zero2auto/Pasted image 20250427104908.png" alt="drawing" width="700"/>

Using CyberChef, we can decrypt the .rsrc content after the key to reveal a second executable:

<img src="/static/Zero2auto/Pasted image 20250427110735.png" alt="drawing" width="700"/>

Using this knowledge, I created a Python script to automate the decryption of the embedded executable: https://github.com/n0tr3alX/Zero2Auto-Custom-Sample

let’s continue the analysis. Once again one value caught my attention: 0xEDB88320 a well-known constant from the CRC-32 hashing algorithm, indicating API hashing is being used.

<img src="/static/Zero2auto/Pasted image 20250429205405.png" alt="drawing" width="700"/>

And looking a bit further it is possible prove this theory, a classic routine of load library, a loop to check the hash of each import, and then GetProcAddress to get the function addresses.

<img src="/static/Zero2auto/Pasted image 20250429205135.png" alt="drawing" width="700"/>

To speed things up, I used [hash db](https://github.com/OALabs/hashdb-ida) to look up the CRC-32 hashes.

<img src="/static/Zero2auto/Pasted image 20250504143935.png" alt="drawing" width="700"/>

<img src="/static/Zero2auto/Pasted image 20250504144245.png" alt="drawing" width="700"/>

So lets take a look again in the main function again, it checks whether the filename is svchost.exe. If not, it executes anti-analysis and anti-debugging routines using IsDebuggerPresent, CreateToolhelp32Snapshot, Process32FirstW, and Process32NextW, looking for x32dbg.exe (easily bypassed by renaming it).

<img src="/static/Zero2auto/Pasted image 20250504144405.png" alt="drawing" width="700"/>

<img src="/static/Zero2auto/Pasted image 20250429215748.png" alt="drawing" width="700"/>

But both of then have the same core functions:

<img src="/static/Zero2auto/Pasted image 20250429215748.png" alt="drawing" width="700"/>

It first resolves some Windows APIs that will connect to a URL and then retrieve its content using InternetReadFile. After that, a value located at xmmword_413C7C and xmmword_413C8C is processed: each character is shifted four positions to the left (using ROL1), then XORed with 0xC5.

<img src="/static/Zero2auto/url.png" alt="drawing" width="700"/>

So lets use cyberchef to do it!

<img src="/static/Zero2auto/Pasted image 20250505193553.png" alt="drawing" width="700"/>

And we have a pastebin URL, that contains another URL.

<img src="/static/Zero2auto/Pasted image 20250503180255.png" alt="drawing" width="700"/>

<img src="/static/Zero2auto/Pasted image 20250503180245.png" alt="drawing" width="700"/>

This URL is passed to a function that appears to retrieve the content from it. (Note that cruloader is set as the user agent.)

<img src="/static/Zero2auto/Pasted image 20250505194140.png" alt="drawing" width="700"/>

<img src="/static/Zero2auto/Pasted image 20250429220013.png" alt="drawing" width="700"/>

So the result of this function is the URL inside the Pastebin. Moving on with the execution, we again have the same call to the function that retrieves the content of the URL, now using the URL that points to the PNG file

<img src="/static/Zero2auto/Pasted image 20250505194930.png" alt="drawing" width="700"/>

After that, it creates a directory and a file in the user's temp folder, and the PNG file is written to disk.

<img src="/static/Zero2auto/Pasted image 20250503175515.png" alt="drawing" width="700"/>

<img src="/static/Zero2auto/Pasted image 20250505200411.png" alt="drawing" width="700"/>

Then it starts doing something really interesting: it searches for the string redaolurc (which is cruloader reversed) within the content of the PNG, likely to locate a specific region of the file.

<img src="/static/Zero2auto/Pasted image 20250505200823.png" alt="drawing" width="700"/>

<img src="/static/Zero2auto/Pasted image 20250503181442.png" alt="drawing" width="700"/>

Right after that, it jumps 9 bytes (to skip the cruloader string) and starts performing a XOR operation with 0x61

<img src="/static/Zero2auto/Pasted image 20250505201511.png" alt="drawing" width="700"/>

So let's do this in CyberChef... and there it is, the final binary!

<img src="/static/Zero2auto/Pasted image 20250503182732.png" alt="drawing" width="700"/>

After this, it performs a classic process hollowing technique on a suspended svchost.exe.

<img src="/static/Zero2auto/Pasted image 20250503200705.png" alt="drawing" width="700"/>

<img src="/static/Zero2auto/Pasted image 20250505204004.png" alt="drawing" width="700"/>

<img src="/static/Zero2auto/Pasted image 20250505203923.png" alt="drawing" width="700"/>

Executing the final binary.....

<img src="/static/Zero2auto/Pasted image 20250505204113.png" alt="drawing" width="700"/>

### Concluding Thoughts

Zero2Auto is an amazing course, and each chapter is really rich in knowledge. Hopefully, this can teach something new!

Thank you for taking the time to read this analysis! If you have any questions, insights, or suggestions, feel free to reach out.
