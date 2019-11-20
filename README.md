# Duplication Removement Tool

As a part of the paper, we release a tool for removing sample duplication in Android malware dataset.

*Step 1:* **Install Apktool**

On Windows OS, it is best to add it to your environment variables.

On Linux OS, please specify the path where Apktool is located by parameter -a.

*Step 2:* **python3 main.py [&lt;parameters&gt;]**

-i, --input, help="Your dataset path."

-o, --output, default="output.csv", help="Your destination output file."

-f, --filter, choices=["d", "o", "a"], help="Dex, Opcode sequence, or API call."

-a, --apktool, default="apktool", help="Your ApkTool path."

-t, --tmp, default="TMP", help="Tmp path."

-l, --logging, default="LOG", help="Logging path."


**e.g. python3 main.py -i genomeapps/samples/ -o no_dex_dup.csv -f d -a /usr/local/bin/apktool** 
