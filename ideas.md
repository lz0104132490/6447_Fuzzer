For this project you will be required to implement a black box fuzzer, that given a binary containing a single vulnerability and a file containing one valid input to the binary, will need to find a valid input that causes an incorrect program state to occur (crash, invalid memory write, heap UAF, etc).

- we are implementing a blackbox fuzzer, given a binary and a valid sample input, we first detect the sample input format, and use corresponding mutation handler specific to that input format.

- we need to implement afl style fork server, 

- mutation strategy refer to /rad folder which is the core logic of project radamsa


All binaries will read in from stdin.

The main goal of your fuzzer should be to touch as many codepaths as possible within the binary by either mutating the supplied valid input or generating completely new input (empty files, null bytes, really big files, etc).

You are permitted to do anything you wish (other than using other fuzzers) to achieve the following functionality.

See Fuzzer Setup page for details on submission expectations, and how we will setup and run your fuzzer.

 

Assumptions
You can assume these facts when developing your fuzzer.

All binaries will have a vulnerability.
All binaries will also have an associated textfile that can be used as example input into the binary. This input will make the program function normally (return 0, not crash, no errors).
All binaries will expect input in one of the following formats:
Plaintext (multiline)
JSON
XML
CSV
JPEG
ELF
PDF
The input textfile provided will be a valid form of one of these text formats.
Your fuzzer will have a maximum of 60 seconds per binary to find a vulnerability.
Your fuzzer will need to find all the possible bad files within this time range.
If there are 10 files, you fuzzer has 600 seconds to run. We expect you to deal with this.
All binaries will be 64-bit Linux ELF’s.
All vulnerabilities will result in memory corruption.
 

 What will the files be named / can we guess the input type based on filenames.
No you can’t make assumptions based on filenames.
What language / libraries can I use to write my fuzzer?
You can use C.
The bulk of the fuzzing logic must be written by you. However, you can use libraries to assist with encoding data into different formats (json, xml, etc), as well as running/debugging binaries.
Does an abort() count as a crash?
No, an abort() is called by the program’s code to early exit when it detects weird state, and is useless when trying to exploit a program. Examples of this include, a program aborting on invalid JSON format.

Harness Functionality (10 marks)
[2] Detecting the type of crash
[2] Detecting Code Coverage
[2] Avoiding overheads
Not creating files
In memory resetting (Not calling execve)
[2] Useful logging / statistics collection and display
[2] Detecting Hangs / Infinite loops
Detecting infinite loop (code coverage) vs slow running program (timeout approach)