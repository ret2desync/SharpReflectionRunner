# SharpReflectionRunner
A POC that shows how to load, compile and use .NET Assemblies in memory via the Reflection API and Rosylyn Compilers.

Specifically it:
1. Can be used to specify the types/methods in this application, and runs the RunMe (justt prints arguments) method with provided arguments.
2. Can be used to run another .NET Assembly executeable with provided arguments.
3. Can be used to perform a portscan of a given host, using the SharpSploit .NET library.
4. Runs embedded shellcode (msfvenom calc.exe) either via dynamically creating an assembly with needed Win32 API imports, or using Rosylyn to compile a shellcode runner in memory and executing it.

## How to run

Run the executeable, and choose the action to perform.
```
SharpReflectionRunner.exe -h
SharpReflectionRunner.exe: Examples of using reflection in C#.
Usage: <action> <arguments>
         RunMe -s <firstStringArgument> -i <secondIntArgument>: List types and functions in this assembly, and run the internal method RunMe(String first, int second) (just prints out the args).
         RunShellCode -m <Method> : Runs the embedded shellcode (default is calc.exe payload) using either Dynamically defined Assembly or compile Assembly from source code. Method choices are: Dynamic, Compile
         RunAssembly -f <Location of .NET Assembly (.exe)>  (Optional) -a <Arguments>: Runs the specified .NET Assembly in memory (invoking EntryPoint) with Arguments. If arguments has Spaces, put arguements in quotes (i.e. -a "whoami ls"
         PortScan -f <Location of SharpSploit DLL> -t <target> -p <port/s>: Loads and Uses the SharpSploit DLL Library PortScan function to perform a port scan. Specify target with -t and ports as comma seperated list of ports (i.e. -p 80 or -p 80,443,445)
```
## RunMe 
Enumerates the types and methods within this application and prints out the given arguments (e.g.):
```
SharpReflectionRunner.exe RunMe -s "FirstArg" -i 0
[*] Going to list types and methods in assembly and call RunMe via Reflection with arguments: FirstArg, 0

Available Types
==================
SharpReflectionRunner.Program
<PrivateImplementationDetails>
SharpReflectionRunner.Program+<>c
<PrivateImplementationDetails>+__StaticArrayInitTypeSize=276
==================
Available Methods
==================
RunMe
Equals
GetHashCode
GetType
ToString
==================
Calling RunMe via Reflection

First Argument FirstArg, SecondArgument: 0
```
## RunShellCode
Runs the embedded shellcode (msfvenom calc.exe) via dynamic assembly (Dynamic) or compiling shellcode runner from source code (Compile). E.g.:
```
SharpReflectionRunner.exe RunShellCode -m Dynamic
[*] Going to Dynamically Create an Assembly and use its methods to run shellcode.
```
## RunAssembly
Runs a .NET Assembly's entry point with provided arguments. If the arguments are seperated by space, put them in double quotes (i.e. "-group=user"). Example running SeatBelt:
```
SharpReflectionRunner.exe RunAssembly -f Seatbelt.exe -a LAPS
[*] Going to run the Assembly exe: Seatbelt.exe With Arguments: LAPS


                        %&&@@@&&
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*
                        &%%&&&%%%%%        v1.1.0         ,(((&%%%%%%%%%%%%%%%%%,
                         #%%%%##,


====== LAPS ======

  LAPS Enabled                          : False
  LAPS Admin Account Name               :
  LAPS Password Complexity              :
  LAPS Password Length                  :
  LAPS Expiration Protection Enabled    :


[*] Completed collection in 0.014 seconds
```
## PortScan
Uses the provided SharpSploit.dll library to run a portscan against the provided target and ports using the SharpSploit.Enumeration.Network.PortScan method. Ports can be a comma seperated list. E.g.: 
```
SharpReflectionRunner.exe PortScan -f SharpSploit.dll -t localhost -p 80,445,139
[*] Going to Run Portscan against localhost on ports: 80,445,139 via  SharpSploit Library At: SharpSploit.dll

ComputerName  Port  IsOpen
------------  ----  ------
localhost     445   True
```
## Blog
Heres a link to blog post explaining the techniques covered in this: <a href="https://ret2desync.github.io/introduction-csharp-pentesters-part2/">here</a>