/*******************************************
*                                          *
*  Simple APRS Server by milokz@gmail.com  * 
*                                          *
*******************************************/

using System;
using System.Reflection;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace SimpleAPRSserver
{
    class Program
    {        
        static void Main(string[] args)
        {
            Console.WriteLine("********************************************");
            Console.WriteLine("*                                          *");
            Console.WriteLine("*  Simple APRS Server by milokz@gmail.com  *");            
            Console.WriteLine("*                                          *");
            Console.WriteLine("********************************************");
            Console.WriteLine("Version " + APRSServer.GetVersion() + " " + APRSServer.Build);
            Console.WriteLine("");

            APRSServer server = new APRSServer();                        
            server.Start();            
            Console.WriteLine("Type exit to Exit:");
            while (true) if(Console.ReadLine() == "exit") break;
            Console.WriteLine("exiting...");
            server.Stop();
        }
    }
}
