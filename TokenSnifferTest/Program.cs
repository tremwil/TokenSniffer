using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TokenSniffer;
using System.Diagnostics;

namespace TokenSnifferTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch w = new Stopwatch();
            w.Start();
            string t = TokenSniffer.TokenSniffer.RetrieveToken(true);
            w.Stop();
            Console.WriteLine($"Token: {t}");
            Console.WriteLine($"Time elapsed (ms): {w.ElapsedMilliseconds}");
            Console.ReadKey();
        }
    }
}
