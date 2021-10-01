/*******************************************
*                                          *
*  Simple APRS Server by milokz@gmail.com  * 
*                                          *
*******************************************/

using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Text.RegularExpressions;
using System.IO;
using System.Web;
using System.Xml;
using System.Xml.Serialization;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Reflection;

namespace SimpleAPRSserver
{
    public class APRSServer : SimpleServersPBAuth.ThreadedHttpServer
    {
        public static string Build = "HTTP+AIS";

        public bool OnlyValidPasswordUsers = false;
        public bool PassDataOnlyValidUsers = false;
        public bool PassDataOnlyLoggedUser = false;
        public bool StoreGPSInMemory = false;
        public bool OutConfigToConsole = true;
        public bool OutAPRStoConsole = true;
        public bool OutConnectionsToConsole = true;
        public bool OutBroadcastsMessages = false;
        public bool OutBuddiesCount = false;
        public int StoreGPSMaxTime = 1440; // in sec
        public int HTTPServer = 0; // 80
        public int AISServer = 0; // 1080
        public bool AISBetween = false;
        public bool EnableClientFilter = false;
        public bool PassBackAPRSPackets = false;
        public List<string> banlist = new List<string>();
        // support remote servers ?

        private Mutex lpMutex = new Mutex();
        private List<string> lastPackets = new List<string>(30);
        public string[] LastAPRSPackets
        {
            get
            {
                if (lastPackets.Count == 0) return new string[0];
                lpMutex.WaitOne();
                string[] res = lastPackets.ToArray();
                lpMutex.ReleaseMutex();
                return res;
            }
        }

        private HttpAPRSServer httpServer = null;
        private AISServer aisServer = null;

        internal Mutex aprsMutex = new Mutex();
        internal List<ClientData> aprsClients = new List<ClientData>();

        internal Mutex lastgeoMutex = new Mutex();
        internal Dictionary<string, ClientAPRSFilter.GeoPos> LastPositions = new Dictionary<string, ClientAPRSFilter.GeoPos>();

        internal Mutex budsMutex = new Mutex();
        internal List<APRSData.Buddie> BUDs = new List<APRSData.Buddie>();

        public APRSServer() : base() { InitConfig(); }
        public APRSServer(int Port) : base(Port) { InitConfig(); }
        public APRSServer(IPAddress IP, int Port) : base(IP, Port) { InitConfig(); }
        ~APRSServer() { this.Dispose(); }

        private void InitConfig()
        {
            this.ServerName = "SimpleAPRSserver";
            this.ListenPort = 14580;
            this.ListenIPAllow = new string[0];
            string fName = SimpleServersPBAuth.TTCPServer.GetCurrentDir() + @"\config.xml";
            XmlDocument xd = new XmlDocument();
            xd.Load(fName);
            XmlNodeList nl = xd.SelectSingleNode("config").ChildNodes;
            if ((nl.Count > 0) && OutConfigToConsole) Console.WriteLine("Loading config from `config.xml`...");
            foreach (XmlNode nn in nl)
            {
                string name = nn.Name;
                string val = nn.ChildNodes.Count == 0 ? null : nn.ChildNodes[0].InnerText;
                if (!String.IsNullOrEmpty(val))
                {
                    if (name == "Ban")
                    {
                        banlist.Add(val.ToUpper());
                        if (OutConfigToConsole)
                            Console.WriteLine("  Ban: " + val.ToUpper());
                        continue;
                    };
                    FieldInfo fi = this.GetType().GetField(name);
                    if ((fi != null) && (fi.IsPublic))
                    {
                        if (OutConfigToConsole)
                            Console.WriteLine("  {0}: {1}", name, val);
                        if (fi.FieldType == typeof(int))
                            fi.SetValue(this, int.Parse(val));
                        if (fi.FieldType == typeof(string))
                            fi.SetValue(this, val);
                        if (fi.FieldType == typeof(bool))
                            fi.SetValue(this, val == "1");
                    };
                    if (fi == null)
                        foreach (PropertyInfo prop in this.GetType().GetProperties())
                            if (prop.Name == name)
                            {
                                if (OutConfigToConsole)
                                    Console.WriteLine("  {0}: {1}", name, val);
                                if (prop.PropertyType == typeof(string))
                                    prop.SetValue(this, val, null);
                                if (prop.PropertyType == typeof(int))
                                    prop.SetValue(this, int.Parse(val), null);
                                if (prop.PropertyType == typeof(ushort))
                                    prop.SetValue(this, ushort.Parse(val), null);
                                if (prop.PropertyType == typeof(bool))
                                    prop.SetValue(this, val == "1", null);
                                if (prop.PropertyType == typeof(SimpleServersPBAuth.ThreadedTCPServer.Mode))
                                    prop.SetValue(this, (SimpleServersPBAuth.ThreadedTCPServer.Mode)int.Parse(val), null);
                                if (prop.PropertyType == typeof(string[]))
                                {
                                    List<string> lst = new List<string>((string[])prop.GetValue(this, null));
                                    lst.Add(val);
                                    prop.SetValue(this, lst.ToArray(), null);
                                };
                            };
                };
            };
            if ((nl.Count > 0) && OutConfigToConsole) Console.WriteLine("");

            this.ServerName = this.ServerName.Replace(" ", "_");

            if (HTTPServer > 0)
            {
                httpServer = new HttpAPRSServer(this, HTTPServer);
                httpServer.ServerName = this.ServerName;
                httpServer.AllowBrowseFiles = true;
                httpServer.ListenIPMode = this.ListenIPMode;
                httpServer.ListenIPAllow = this.ListenIPAllow;
                httpServer.ListenIPDeny = this.ListenIPDeny;
                httpServer.ListenMacMode = this.ListenMacMode;
                httpServer.ListenMacAllow = this.ListenMacAllow;
                httpServer.ListenMacDeny = this.ListenMacDeny;
                httpServer.MaxClients = this.MaxClients;
            };

            if (AISServer > 0)
            {
                aisServer = new AISServer(this, AISServer);
                aisServer.ServerName = this.ServerName.ToUpper();
                aisServer.ListenIPMode = this.ListenIPMode;
                aisServer.ListenIPAllow = this.ListenIPAllow;
                aisServer.ListenIPDeny = this.ListenIPDeny;
                aisServer.ListenMacMode = this.ListenMacMode;
                aisServer.ListenMacAllow = this.ListenMacAllow;
                aisServer.ListenMacDeny = this.ListenMacDeny;
                aisServer.MaxClients = this.MaxClients;
            };
        }

        public bool AISRunning { get { return aisServer == null ? false : aisServer.Running; } }
        public ulong AISAlive { get { return aisServer == null ? 0 : aisServer.ClientsAlive; } }
        public ulong AISCounter { get { return aisServer == null ? 0 : aisServer.ClientsCounter; } }
        public string[] AISClients { get { return aisServer == null ? new string[0] : aisServer.GetClients();  } }
        public int AISPort { get { return aisServer == null ? 0 : aisServer.ServerPort; } }

        public override void Start()
        {
            base.Start();
            Console.WriteLine("ServerName: {0}", this.ServerName);
            Console.WriteLine("  APRS Started at: {0}:{1}", this.ServerIP.ToString(), this.ServerPort);
            if (httpServer != null)
            {
                httpServer.Start();
                Console.WriteLine("  HTTP Started at: {0}:{1}", httpServer.ServerIP.ToString(), httpServer.ServerPort);
            };
            if (aisServer != null)
            {
                aisServer.Start();
                Console.WriteLine("  AIS  Started at: {0}:{1}", httpServer.ServerIP.ToString(), aisServer.ServerPort);
            };
            Console.WriteLine();
        }

        public override void Stop()
        {
            base.Stop();
            if (httpServer != null) httpServer.Stop();
            if (aisServer != null) aisServer.Stop();
            httpServer = null;
        }

        // Get Client, threaded
        protected override void GetClient(TcpClient Client, ulong clientID)
        {
            int bRead = -1;
            int posCRLF = -1;
            int receivedBytes = 0;
            string receivedText = "";

            // APRS Server Welcome
            byte[] toSend = System.Text.Encoding.ASCII.GetBytes("# " + ServerName + " v" + GetVersion() + "\r\n");
            Send(Client.GetStream(), toSend);

            //while ((Client.Available > 0) && ((bRead = Client.GetStream().ReadByte()) >= 0)) // doesn't work correct
            while ((bRead = Client.GetStream().ReadByte()) >= 0)
            {
                receivedBytes++;
                receivedText += (char)bRead;

                if ((receivedBytes == 1) && (receivedText != "u")) return;
                if ((receivedBytes == 2) && (receivedText != "us")) return;
                if ((receivedBytes == 3) && (receivedText != "use")) return;
                if ((receivedBytes == 4) && (receivedText != "user")) return;

                if (bRead == 0x0A) posCRLF = receivedText.IndexOf("\n"); // End of single packet
                if (posCRLF >= 0 || receivedText.Length > 2048) { break; }; // BAD CLIENT
            };

            GetAPRSClient(Client, clientID, receivedText);
        }

        // Get APRS client, threaded
        private void GetAPRSClient(TcpClient Client, ulong clientID, string firstPacket)
        {
            string loginstring = firstPacket.Replace("\r", "").Replace("\n", "");
            string res = "# logresp user unverified, server " + ServerName.ToUpper() + " v" + GetVersion();
            string re2 = "";

            Match rm = Regex.Match(loginstring, @"^user\s([\w\-]{3,})\spass\s([\d\-]+)\svers\s([\w\d\-.]+)(?:\s([\w\d\-.\+]+))?");
            if (!rm.Success) return; // not valid

            string callsign = rm.Groups[1].Value.ToUpper();
            if (banlist.Contains(callsign)) return;

            string password = rm.Groups[2].Value;
            string software = "";  
            string version = ""; 
            try { software = rm.Groups[3].Value; } catch { };
            try { version = rm.Groups[4].Value; } catch { };
            string doptext = loginstring.Substring(rm.Groups[0].Value.Length).Trim();

            int psw = -1;
            if (!int.TryParse(password, out psw)) return;

            ClientData cd = new ClientData(Client, clientID);
            cd.user = callsign;
            cd.SoftNam = software;
            cd.SoftVer = version;
            if (cd.user.Contains("-")) cd.user = cd.user.Substring(0, cd.user.IndexOf("-")); // remove SSID

            if (EnableClientFilter && (doptext.IndexOf("filter ") >= 0))
            {
                string fres = cd.SetFilter(doptext.Substring(doptext.IndexOf("filter") + 7), cd.user);
                if(!String.IsNullOrEmpty(fres)) re2 = "# filter '" + fres + "' is active\r\n";
            };

            // check for valid HAM user or for valid OruxPalsServer user
            if ((psw == APRSData.CallsignChecksum(callsign)) || (psw == APRSData.Buddie.Hash(callsign)))
            {
                cd.validated = true;
                res = "# logresp " + callsign + " verified, server " + ServerName + " v" + GetVersion() + "\r\n";
                byte[] ret = Encoding.ASCII.GetBytes(res);
                try { Send(cd.stream, ret); }
                catch { };                
            }
            else
            {
                cd.validated = false;
                res = "# logresp " + callsign + " unverified, server " + ServerName + " v" + GetVersion() + "\r\n";
                byte[] ret = Encoding.ASCII.GetBytes(res);
                try { Send(cd.stream, ret); }
                catch { };
                if (OnlyValidPasswordUsers) return;
            };
            if (re2 != "")
            {
                byte[] ret = Encoding.ASCII.GetBytes(re2);
                try { Send(cd.stream, ret); }
                catch { };
            };

            GetAPRSClient(cd);
        }

        // Get APRS client, threaded
        private void GetAPRSClient(ClientData cd)
        {
            aprsMutex.WaitOne();
            aprsClients.Add(cd);
            aprsMutex.ReleaseMutex();

            if (OutConnectionsToConsole)
                Console.WriteLine("APRS client connected from: {0}:{1} as {2} via {4}, total {3}", ((IPEndPoint)cd.client.Client.RemoteEndPoint).Address.ToString(), ((IPEndPoint)cd.client.Client.RemoteEndPoint).Port, cd.user, aprsClients.Count, cd.SoftNam + " " + cd.SoftVer);

            PassBuds(cd);

            if ((OutBroadcastsMessages) && (BUDs.Count > 0))
                Console.WriteLine("Pass {0} buddies to APRS {1}:{2}", BUDs.Count, ((IPEndPoint)cd.client.Client.RemoteEndPoint).Address.ToString(), ((IPEndPoint)cd.client.Client.RemoteEndPoint).Port);

            int rxCount = 0;
            int rxAvailable = 0;
            byte[] rxBuffer = new byte[65536];
            bool loop = true;
            int rCounter = 0;
            string rxText = "";
            while (loop)
            {
                try { rxAvailable = cd.client.Available; }
                catch { break; };

                // Read Incoming Data
                while (rxAvailable > 0)
                {
                    try { rxAvailable -= (rxCount = cd.stream.Read(rxBuffer, 0, rxBuffer.Length > rxAvailable ? rxAvailable : rxBuffer.Length)); }
                    catch { break; };
                    if (rxCount > 0) rxText += Encoding.ASCII.GetString(rxBuffer, 0, rxCount);
                };

                // Read Packet
                if ((rxText != "") && (rxText.IndexOf("\n") > 0))
                {
                    OnAPRSData(cd, rxText);
                    rxText = "";
                };

                if (!isRunning) loop = false;
                if (rCounter >= 600) // 30s ping
                {
                    try
                    {
                        if (!IsConnected(cd.client)) break;
                        byte[] ping = System.Text.Encoding.ASCII.GetBytes("#ping; server " + ServerName + " v" + GetVersion() + "\r\n");
                        Send(cd.stream, ping);
                        rCounter = 0;
                    }
                    catch { loop = false; };
                };
                System.Threading.Thread.Sleep(50);
                rCounter++;
            };

            aprsMutex.WaitOne();
            for (int i = 0; i < aprsClients.Count; i++)
                if (aprsClients[i].id == cd.id)
                {
                    aprsClients.RemoveAt(i);
                    break;
                };
            aprsMutex.ReleaseMutex();

            if (OutConnectionsToConsole)
                Console.WriteLine("APRS client disconnected from: {0}:{1} as {2}, total {3}", ((IPEndPoint)cd.client.Client.RemoteEndPoint).Address.ToString(), ((IPEndPoint)cd.client.Client.RemoteEndPoint).Port, cd.user, aprsClients.Count);
        }

        // On APRS User Data // they can upload data to server
        private void OnAPRSData(ClientData cd, string line)
        {
            line = line.Trim();
            if (String.IsNullOrEmpty(line)) return;

            if (OutAPRStoConsole)
                Console.WriteLine("APRS from {0}:{1}:: {2}", cd.IP, ((IPEndPoint)cd.client.Client.RemoteEndPoint).Port, line.Replace("\r", "").Replace("\n", ""));

            UpdateLastPackets(line, cd);

            // COMMENT STRING
            if (line.IndexOf("#") == 0)
            {
                string filter = "";
                if (line.IndexOf("filter") > 0) filter = line.Substring(line.IndexOf("filter"));
                // filter ... active
                if (EnableClientFilter &&  (filter != ""))
                {
                    string fres = cd.SetFilter(filter.Substring(7), cd.user);
                    string resp = "# filter '" + fres + "' is active\r\n";
                    byte[] bts = Encoding.ASCII.GetBytes(resp);
                    try { Send(cd.stream, bts); }
                    catch { }
                };
                return;
            };

            // Ping Packet
            if (line.IndexOf(">online") > 0) return;

            // if no pass any incoming data from user with bad password
            if (PassDataOnlyValidUsers && (!cd.validated)) return;

            // Broadcast to APRS
            bool broadcasted = false;
            // Broadcast packets only if packet sender is a logged aprs user,
            if (PassDataOnlyLoggedUser)
            {
                if (line.StartsWith(cd.user + ">") || line.StartsWith(cd.user + "-"))
                {
                    broadcasted = true;
                    BroadcastAPRS(line, cd, (long)cd.id);
                };
            }
            else
            {
                broadcasted = true;
                BroadcastAPRS(line, cd, (long)cd.id);
            };

            // if Not Broadcasted -> No Store
            if (!broadcasted) return;

            // PARSE NORMAL PACKET
            cd.lastBuddie = null;
            try 
            { 
                cd.lastBuddie = APRSData.ParseAPRSPacket(line);
                cd.lastBuddie.Verified = cd.validated;
                cd.lastBuddie.Owner = cd.user == cd.lastBuddie.name;
            }
            catch { };                        

            if (cd.lastBuddie == null) return; // Bad Data              
            if ((!cd.validated) && (!cd.lastBuddie.PositionIsValid)) return; // No pass nonGPS data from not validated users            

            // Update Buddies (Last User Info)
            UpdateBUDs(cd.lastBuddie);

            // Broadcast GEO
            if (cd.lastBuddie.PositionIsValid)
            {
                // Update stored positions
                UpdateLastPos(cd.lastBuddie);

                // Broadcast to AIS
                BroadcastAIS(cd.lastBuddie);

                // Broadcast to HTTP            
                BroadcastHTTP(cd.lastBuddie);
            };
        }

        private void UpdateLastPackets(string packet, ClientData cd)
        {
            lpMutex.WaitOne();
            if (lastPackets.Count == 30) lastPackets.RemoveAt(29);
            lastPackets.Insert(0,String.Format("<b>{1:yyyy-MM-dd HH:mm:ss} UTC</b>: {0} <i>from</i> <b>{4} - {2}:{3}</b>", packet, DateTime.UtcNow, cd.IP, cd.Port, cd.user));
            lpMutex.ReleaseMutex();
        }

        private void UpdateLastPos(APRSData.Buddie bud)
        {
            lastgeoMutex.WaitOne();
            if (LastPositions.ContainsKey(bud.name))
            {
                LastPositions[bud.name].lon = bud.lat;
                LastPositions[bud.name].lon = bud.lon;
            }
            else
                LastPositions.Add(bud.name, new ClientAPRSFilter.GeoPos(bud.lat, bud.lon));
            lastgeoMutex.ReleaseMutex();
        }

        // Update Memory
        private void UpdateBUDs(APRSData.Buddie bud)
        {
            if (!StoreGPSInMemory) return;

            int rmvd = 0;
            budsMutex.WaitOne();
            bool ex = false;
            if (BUDs.Count > 0)
                for (int i = BUDs.Count - 1; i >= 0; i--)
                {
                    double ttlm = DateTime.UtcNow.Subtract(BUDs[i].last).TotalMinutes;
                    if (ttlm >= StoreGPSMaxTime)
                    {
                        rmvd++;
                        BUDs.RemoveAt(i);
                        continue;
                    };
                    if (BUDs[i].name == bud.name)
                    {
                        ex = true;
                        BUDs[i].FillFrom(bud);
                        break;
                    };
                };
            if ((rmvd > 0) && (OutBuddiesCount))
                Console.WriteLine("Removed {0} buddies, total {1}", rmvd, BUDs.Count);
            if (!ex)
            {
                BUDs.Add(bud);
                if (OutBuddiesCount)
                    Console.WriteLine("Added 1 buddies, total {0}", BUDs.Count);
            };
            budsMutex.ReleaseMutex();
        }

        // Send Buddies to client
        private void PassBuds(ClientData cd)
        {
            if (!StoreGPSInMemory) return;
            ClearBuds();

            budsMutex.WaitOne();
            if (BUDs.Count > 0)
                for (int i = 0; i < BUDs.Count; i++)
                {
                    BUDs[i].SetAPRSWithDate();
                    lastgeoMutex.WaitOne();
                    bool pass = !EnableClientFilter ? true : cd.PassFilter(BUDs[i].APRS, BUDs[i], LastPositions);
                    lastgeoMutex.ReleaseMutex();
                    if (pass) try { Send(cd.stream, BUDs[i].APRSData); }
                        catch { };
                };
            budsMutex.ReleaseMutex();
        }

        // Clear Old Buddies
        internal void ClearBuds()
        {
            int rmvd = 0;
            budsMutex.WaitOne();
            if (BUDs.Count > 0)
                for (int i = BUDs.Count - 1; i >= 0; i--)
                    if (DateTime.UtcNow.Subtract(BUDs[i].last).TotalMinutes >= StoreGPSMaxTime)
                    {
                        BUDs.RemoveAt(i);
                        rmvd++;
                    };
            if ((rmvd > 0) && (OutBuddiesCount))
                Console.WriteLine("Removed {0} buddies, total {1}", rmvd, BUDs.Count);
            budsMutex.ReleaseMutex();
        }

        private string PlaceQAConstruct(string message, ClientData cReq)
        {
            string csign, rt, pckt;
            if (APRSData.ParseAPRSRoute(message, out csign, out rt, out pckt))
            {
                rt = (new Regex(@"qA\w,?", RegexOptions.None)).Replace(rt, "").Trim(new char[] { ',' });
                string qAdd = "";
                if (cReq.validated && (cReq.user == csign)) qAdd = "qAC";
                if ((!cReq.validated) && (cReq.user == csign)) qAdd = "qAX";
                if (cReq.validated && (cReq.user != csign)) qAdd = "qAO";
                if ((!cReq.validated) && (cReq.user != csign)) qAdd = "qAo";
                message = csign + ">";
                if (qAdd != "")
                {
                    int pos = Math.Max(rt.IndexOf("APRS"), rt.IndexOf("PIP*"));
                    if (pos >= 0)
                        message += rt.Insert(pos + 4, "," + qAdd);
                    else
                        message += qAdd + (rt.Length > 0 ? "," : "") + rt;
                };
                message += ":" + pckt;
            };
            return message;
        }

        //  Send message to all aprs clients
        public void BroadcastAPRS(string message, ClientData cReq)
        {
            BroadcastAPRS(message, cReq, -1);
        }

        //  Send message to all aprs clients
        public void BroadcastAPRS(string message, ClientData cReq, long instedOf)
        {
            // place qA construct
            message = PlaceQAConstruct(message, cReq);
            string tosend = message.EndsWith("\n") ? message : message + "\r\n";
            byte[] msg = System.Text.Encoding.ASCII.GetBytes(tosend);

            aprsMutex.WaitOne();
            if (aprsClients.Count > 0)
            {
                if (OutBroadcastsMessages)
                    Console.WriteLine("Broadcast APRS: {0}", tosend.Replace("\r", "").Replace("\n", ""));
                for (int i = 0; i < aprsClients.Count; i++)
                {
                    if (!PassBackAPRSPackets)
                        if (instedOf != -1)
                            if (aprsClients[i].id == (ulong)instedOf)
                                continue;
                    lastgeoMutex.WaitOne();
                    bool pass = !EnableClientFilter ? true : aprsClients[i].PassFilter(message, cReq.lastBuddie, LastPositions);
                    lastgeoMutex.ReleaseMutex();
                    if (pass) try { Send(aprsClients[i].stream, msg); }
                        catch { };
                };
            };
            aprsMutex.ReleaseMutex();
        }

        //  Send message to all WebSocket clients
        public void BroadcastHTTP(APRSData.Buddie bud)
        {
            if (httpServer == null) return;
            httpServer.Broadcast(bud);
        }

        public void BroadcastAIS(APRSData.Buddie bud)
        {
            if (aisServer == null) return;
            aisServer.Broadcast(bud);
        }

        // Write to Net Stream
        private static void Send(Stream stream, byte[] data)
        {
            stream.Write(data, 0, data.Length);
            stream.Flush();
        }

        // Get Server Version
        public static string GetVersion()
        {
            System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
            System.Diagnostics.FileVersionInfo fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(assembly.Location);
            return fvi.FileVersion;
        }
    }        
}
