/*******************************************
*                                          *
*   Simple AIS Server by milokz@gmail.com  * 
*                                          *
*******************************************/

using System;
using System.IO;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;

namespace SimpleAPRSserver
{
    public class AISServer : SimpleServersPBAuth.ThreadedTCPServer
    {
        private APRSServer aprsServer = null;
        public string ServerName = "SimpleAISServer";

        public AISServer(APRSServer aprsServer) : base() { this.aprsServer = aprsServer; }
        public AISServer(APRSServer aprsServer, int Port) : base(Port) { this.aprsServer = aprsServer; }
        public AISServer(APRSServer aprsServer, IPAddress IP, int Port) : base(IP, Port) { this.aprsServer = aprsServer; }
        ~AISServer() { this.Dispose(); }

        private Mutex acMutex = new Mutex();
        private Dictionary<ulong, TcpClient> aisClients = new Dictionary<ulong, TcpClient>();

        protected override void GetClient(TcpClient Client, ulong clientID)
        {
            try { GetAISClientConnected(Client, clientID); }
            catch { };

            int rCounter = 0;
            bool loop = true;
            while (loop)
            {
                try
                {
                    string line = "";
                    int bRead = -1;
                    int posCRLF = -1;
                    int receivedBytes = 0;

                    if (Client.Available > 0)
                        while (((bRead = Client.GetStream().ReadByte()) >= 0)) // doesn't work correct
                        {
                            receivedBytes++;
                            line += (char)bRead; // standard symbol

                            if ((receivedBytes == 1) && (line != "!")) { line = ""; break; };
                            if ((receivedBytes == 2) && (line != "!A")) { line = ""; break; };
                            if ((receivedBytes == 3) && (line != "!AI")) { line = ""; break; };
                            if ((receivedBytes == 4) && (line != "!AIV")) { line = ""; break; };
                            if ((receivedBytes == 5) && (line != "!AIVD")) { line = ""; break; };

                            if (bRead == 0x0A) posCRLF = line.IndexOf("\n");
                            if (posCRLF >= 0 || line.Length > 1024) { break; };
                        };
                    if (!String.IsNullOrEmpty(line))
                        GetAISClientData(Client, clientID, line.Trim());
                }
                catch { };

                if (!isRunning) loop = false;

                if (rCounter >= 600) // 30s ping
                {
                    try
                    {
                        if (!IsConnected(Client)) break;
                        SafetyRelatedBroadcastMessage sbm = new SafetyRelatedBroadcastMessage("#PING, " + ServerName.ToUpper() + " " + APRSServer.GetVersion().ToUpper());
                        string frm = sbm.ToPacketFrame() + "\r\n";
                        byte[] ret = Encoding.ASCII.GetBytes(frm);
                        Client.GetStream().Write(ret, 0, ret.Length);
                        Client.GetStream().Flush();
                        rCounter = 0;
                    }
                    catch { loop = false; };
                };
                System.Threading.Thread.Sleep(50);
                rCounter++;
            };

            try { GetAISClientDisconnected(Client, clientID); }
            catch { };
        }

        protected virtual void GetAISClientConnected(TcpClient Client, ulong clientID)
        {
            acMutex.WaitOne();
            aisClients.Add(clientID, Client);
            acMutex.ReleaseMutex();

            SafetyRelatedBroadcastMessage sbm = new SafetyRelatedBroadcastMessage("#WELCOME TO " + ServerName.ToUpper() + " " + APRSServer.GetVersion().ToUpper());
            string frm = sbm.ToPacketFrame() + "\r\n";
            byte[] ret = Encoding.ASCII.GetBytes(frm);
            Client.GetStream().Write(ret, 0, ret.Length);
            Client.GetStream().Flush();

            PassBuds(Client);
        }

        protected virtual void GetAISClientDisconnected(TcpClient Client, ulong clientID)
        {
            acMutex.WaitOne();
            aisClients.Remove(clientID);
            acMutex.ReleaseMutex();
        }

        protected virtual void GetAISClientData(TcpClient Client, ulong clientID, string line)
        {
            AISTransCoder.AISPacket pRec = AISTransCoder.AISPacket.FromPacketFrame(line);
            if (!pRec.Valid)
                return;
            else
                if ((pRec.SafetyMessage != null) && (!String.IsNullOrEmpty(pRec.SafetyMessage.Message)) && (pRec.SafetyMessage.Message.StartsWith("#"))) 
                    return;

            // Broadcast
            if(aprsServer.AISBetween)
                Broadcast(line, clientID);
        }

        protected virtual void Broadcast(string message)
        {
            Broadcast(message, ulong.MaxValue);
        }

        protected virtual void Broadcast(string message, ulong instedOf)
        {
            string toSend = message;
            if (!toSend.EndsWith("\n")) toSend += "\r\n";
            byte[] packet = System.Text.Encoding.ASCII.GetBytes(toSend);

            acMutex.WaitOne();
            foreach (ulong key in aisClients.Keys)
            {
                if (key == instedOf) continue;
                try
                {
                    aisClients[key].GetStream().Write(packet, 0, packet.Length);
                    aisClients[key].GetStream().Flush();
                }
                catch { };
            };
            acMutex.ReleaseMutex();
        }

        public void Broadcast(APRSData.Buddie bud)
        {
            PositionReportClassA a = PositionReportClassA.FromBuddie(bud);
            string ln1 = "!AIVDM,1,1,,A," + a.ToString() + ",0";
            PositionReportClassAExt ae = PositionReportClassAExt.FromBuddie(bud);
            string frm = a.ToPacketFrame() + "\r\n" + ae.ToPacketFrame() + "\r\n";
            Broadcast(frm);
        }

        // Send Buddies to client
        private void PassBuds(TcpClient Client)
        {
            if (!aprsServer.StoreGPSInMemory) return;
            aprsServer.ClearBuds();

            aprsServer.budsMutex.WaitOne();
            if (aprsServer.BUDs.Count > 0)
                for (int i = 0; i < aprsServer.BUDs.Count; i++)
                {
                    PositionReportClassB a = PositionReportClassB.FromBuddie(aprsServer.BUDs[i]);
                    string frm = a.ToPacketFrame() + "\r\n";
                    byte[] toSend = System.Text.Encoding.ASCII.GetBytes(frm);
                    try
                    {
                        Client.GetStream().Write(toSend, 0, toSend.Length);
                        Client.GetStream().Flush();
                    }
                    catch { };
                };
            aprsServer.budsMutex.ReleaseMutex();
        }

        // Get Connected Clients
        public string[] GetClients()
        {
            List<string> res = new List<string>();
            acMutex.WaitOne();
            foreach(ulong Key in aisClients.Keys)
            {
                IPEndPoint ipp = (IPEndPoint)aisClients[Key].Client.RemoteEndPoint;
                res.Add(ipp.Address.ToString() + ":" + ipp.Port.ToString());
            };
            acMutex.ReleaseMutex();
            return res.ToArray();
        }
    }

}
