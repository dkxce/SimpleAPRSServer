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
    public class ClientData
    {
        public TcpClient client;
        public DateTime connected;
        public ulong id;
        public Stream stream;
        public string SoftNam = "";
        public string SoftVer = "";

        public string user = "UNKNOWN";
        public bool validated;

        public ClientAPRSFilter filter = null;
        public APRSData.Buddie lastBuddie = null;

        public string IP { get { return ((IPEndPoint)this.client.Client.RemoteEndPoint).Address.ToString(); } }
        public int Port { get { return ((IPEndPoint)this.client.Client.RemoteEndPoint).Port; } }

        public ClientData(TcpClient client, ulong clientID)
        {
            this.id = clientID;
            this.connected = DateTime.UtcNow;
            this.client = client;
            this.validated = false;
            this.stream = client.GetStream();
        }

        public string SetFilter(string filter, string user)
        {
            this.filter = new ClientAPRSFilter(filter, user);
            if((this.filter== null) || (this.filter.Count == 0))
                return "NOT DEFINED";
            else
                return this.filter.ToString();
        }

        public bool PassFilter(string APRS, APRSData.Buddie buddie, Dictionary<string, ClientAPRSFilter.GeoPos> LastPositions)
        {
            if (filter == null) return true;
            return filter.Pass(APRS, buddie, LastPositions);
        }
    }
}
