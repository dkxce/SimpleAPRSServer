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
    public class ClientAPRSFilter
    {
        public class GeoPos
        {
            public double lat;
            public double lon;
            public GeoPos(double lat, double lon) { this.lat = lat; this.lon = lon; }
            public override string ToString()
            {
                return String.Format(System.Globalization.CultureInfo.InvariantCulture, "{0} {1}", lat, lon);
            }

            public static uint GetLengthMeters(double StartLat, double StartLong, double EndLat, double EndLong, bool radians)
            {
                double D2R = Math.PI / 180;
                if (radians) D2R = 1;
                double dDistance = Double.MinValue;
                double dLat1InRad = StartLat * D2R;
                double dLong1InRad = StartLong * D2R;
                double dLat2InRad = EndLat * D2R;
                double dLong2InRad = EndLong * D2R;

                double dLongitude = dLong2InRad - dLong1InRad;
                double dLatitude = dLat2InRad - dLat1InRad;

                // Intermediate result a.
                double a = Math.Pow(Math.Sin(dLatitude / 2.0), 2.0) +
                           Math.Cos(dLat1InRad) * Math.Cos(dLat2InRad) *
                           Math.Pow(Math.Sin(dLongitude / 2.0), 2.0);

                // Intermediate result c (great circle distance in Radians).
                double c = 2.0 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1.0 - a));

                const double kEarthRadiusKms = 6378137.0000;
                dDistance = kEarthRadiusKms * c;

                return (uint)Math.Round(dDistance);
            }

            public static double GetLengthKm(double StartLat, double StartLong, double EndLat, double EndLong, bool radians)
            {
                return (double)GetLengthMeters(StartLat, StartLong, EndLat, EndLong, radians) / 1000.0;
            }
        }

        private const string R_r = @"(?:^|\s)r/(?<lat>[\d\.\-]+)/(?<lon>[\d\.\-]+)/(?<dist>[\d]+)";
        private const string R_p = @"(?:^|\s)p(?:/(?<call>[^\/\s\r\n]+))+";
        private const string R_b = @"(?:^|\s)b(?:/(?<exact>[^\/\s\r\n]+))+";
        private const string R_o = @"(?:^|\s)o(?:/(?<obj>[^\/\s\r\n]+))+";
        private const string R_os = @"(?:^|\s)os(?:/(?<strict>[^\/\r\n]{3,9}))+$";
        private const string R_t = @"(?:^|\s)t/(?<type>[poimqstunw]+)(?:/(?<call>[^\/\s\r\n]+)/(?<dist>[\d]+))?";
        private const string R_s = @"(?:^|\s)s/(?<pri>[^\/\s\r\n]*)(?:/(?<alt>[^\/\s\r\n]*)(?:/(?<over>[^\/\s\r\n]+))?)?";
        private const string R_d = @"(?:^|\s)d(?:/(?<call>[^\/\s\r\n]+))+";
        private const string R_a = @"(?:^|\s)a/(?<top>[\d\.\-]+)/(?<left>[\d\.\-]+)/(?<bottom>[\d\.\-]+)/(?<right>[\d\.\-]+)";
        private const string R_e = @"(?:^|\s)e(?:/(?<ssid>[^\/\s\r\n]+))+";
        private const string R_g = @"(?:^|\s)g(?:/(?<ssid>[^\/\s\r\n]+))+";
        private const string R_u = @"(?:^|\s)u(?:/(?<ssid>[^\/\s\r\n]+))+";
        private const string R_m = @"(?:^|\s)m/(?<dist>[\d]+)";
        private const string R_f = @"(?:^|\s)f/(?<call>[^\/\s\r\n]+)/(?<dist>[\d]+)";

        private List<F> list = new List<F>();
        public int Count { get { return list.Count; } }

        private string filter = "";
        public string Filter { get { return filter; } }

        private string user = "UNKNOWN";
        public string User { get { return user; } }
        
        public ClientAPRSFilter(string filter, string user)
        {
            this.filter = filter;
            if (!String.IsNullOrEmpty(this.filter)) this.filter = this.filter.Trim(new char[] { '\r', '\n' });
            if (!String.IsNullOrEmpty(user)) this.user = user;
            Init();
        }

        private void Init()
        {
            if (String.IsNullOrEmpty(filter)) return;

            F f = null;
            try { if ((f = new F_r(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_p(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_b(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_o(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_os(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_t(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_s(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_d(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_a(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_e(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_g(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_u(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_m(filter, this)).Sucess) list.Add(f); }
            catch { };
            try { if ((f = new F_f(filter, this)).Sucess) list.Add(f); }
            catch { };
        }

        public bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
        {
            if (list.Count == 0) return true;
            foreach (F f in list)
            {
                try
                {
                    if (f.Pass(APRS, buddie, LastPositions)) return true;
                }
                catch { };
            };
            return false;
        }

        public override string ToString()
        {
            string res = "";
            if (list.Count > 0)
            {
                foreach(F f in list) res += (res.Length > 0 ? " " : "") + f.filter;
                return res;
            }
            else
                return filter;
        }

        public class F        // Filter Prototype
        {
            public ClientAPRSFilter parent;
            public string filter;
            public string f_str;
            public Regex f_reg;
            public MatchCollection mc;
            public F(string regExp, ClientAPRSFilter parent) { this.parent = parent; this.f_str = regExp; this.f_reg = new Regex(this.f_str, RegexOptions.None); }
            protected void Init(string filter)
            {
                this.filter = filter;
                this.mc = this.f_reg.Matches(filter);
                if (Sucess)
                {
                    this.filter = "";
                    foreach (Match mx in mc)
                        this.filter += (this.filter.Length > 0 ? " " : "") + mx.Value.Trim();
                };
            }
            public bool Sucess { get { return this.mc.Count > 0; } }
            public virtual bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions) { return true; }
        }     
        public class F_r : F  // r/lat/lon/dist -- Range filter 
        {
            public double[] lat;
            public double[] lon;
            public int[] dist;
            public F_r(string filter, ClientAPRSFilter parent)
                : base(R_r, parent)
            {
                Init(filter);
                if (!Sucess) return;
                lat = new double[mc.Count];
                lon = new double[mc.Count];
                dist = new int[mc.Count];
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    lat[i] = double.Parse(mx.Groups["lat"].Value, System.Globalization.CultureInfo.InvariantCulture);
                    lon[i] = double.Parse(mx.Groups["lon"].Value, System.Globalization.CultureInfo.InvariantCulture);
                    dist[i] = int.Parse(mx.Groups["dist"].Value, System.Globalization.CultureInfo.InvariantCulture);
                };
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (buddie == null) return false;
                if (!buddie.PositionIsValid) return false;
                for (int i = 0; i < lat.Length; i++)
                    if (GeoPos.GetLengthKm(buddie.lat, buddie.lon, lat[i], lon[i], false) <= dist[i])
                        return true;
                return false;
            }
        }
        public class F_p : F  // p/aa/bb/cc -- Prefix filter  
        {
            public string[] pass;
            public F_p(string filter, ClientAPRSFilter parent)
                : base(R_p, parent)
            {
                Init(filter);
                if (!Sucess) return;
                List<string> strs = new List<string>();
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    CaptureCollection cc = mx.Groups["call"].Captures;
                    if (cc.Count > 0)
                        foreach (Capture c in cc)
                            strs.Add(c.Value);
                };
                pass = strs.ToArray();
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (pass == null) return false;
                if (String.IsNullOrEmpty(APRS)) return false;
                foreach (string p in pass)
                {
                    Regex rx = new Regex(@"(?:^|\s)" + p + @"[\w\-]+>", RegexOptions.IgnoreCase);
                    if (rx.Match(APRS).Success) return true;
                };
                return false;
            }
        }
        public class F_b : F  // b/call1/call2 -- Budlist filter 
        {
            public string[] pass;
            public F_b(string filter, ClientAPRSFilter parent)
                : base(R_b, parent)
            {
                Init(filter);
                if (!Sucess) return;
                List<string> strs = new List<string>();
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    CaptureCollection cc = mx.Groups["exact"].Captures;
                    if (cc.Count > 0)
                        foreach (Capture c in cc)
                            strs.Add(c.Value);
                };
                pass = strs.ToArray();
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (pass == null) return false;
                if (String.IsNullOrEmpty(APRS)) return false;
                foreach (string p in pass)
                {
                    Regex rx = new Regex(@"(?:^|\s)" + p.Replace("*", @"[^\>,\s]*") + @"\>", RegexOptions.None);
                    if (rx.Match(APRS).Success) return true;
                };
                return false;
            }
        }
        public class F_o : F  // o/call1/call2 -- Object filter 
        {
            public string[] pass;
            public F_o(string filter, ClientAPRSFilter parent)
                : base(R_o, parent)
            {
                Init(filter);
                if (!Sucess) return;
                List<string> strs = new List<string>();
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    CaptureCollection cc = mx.Groups["obj"].Captures;
                    if (cc.Count > 0)
                        foreach (Capture c in cc)
                            strs.Add(c.Value);
                };
                pass = strs.ToArray();
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (pass == null) return false;
                if (String.IsNullOrEmpty(APRS)) return false;

                string csign, rt, pckt;
                if (!APRSData.ParseAPRSRoute(APRS, out csign, out rt, out pckt)) pckt = APRS;

                foreach (string p in pass)
                {
                    Regex rx = new Regex(@"(?:^|\s)" + ";" + p.Replace("*", @"[^\*_\s\>,]*") + @"\s*[\*_]", RegexOptions.None);
                    if (rx.Match(pckt).Success) return true;
                    rx = new Regex(@"(?:^|\s)" + @"\)" + p.Replace("*", @"[^!_\s\>,]*") + @"\s*[!_]", RegexOptions.None);
                    if (rx.Match(pckt).Success) return true;
                };
                return false;
            }
        }
        public class F_os : F // os/call1/call2 -- Strict Object filter
        {
            public string[] pass;
            public F_os(string filter, ClientAPRSFilter parent)
                : base(R_os, parent)
            {
                Init(filter);
                if (!Sucess) return;
                List<string> strs = new List<string>();
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    CaptureCollection cc = mx.Groups["strict"].Captures;
                    if (cc.Count > 0)
                        foreach (Capture c in cc)
                            strs.Add(c.Value);
                };
                pass = strs.ToArray();
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (pass == null) return false;
                if (String.IsNullOrEmpty(APRS)) return false;

                string csign, rt, pckt;
                if (!APRSData.ParseAPRSRoute(APRS, out csign, out rt, out pckt)) pckt = APRS;

                foreach (string p in pass)
                {
                    string srep = @"(?:^|\s)" + ";" + p.Replace(" ", @"\s").Replace("*", @"[^\*_\>,]*") + @"\s*[\*_]";
                    Regex rx = new Regex(srep, RegexOptions.None);
                    if (rx.Match(pckt).Success) return true;
                    srep = @"(?:^|\s)" + @"\)" + p.Replace(" ", @"\s").Replace("*", @"[^!_\>,]*") + @"\s*[!_]";
                    rx = new Regex(srep, RegexOptions.None);
                    if (rx.Match(pckt).Success) return true;
                };
                return false;
            }
        }
        public class F_t : F  // t/poimqstuw/call/km -- Type filter
        {
            public string[] types;
            public string[] calls;
            public int[] dists;
            public F_t(string filter, ClientAPRSFilter parent)
                : base(R_t, parent)
            {
                Init(filter);
                if (!Sucess) return;
                types = new string[mc.Count];
                calls = new string[mc.Count];
                dists = new int[mc.Count];
                for (int i = 0; i < mc.Count; i++)
                {
                    types[i] = mc[i].Groups["type"].Value;
                    calls[i] = mc[i].Groups["call"].Value;
                    if (!String.IsNullOrEmpty(mc[i].Groups["dist"].Value)) dists[i] = int.Parse(mc[i].Groups["dist"].Value);
                };
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (types == null) return false;
                if (String.IsNullOrEmpty(APRS)) return false;
                for (int i = 0; i < types.Length; i++)
                {
                    string csign, rt, pckt;
                    if (!APRSData.ParseAPRSRoute(APRS, out csign, out rt, out pckt)) pckt = APRS;

                    bool pass = false;
                    if (types[i].IndexOf("p") >= 0) // position
                    {
                        if (pckt.StartsWith(";")) pass = true;
                        else
                            if (pckt.StartsWith(")")) pass = true;
                            else
                                if ((new Regex(@"^[^\s\>]+>[^\s\:]+:[!=/@]", RegexOptions.None)).Match(APRS).Success) pass = true;
                    };
                    if ((!pass) && (types[i].IndexOf("o") >= 0) && (pckt.StartsWith(";"))) pass = true; // objects
                    if ((!pass) && (types[i].IndexOf("i") >= 0) && (pckt.StartsWith(")"))) pass = true; // items
                    if ((!pass) && (types[i].IndexOf("m") >= 0) && (pckt.StartsWith(":"))) pass = true; // messages
                    if ((!pass) && (types[i].IndexOf("q") >= 0) && (pckt.StartsWith("?"))) pass = true; // queries
                    if ((!pass) && (types[i].IndexOf("s") >= 0) && (pckt.StartsWith(">"))) pass = true; // status
                    if ((!pass) && (types[i].IndexOf("t") >= 0) && (pckt.StartsWith("T#"))) pass = true; // telemetry
                    if ((!pass) && (types[i].IndexOf("u") >= 0) && (pckt.StartsWith("{"))) pass = true; // user-defined
                    if ((!pass) && (types[i].IndexOf("n") >= 0) && (pckt.StartsWith(":NWS"))) pass = true; // NWS
                    if ((!pass) && (types[i].IndexOf("w") >= 0) && (pckt.StartsWith("!") || pckt.StartsWith("#") || pckt.StartsWith("$") || pckt.StartsWith("*"))) pass = true; // weather
                    if (pass && (!String.IsNullOrEmpty(calls[i])) && (buddie != null) && (!String.IsNullOrEmpty(buddie.name)))
                    {
                        if (buddie.name != calls[i]) pass = false; // not specified user
                        if (pass && (!buddie.PositionIsValid)) pass = false; // bad position
                        if (pass && (LastPositions == null)) pass = false; // no stored positions
                        if (pass && !LastPositions.ContainsKey(buddie.name)) pass = false; // no stored positions
                        if (pass && (GeoPos.GetLengthKm(buddie.lat, buddie.lon, LastPositions[buddie.name].lat, LastPositions[buddie.name].lon, false) > dists[i])) pass = false; // too far
                    };
                    if (pass) return true;
                };
                return false;
            }
        }
        public class F_s : F  // s/pri/alt/over -- Symbol filter 
        {
            public string[] pri;
            public string[] alt;
            public string[] over;
            public F_s(string filter, ClientAPRSFilter parent)
                : base(R_s, parent)
            {
                Init(filter);
                if (!Sucess) return;
                List<string> strs = new List<string>();
                pri = new string[mc.Count];
                alt = new string[mc.Count];
                over = new string[mc.Count];
                for (int i = 0; i < mc.Count; i++)
                {
                    if (!String.IsNullOrEmpty(mc[i].Groups["pri"].Value)) pri[i] = mc[i].Groups["pri"].Value; else pri[i] = "";
                    if (!String.IsNullOrEmpty(mc[i].Groups["alt"].Value)) alt[i] = mc[i].Groups["alt"].Value; else alt[i] = "";
                    if (!String.IsNullOrEmpty(mc[i].Groups["over"].Value)) over[i] = mc[i].Groups["over"].Value; else over[i] = "";
                };
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (String.IsNullOrEmpty(APRS)) return false;
                if (buddie == null) return false;
                if (String.IsNullOrEmpty(buddie.iconSymbol)) return false;
                if (buddie.iconSymbol.Length != 2) return false;
                for (int i = 0; i < pri.Length; i++)
                {
                    if (over[i] == "")
                    {
                        if ((buddie.iconSymbol[0] == '/') && (pri[i].IndexOf(buddie.iconSymbol[1]) >= 0)) return true;
                        if ((buddie.iconSymbol[0] == '\\') && (alt[i].IndexOf(buddie.iconSymbol[1]) >= 0)) return true;
                    }
                    else
                    {
                        if ((over[i].IndexOf(buddie.iconSymbol[0]) >= 0) && (alt[i].IndexOf(buddie.iconSymbol[1]) >= 0)) return true;
                    };
                };
                return false;
            }
        }
        public class F_d : F  // d/digi1/digi2 -- Digipeater filter
        {
            public string[] pass;
            public F_d(string filter, ClientAPRSFilter parent)
                : base(R_d, parent)
            {
                Init(filter);
                if (!Sucess) return;
                List<string> strs = new List<string>();
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    CaptureCollection cc = mx.Groups["call"].Captures;
                    if (cc.Count > 0)
                        foreach (Capture c in cc)
                            strs.Add(c.Value);
                };
                pass = strs.ToArray();
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (pass == null) return false;
                if (String.IsNullOrEmpty(APRS)) return false;
                foreach (string p in pass)
                {
                    Regex rx = new Regex(@">\S*,?(?<who>" + p.Replace("*", @"[^\>,\s]*") + @"),?[^\w\-\*\s]", RegexOptions.None);
                    if (rx.Match(APRS).Success) return true;
                };
                return false;
            }
        }
        public class F_a : F  // a/latN/lonW/latS/lonE -- Area filter 
        {
            public double[] top, left, bottom, right;
            public F_a(string filter, ClientAPRSFilter parent)
                : base(R_a, parent)
            {
                Init(filter);
                if (!Sucess) return;
                top = new double[mc.Count];
                left = new double[mc.Count];
                bottom = new double[mc.Count];
                right = new double[mc.Count];
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    top[i] = double.Parse(mx.Groups["top"].Value, System.Globalization.CultureInfo.InvariantCulture);
                    left[i] = double.Parse(mx.Groups["left"].Value, System.Globalization.CultureInfo.InvariantCulture);
                    bottom[i] = double.Parse(mx.Groups["bottom"].Value, System.Globalization.CultureInfo.InvariantCulture);
                    right[i] = double.Parse(mx.Groups["right"].Value, System.Globalization.CultureInfo.InvariantCulture);
                };
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (buddie == null) return false;
                if (!buddie.PositionIsValid) return false;
                for (int i = 0; i < left.Length; i++)
                    if ((buddie.lat <= top[i]) && (buddie.lat >= bottom[i]) && (buddie.lon >= left[i]) && (buddie.lon <= right[i]))
                        return true;
                return false;
            }
        }
        public class F_e : F  // e/call1/call2 -- Entry station filter
        {
            public string[] pass;
            public F_e(string filter, ClientAPRSFilter parent)
                : base(R_e, parent)
            {
                Init(filter);
                if (!Sucess) return;
                List<string> strs = new List<string>();
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    CaptureCollection cc = mx.Groups["ssid"].Captures;
                    if (cc.Count > 0)
                        foreach (Capture c in cc)
                            strs.Add(c.Value);
                };
                pass = strs.ToArray();
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (pass == null) return false;
                if (String.IsNullOrEmpty(APRS)) return false;
                foreach (string p in pass)
                {
                    Regex rx = new Regex(@"[>,]" + p.Replace("*", @"[\w-]*") + @"[^\w-\s]", RegexOptions.None);
                    if (rx.Match(APRS).Success) return true;
                };
                return false;
            }
        }
        public class F_g : F  // g/call1/call2 -- Group Message filter 
        {
            public string[] pass;
            public F_g(string filter, ClientAPRSFilter parent)
                : base(R_g, parent)
            {
                Init(filter);
                if (!Sucess) return;
                List<string> strs = new List<string>();
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    CaptureCollection cc = mx.Groups["ssid"].Captures;
                    if (cc.Count > 0)
                        foreach (Capture c in cc)
                            strs.Add(c.Value);
                };
                pass = strs.ToArray();
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (pass == null) return false;
                if (String.IsNullOrEmpty(APRS)) return false;

                string csign, rt, pckt;
                if (!APRSData.ParseAPRSRoute(APRS, out csign, out rt, out pckt)) pckt = APRS;

                foreach (string p in pass)
                {
                    Regex rx = new Regex(@"(?:^|\s):" + p.Replace("*", @"[\w-]*") + @":", RegexOptions.None);
                    if (rx.Match(pckt).Success) return true;
                };
                return false;
            }
        }
        public class F_u : F  // u/call1/call2 -- Unproto filter
        {
            public string[] pass;
            public F_u(string filter, ClientAPRSFilter parent)
                : base(R_u, parent)
            {
                Init(filter);
                if (!Sucess) return;
                List<string> strs = new List<string>();
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    CaptureCollection cc = mx.Groups["ssid"].Captures;
                    if (cc.Count > 0)
                        foreach (Capture c in cc)
                            strs.Add(c.Value);
                };
                pass = strs.ToArray();
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (pass == null) return false;
                if (String.IsNullOrEmpty(APRS)) return false;

                string csign, rt, pckt;
                if (!APRSData.ParseAPRSRoute(APRS, out csign, out rt, out pckt)) return false;

                foreach (string p in pass)
                {
                    Regex rx = new Regex(@":;" + p.Replace("*", @"[\w-]*") + @"[^\w-\s]", RegexOptions.None);
                    if (rx.Match(pckt).Success) return true;
                };
                return false;
            }
        }
        public class F_m : F  // m/dist -- My Range filter
        {
            public int dist;
            public F_m(string filter, ClientAPRSFilter parent)
                : base(R_m, parent)
            {
                Init(filter);
                if (!Sucess) return;
                for (int i = 0; i < mc.Count; i++)
                    dist = int.Parse(mc[i].Groups["dist"].Value, System.Globalization.CultureInfo.InvariantCulture);
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (buddie == null) return false;
                if (!buddie.PositionIsValid) return false;
                if (LastPositions == null) return false;
                if (LastPositions.Count == 0) return false;
                if (!LastPositions.ContainsKey(parent.User)) return false;
                if (GeoPos.GetLengthKm(buddie.lat, buddie.lon, LastPositions[parent.User].lat, LastPositions[parent.User].lon, false) <= dist) return true;
                return false;
            }
        }
        public class F_f : F  // f/user/dist --	Friend Range filter 
        {
            public string[] user;
            public int[] dist;
            public F_f(string filter, ClientAPRSFilter parent)
                : base(R_f, parent)
            {
                Init(filter);
                if (!Sucess) return;
                user = new string[mc.Count];
                dist = new int[mc.Count];
                for (int i = 0; i < mc.Count; i++)
                {
                    Match mx = mc[i];
                    user[i] = mx.Groups["call"].Value;
                    dist[i] = int.Parse(mx.Groups["dist"].Value, System.Globalization.CultureInfo.InvariantCulture);
                };
            }
            public override bool Pass(string APRS, APRSData.Buddie buddie, Dictionary<string, GeoPos> LastPositions)
            {
                if (!Sucess) return false;
                if (buddie == null) return false;
                if (!buddie.PositionIsValid) return false;
                if (LastPositions == null) return false;
                if (LastPositions.Count == 0) return false;
                for (int i = 0; i < user.Length; i++)
                {
                    if (LastPositions.ContainsKey(user[i]))
                        if (GeoPos.GetLengthKm(buddie.lat, buddie.lon, LastPositions[user[i]].lat, LastPositions[user[i]].lon, false) <= dist[i])
                            return true;
                };
                return false;
            }
        }
    }
}
