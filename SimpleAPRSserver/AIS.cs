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
    // Ship Types
    public enum ShipType : int
    {
        Default = 0,
        WIG_AllShips = 20,
        Fishing = 30,
        Towing = 31,
        TowingBig = 32,
        DredgingOrUnderwater = 33,
        Diving = 34,
        Military = 35,
        Sailing = 36,
        PleasureCraft = 37,
        HighSpeedCraft_All = 40,
        HighSpeedCraft_A = 41,
        HighSpeedCraft_B = 42,
        HighSpeedCraft_NoInfo = 49,
        PilotVessel = 50,
        SearchRescue = 51,
        Tug = 52,
        PortTender = 53,
        MedicalTransport = 58,
        Passenger_All = 60,
        Passenger_A = 61,
        Passenger_B = 62,
        Passenger_NoInfo = 69,
        Cargo_All = 70,
        Cargo_A = 71,
        Cargo_B = 72,
        Cargo_NoInfo = 79,
        Tanker_All = 80,
        Tanker_A = 81,
        Tanker_B = 82,
        Tanker_NoInfo = 89
    }

    // Code to/from AIS packet
    public class AISTransCoder
    {
        public class AISPacket
        {
            public byte[] OriginalData = null;
            public string OriginalText = null;
            public string OriginalFrame = null;

            public uint PacketType = 0;
            public bool HasData = false;
            public bool Valid = false;

            public PositionReportClassA PositionReportA { get { if ((PacketType == 1) || (PacketType == 2) || (PacketType == 3)) return PositionReportClassA.FromAIS(OriginalData); else return null; } }
            public PositionReportClassAExt PositionReportAext { get { if (PacketType == 5) return PositionReportClassAExt.FromAIS(OriginalData); else return null; } }
            public PositionReportClassB PositionReportB { get { if (PacketType == 18) return PositionReportClassB.FromAIS(OriginalData); else return null; } }
            public PositionReportClassBE PositionReportBext { get { if (PacketType == 19) return PositionReportClassBE.FromAIS(OriginalData); else return null; } }
            public CNBAsentense SentenseA { get { if ((PacketType == 1) || (PacketType == 2) || (PacketType == 3)) return CNBAsentense.FromAIS(OriginalData); else return null; } }
            public StaVoyData SentenseStaVoyData { get { if (PacketType == 5) return StaVoyData.FromAIS(OriginalData); else return null; } }
            public AIVDMSentense SentenseAIVDM { get { if (PacketType == 5) return AIVDMSentense.FromAIS(OriginalData); else return null; } }
            public SafetyRelatedBroadcastMessage SafetyMessage { get { if (PacketType == 14) return SafetyRelatedBroadcastMessage.FromAIS(OriginalData); else return null; } }
            public CNBBsentense SentenseB { get { if (PacketType == 18) return CNBBsentense.FromAIS(OriginalData); else return null; } }
            public CNBBEsentense SentenseSB { get { if (PacketType == 19) return CNBBEsentense.FromAIS(OriginalData); else return null; } }
            public StaticDataReport StaticReport { get { if (PacketType == 24) return StaticDataReport.FromAIS(OriginalData); else return null; } }
            
            public object Result
            {
                get
                {
                    switch (PacketType)
                    {
                        case 01:
                        case 02:
                        case 03: return this.PositionReportA;
                        case 05: return this.PositionReportAext;
                        case 14: return this.SafetyMessage;
                        case 18: return this.PositionReportB;
                        case 19: return this.PositionReportBext;
                        case 24: return this.StaticReport;
                        default: return null;
                    };
                }
            }

            // Get Normal Data from Unpacked AIS text
            public static AISPacket FromUnpackedData(byte[] unpackedData, uint packetType)
            {
                AISPacket res = new AISPacket();                
                res.PacketType = packetType;
                res.OriginalData = unpackedData;
                res.OriginalText = null;
                res.HasData = res.Result != null;
                res.Valid = (packetType > 0) && (unpackedData != null) && (unpackedData.Length > 0);
                return res;
            }

            // Get Normal Data from AIS Frame text
            public static AISPacket FromPacketFrame(string PacketFrame)
            {
                AISPacket res = new AISPacket();
                res.OriginalFrame = PacketFrame;                
                res.Valid = AISTransCoder.ValidatePacket(PacketFrame, out res.OriginalText, out res.OriginalData, out res.PacketType);
                if (res.Valid) res.HasData = res.Result != null;
                return res;
            }
        }

        // desc http://www.bosunsmate.org/ais
        // test http://ais.tbsalling.dk/
        // test http://www.aggsoft.com/ais-decoder.htm
        // api  http://catb.org/gpsd/AIVDM.html        

        // Orux Decode:  AIS 1,2,3,5,18,19,24 ( http://www.oruxmaps.com/foro/viewtopic.php?t=1627 )
        // http://wiki.openseamap.org/wiki/OruxMaps

        // AIS Message Types:
        // 01 - Position Report with SOTDMA
        // 02 - Position Report with SOTDMA
        // 03 - Position Report with ITDMA
        // 05 - Static and Voyage Related Dat;; http://www.navcen.uscg.gov/?pageName=AISMessagesAStatic
        // 14 - SafetyRelatedBroadcastMessage
        // 18 - Standard Class B CS Position Report
        // 19 - Extended Class B CS Position Report
        // 24 - Static Data Report

        // Check Valid AIS Packet
        public static bool ValidatePacket(string packet, out string command, out byte[] unpacked, out uint packetType)
        {
            command = null;
            unpacked = null;
            packetType = 0;

            if (String.IsNullOrEmpty(packet)) return false;
            if (!packet.StartsWith("!AIVD")) return false;

            string chsum = Checksum(packet.Substring(0, packet.Length - 3));
            if (packet.Substring(packet.Length - 2) != chsum) return false;

            string checksum = packet.Substring(packet.Length - 2);
            command = packet.Remove(packet.Length - 5);
            command = command.Substring(command.LastIndexOf(",") + 1);

            unpacked = AISTransCoder.UnpackAisEncoding(command);
            packetType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpacked, 0, 6);

            return true;
        }        

        // Get Checksum
        public static string Checksum(string sentence)
        {
            int iFrom = 0;
            if (sentence.IndexOf('$') == 0) iFrom++;
            if (sentence.IndexOf('!') == 0) iFrom++;
            int iTo = sentence.Length;
            if (sentence.LastIndexOf('*') == (sentence.Length - 3))
                iTo = sentence.IndexOf('*');
            int checksum = Convert.ToByte(sentence[iFrom]);
            for (int i = iFrom + 1; i < iTo; i++)
                checksum ^= Convert.ToByte(sentence[i]);
            return checksum.ToString("X2");
        }

        // Unpack from 6-bit AIS string to 8-bit normal array 
        public static byte[] UnpackAisEncoding(string s)
        {
            return UnpackAisEncoding(Encoding.UTF8.GetBytes(s));
        }

        // Unpack from 6-bit AIS chars array to 8-bit normal array 
        private static byte[] UnpackAisEncoding(byte[] data)
        {
            int outputLen = ((data.Length * 6) + 7) / 8;
            byte[] result = new byte[outputLen];

            // We are always combining two input bytes into one or two output bytes.
            // This happens in three phases.  The phases are
            //  0 == 6,2  (six bits of the current source byte, plus 2 bits of the next)
            //  1 == 4,4
            //  2 == 2,6;
            int iSrcByte = 0;
            byte nextByte = ConvertSixBit(data[iSrcByte]);
            for (int iDstByte = 0; iDstByte < outputLen; ++iDstByte)
            {
                byte currByte = nextByte;
                if (iSrcByte < data.Length - 1)
                    nextByte = ConvertSixBit(data[++iSrcByte]);
                else
                    nextByte = 0;

                // iDstByte % 3 is the 'phase' we are in and determins the shifting pattern to use
                switch (iDstByte % 3)
                {
                    case 0:
                        // 11111122 2222xxxx
                        result[iDstByte] = (byte)((currByte << 2) | (nextByte >> 4));
                        break;
                    case 1:
                        // 11112222 22xxxxxx
                        result[iDstByte] = (byte)((currByte << 4) | (nextByte >> 2));
                        break;
                    case 2:
                        // 11222222 xxxxxxxx
                        result[iDstByte] = (byte)((currByte << 6) | (nextByte));
                        // There are now no remainder bits, so we need to eat another input byte
                        if (iSrcByte < data.Length - 1)
                            nextByte = ConvertSixBit(data[++iSrcByte]);
                        else
                            nextByte = 0;
                        break;
                }
            }

            return result;
        }

        // Pack from 8-bit normal array to 6-bit AIS string
        public static string EnpackAisToString(byte[] ba)
        {
            return Encoding.UTF8.GetString(EnpackAisEncoding(ba));
        }

        // Pack from 8-bit normal array to 6-bit AIS chars array
        private static byte[] EnpackAisEncoding(byte[] ba)
        {
            List<byte> res = new List<byte>();
            for (int i = 0; i < ba.Length; i++)
            {
                int val = 0;
                int val2 = 0;
                switch (i % 3)
                {
                    case 0:
                        val = (byte)((ba[i] >> 2) & 0x3F);
                        break;
                    case 1:
                        val = (byte)((ba[i - 1] & 0x03) << 4) | (byte)((ba[i] & 0xF0) >> 4);
                        break;
                    case 2:
                        val = (byte)((ba[i - 1] & 0x0F) << 2) | (byte)((ba[i] & 0xC0) >> 6);
                        val2 = (byte)((ba[i] & 0x3F)) + 48;
                        if (val2 > 87) val2 += 8;
                        break;
                };
                val += 48;
                if (val > 87) val += 8;
                res.Add((byte)val);
                if ((i % 3) == 2) res.Add((byte)val2);
            };
            return res.ToArray();
        }

        // Get Strring From Unpacked Bytes
        public static string GetAisString(byte[] source, int start, int len)
        {
            string key = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?";
            int l = key.Length;
            string val = "";
            for (int i = 0; i < len; i += 6)
            {
                byte c = (byte)(GetBitsAsSignedInt(source, start + i, 6) & 0x3F);
                val += key[c];
            };
            return val.Trim();
        }

        // Set String To Unpacked Bytes
        public static void SetAisString(byte[] source, int start, int len, string val)
        {
            if (val == null) val = "";
            string key = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?;";
            int strlen = len / 6;
            if (val.Length > strlen) val = val.Substring(0, strlen);
            while (val.Length < strlen) val += " ";
            int s = 0;
            for (int i = 0; i < len; i += 6, s++)
            {
                byte c = (byte)key.IndexOf(val[s]);
                SetBitsAsSignedInt(source, start + i, 6, c);
            };
        }

        // Get Int32 From Unpacked Bytes
        public static int GetBitsAsSignedInt(byte[] source, int start, int len)
        {
            int value = GetBitsAsUnsignedInt(source, start, len);
            if ((value & (1 << (len - 1))) != 0)
            {
                // perform 32 bit sign extension
                for (int i = len; i < 32; ++i)
                {
                    value |= (1 << i);
                }
            };
            return value;
        }

        // Set Int32 To Unpacked Bytes
        public static void SetBitsAsSignedInt(byte[] source, int start, int len, int val)
        {
            int value = val;
            if (value < 0)
            {
                value = ~value;
                for (int i = len; i < 32; ++i)
                {
                    value |= (1 << i);
                };
            }
            SetBitsAsUnsignedInt(source, start, len, val);
        }

        // Get UInt32 From Unpacked Bytes
        public static int GetBitsAsUnsignedInt(byte[] source, int start, int len)
        {
            int result = 0;

            for (int i = start; i < (start + len); ++i)
            {
                int iByte = i / 8;
                int iBit = 7 - (i % 8);
                result = result << 1 | (((source[iByte] & (1 << iBit)) != 0) ? 1 : 0);
            }

            return result;
        }

        // Set UInt32 To Unpacked Bytes
        public static void SetBitsAsUnsignedInt(byte[] source, int start, int len, int val)
        {
            int bit = len - 1;
            for (int i = start; i < (start + len); ++i, --bit)
            {
                int iByte = i / 8;
                int iBit = 7 - (i % 8);
                byte mask = (byte)(0xFF - (byte)(1 << iBit));
                byte bitm = (byte)~mask;
                byte b = (byte)(((val >> bit) & 0x01) << iBit);
                source[iByte] = (byte)((source[iByte] & mask) | b);
            }
        }

        private static byte ConvertSixBit(byte b)
        {
            byte result = (byte)(b - 48);
            if (result > 39)
                result -= 8;
            return result;
        }
    }

    // 1, 2, 3 -- Violet
    // Position Report with SOTDMA
    // Position Report with ITDMA
    public class PositionReportClassA
    {
        public bool valid = false;
        public byte length = 168;

        private uint pType = 1;
        private uint pRepeat = 0;

        public bool Accuracy = false;        
        public uint MMSI;
        private uint Status = 15;
        private int Turn = 0;
        public uint Speed = 0;        
        public double Lon = 0;
        public double Lat = 0;
        public double Course = 0;
        public ushort Heading = 0;
        private uint Second = 60;
        private uint Maneuver = 0;
        private uint Radio = 0;

        public static PositionReportClassA FromAIS(byte[] unpackedBytes)
        {
            PositionReportClassA res = new PositionReportClassA();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if ((res.pType < 1) || (res.pType > 3)) return res;

            res.valid = true;
            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2);
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            res.Status = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 38, 4);
            res.Turn = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 42, 8);
            res.Speed = (uint)(AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 50, 10) / 10 * 1.852);
            res.Accuracy = (byte)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 60, 1) == 1 ? true : false;
            res.Lon = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 61, 28) / 600000.0;
            res.Lat = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 89, 27) / 600000.0;
            res.Course = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 116, 12) / 10.0;
            res.Heading = (ushort)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 128, 9);
            res.Second = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 137, 6);
            res.Maneuver = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 143, 2);
            res.Radio = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 149, 19);
            return res;
        }

        public static PositionReportClassA FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public static PositionReportClassA FromBuddie(APRSData.Buddie buddie)
        {
            PositionReportClassA res = new PositionReportClassA();
            res.Accuracy = buddie.PositionIsValid;
            res.MMSI = APRSData.Buddie.MMSI(buddie.name);
            res.Turn = 0;
            res.Speed = (uint)buddie.speed;            
            res.Lon = buddie.lon;
            res.Lat = buddie.lat;
            res.Course = (ushort)buddie.course;
            res.Heading = (ushort)buddie.course;
            return res;
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS());
        }

        public byte[] ToAIS()
        {
            byte[] unpackedBytes = new byte[21];
            if ((pType < 0) || (pType > 3)) pType = 3;
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType); // type
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat); // repeat (no)
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI); // mmsi
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 38, 4, (int)Status); // status (default)
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 42, 8, (int)Turn); // turn (off)
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 50, 10, (int)(Speed / 1.852 * 10)); // speed                                                
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 60, 1, Accuracy ? 1 : 0); // FixOk
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 61, 28, (int)(Lon * 600000)); // lon
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 89, 27, (int)(Lat * 600000)); // lat        
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 116, 12, (int)(Course * 10)); // course
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 128, 9, (int)Heading); // heading
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 137, 6, (int)Second); // timestamp (not available (default))
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 143, 2, (int)Maneuver); // no Maneuver 
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 149, 19, (int)Radio); // no Maneuver 
            return unpackedBytes;
        }

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }

    // 5
    // Static and Voyage Related Data
    public class PositionReportClassAExt
    {
        private const short length = 424;

        private uint pType = 5;
        private uint pRepeat = 0;
        public uint MMSI;
        public uint IMOShipID;
        public string CallSign;
        public string VesselName;
        public int ShipType = 0;
        public string Destination = "";

        public static PositionReportClassAExt FromAIS(byte[] unpackedBytes)
        {
            PositionReportClassAExt res = new PositionReportClassAExt();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if (res.pType != 5) return res;

            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2);
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            res.IMOShipID = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 40, 30);
            res.CallSign = AISTransCoder.GetAisString(unpackedBytes, 70, 42);
            res.VesselName = AISTransCoder.GetAisString(unpackedBytes, 112, 120);
            res.ShipType = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 232, 8);
            res.Destination = AISTransCoder.GetAisString(unpackedBytes, 302, 120);

            return res;
        }

        public static PositionReportClassAExt FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public static PositionReportClassAExt FromBuddie(APRSData.Buddie buddie)
        {
            PositionReportClassAExt res = new PositionReportClassAExt();
            res.CallSign = res.VesselName = buddie.name;
            res.Destination = DateTime.Now.ToString("HHmmss ddMMyy");
            res.ShipType = 0;
            res.MMSI = res.IMOShipID = APRSData.Buddie.MMSI(buddie.name);
            return res;
        }

        public byte[] ToAIS()
        {
            byte[] unpackedBytes = new byte[54];
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, 5);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, 0);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 38, 2, 0);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 40, 30, (int)IMOShipID);
            AISTransCoder.SetAisString(unpackedBytes, 70, 42, CallSign);
            AISTransCoder.SetAisString(unpackedBytes, 112, 120, VesselName);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 232, 8, (int)ShipType);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 240, 9, 4); //A
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 249, 9, 1); //B
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 258, 6, 1); //C
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 264, 6, 2); //D
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 270, 4, 1); //PostFix
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 274, 4, DateTime.UtcNow.Month);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 278, 5, DateTime.UtcNow.Day);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 283, 5, DateTime.UtcNow.Hour);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 288, 6, DateTime.UtcNow.Minute);
            AISTransCoder.SetAisString(unpackedBytes, 302, 120, Destination);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 422, 1, 0);
            return unpackedBytes;
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS());
        }

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }   

    // 18 -- Green
    // Standard Class B CS Position Report
    public class PositionReportClassB
    {
        public bool valid = false;
        public int length = 168;

        private uint pType = 18;
        private uint pRepeat = 0;

        public bool Accuracy;
        public uint MMSI;
        public uint Speed;        
        public double Lon;
        public double Lat;
        public double Course = 0;
        public ushort Heading = 0;
        private uint Second = 60;

        public static PositionReportClassB FromAIS(byte[] unpackedBytes)
        {
            PositionReportClassB res = new PositionReportClassB();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if (res.pType != 18) return res;

            res.valid = true;
            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2);
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            res.Speed = (uint)(AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 46, 10) / 10 * 1.852);
            res.Accuracy = (byte)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 56, 1) == 1 ? true : false;
            res.Lon = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 57, 28) / 600000.0;
            res.Lat = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 85, 27) / 600000.0;
            res.Course = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 112, 12) / 10.0;
            res.Heading = (ushort)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 124, 9);
            res.Second = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 133, 6);
            return res;
        }

        public static PositionReportClassB FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public static PositionReportClassB FromBuddie(APRSData.Buddie buddie)
        {
            PositionReportClassB res = new PositionReportClassB();
            res.Accuracy = buddie.PositionIsValid;
            res.MMSI = APRSData.Buddie.MMSI(buddie.name);
            res.Speed = (ushort)buddie.speed;
            res.Lon = buddie.lon;
            res.Lat = buddie.lat;            
            res.Course = (ushort)buddie.course;
            res.Heading = (ushort)buddie.course;                        
            res.Speed = (uint)buddie.speed;            
            return res;
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS());
        }

        public byte[] ToAIS()
        {
            byte[] unpackedBytes = new byte[21];
            pType = 18;
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType); // type
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 46, 10, (int)(Speed / 1.852 * 10)); // speed            
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 56, 1, Accuracy ? 1 : 0);
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 57, 28, (int)(Lon * 600000));
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 85, 27, (int)(Lat * 600000));
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 112, 12, (int)(Course * 10.0));
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 124, 9, Heading);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 133, 6, 60);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 142, 1, 1);
            return unpackedBytes;
        }

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }

    // 19 -- Green
    // Extended Class B CS Position Report
    public class PositionReportClassBE
    {
        public bool valid = false;
        public int length = 312;

        private uint pType = 19;
        private uint pRepeat = 0;

        public bool Accuracy;
        public uint MMSI;
        public uint Speed;        
        public double Lon;
        public double Lat;
        public double Course = 0;
        public ushort Heading = 0;
        private uint Second = 60;
        public string Name;
        public int ShipType = 31;

        public static PositionReportClassBE FromAIS(byte[] unpackedBytes)
        {
            PositionReportClassBE res = new PositionReportClassBE();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if (res.pType != 19) return res;

            res.valid = true;
            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2);
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            res.Speed = (uint)(AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 46, 10) / 10 * 1.852);
            res.Accuracy = (byte)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 56, 1) == 1 ? true : false;
            res.Lon = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 57, 28) / 600000.0;
            res.Lat = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 85, 27) / 600000.0;
            res.Course = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 112, 12) / 10.0;
            res.Heading = (ushort)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 124, 9);
            res.Second = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 133, 6);
            res.Name = AISTransCoder.GetAisString(unpackedBytes, 143, 120);
            res.ShipType = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 263, 8);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 271, 9, 4);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 280, 9, 1);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 289, 6, 1);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 295, 6, 2);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 301, 4, 1);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 306, 6, 1);
            return res;
        }

        public static PositionReportClassBE FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public static PositionReportClassBE FromBuddie(APRSData.Buddie buddie)
        {
            PositionReportClassBE res = new PositionReportClassBE();
            res.Accuracy = buddie.PositionIsValid;
            res.MMSI = APRSData.Buddie.MMSI(buddie.name);
            res.Speed = (uint)buddie.speed;
            res.Lon = buddie.lon;
            res.Lat = buddie.lat;
            res.Course = (ushort)buddie.course;
            res.Heading = (ushort)buddie.course;
            res.Name = buddie.name;            
            return res;
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS());
        }

        public byte[] ToAIS()
        {
            byte[] unpackedBytes = new byte[39];
            pType = 19;
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType); // type
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 46, 10, (int)(Speed / 1.852 * 10)); // speed            
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 56, 1, Accuracy ? 1 : 0);
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 57, 28, (int)(Lon * 600000));
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 85, 27, (int)(Lat * 600000));
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 112, 12, (int)(Course * 10.0));
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 124, 9, Heading);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 133, 6, 60);
            AISTransCoder.SetAisString(unpackedBytes, 143, 120, Name);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 263, 8, ShipType);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 301, 4, 1);
            return unpackedBytes;
        }        

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }  
        
    // 1, 2, 3 -- Violet
    // Position Report with SOTDMA
    // Position Report with ITDMA
    public class CNBAsentense
    {
        private const byte length = 168;

        private uint pType = 1; // packet type
        private uint pRepeat = 0; // repeat
        public uint MMSI; // mmsi
        private uint NavigationStatus = 15; // status
        private int ROT = 0; // turn
        public uint SOG = 0; // speed
        public bool Accuracy = false; // FixOk
        public double Longitude = 0; // lon
        public double Latitude = 0; // lat
        public double COG = 0; // course
        public ushort HDG = 0; // heading
        private uint TimeStamp = 60;
        private uint ManeuverIndicator = 1;
        private uint RadioStatus = 0;

        public static CNBAsentense FromAIS(byte[] unpackedBytes)
        {
            CNBAsentense res = new CNBAsentense();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if ((res.pType < 1) || (res.pType > 3)) return null;

            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2); // 
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30); // 
            res.NavigationStatus = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 38, 4);
            res.ROT = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 42, 8);
            res.SOG = (uint)(AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 50, 10) / 10 * 1.852);
            res.Accuracy = (byte)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 60, 1) == 1 ? true : false;
            res.Longitude = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 61, 28) / 600000.0;
            res.Latitude = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 89, 27) / 600000.0;
            res.COG = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 116, 12) / 10.0;
            res.HDG = (ushort)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 128, 9);
            res.TimeStamp = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 137, 6);
            res.ManeuverIndicator = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 143, 2);
            res.RadioStatus = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 149, 19);
            return res;
        }

        public static CNBAsentense FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public static CNBAsentense FromBuddie(APRSData.Buddie buddie)
        {
            CNBAsentense res = new CNBAsentense();
            res.Accuracy = buddie.PositionIsValid;
            res.Latitude = buddie.lat;
            res.Longitude = buddie.lon;
            res.COG = res.HDG = (ushort)buddie.course;
            res.SOG = (uint)buddie.speed;
            res.MMSI = APRSData.Buddie.MMSI(buddie.name);
            return res;
        }

        public byte[] ToAIS()
        {
            byte[] unpackedBytes = new byte[21];
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType); // type
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat); // repeat
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 38, 4, (int)NavigationStatus);
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 42, 8, (int)ROT);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 50, 10, (int)(SOG / 1.852 * 10)); // speed                                                
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 60, 1, Accuracy ? 1 : 0);
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 61, 28, (int)(Longitude * 600000));
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 89, 27, (int)(Latitude * 600000));
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 116, 12, (int)(COG * 10)); // course
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 128, 9, (int)HDG); // heading
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 137, 6, (int)TimeStamp); // timestamp (not available (default))
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 143, 2, (int)ManeuverIndicator); // no Maneuver 
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 149, 19, (int)RadioStatus);
            return unpackedBytes;
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS());
        }

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }

    // 5
    // Static and Voyage Related Dat
    public class StaVoyData
    {
        public bool valid = false;
        public int length = 424;

        private uint pType = 5;
        private uint pRepeat = 0;

        public uint MMSI;
        private int AISv = 0;
        public uint ShipNo;
        public string Callsign;
        public string Name;
        public int ShipType = 31;
        private int Posfixt = 1;
        public string Destination = "";

        public static StaVoyData FromAIS(byte[] unpackedBytes)
        {
            StaVoyData res = new StaVoyData();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if (res.pType != 5) return res;
            res.valid = true;

            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2);
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            res.AISv = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 38, 2);
            res.ShipNo = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 40, 30);
            res.Callsign = AISTransCoder.GetAisString(unpackedBytes, 70, 42);
            res.Name = AISTransCoder.GetAisString(unpackedBytes, 112, 120);
            res.ShipType = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 232, 8); //30 - fishing, 31 - towing; 34 - diving; 36 - sailing; 37 - pleasure craft; 
            // 40 - hi speed; 50 - pilot vessel; 52 - tug; 60/69 - passenger; 70/79 - cargo; 80/89 - tanker
            res.Posfixt = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 270, 4);
            res.Destination = AISTransCoder.GetAisString(unpackedBytes, 302, 120);

            return res;
        }

        public static StaVoyData FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS());
        }

        public byte[] ToAIS()
        {
            byte[] unpackedBytes = new byte[54];
            pType = 5;
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 38, 2, (int)AISv);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 40, 30, (int)ShipNo);
            AISTransCoder.SetAisString(unpackedBytes, 70, 42, Callsign);
            AISTransCoder.SetAisString(unpackedBytes, 112, 120, Name);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 232, 8, (int)ShipType); //30 - fishing, 31 - towing; 34 - diving; 36 - sailing; 37 - pleasure craft; 
            // 40 - hi speed; 50 - pilot vessel; 52 - tug; 60/69 - passenger; 70/79 - cargo; 80/89 - tanker
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 240, 9, 4);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 249, 9, 1);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 258, 6, 1);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 264, 6, 2);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 270, 4, (int)Posfixt);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 274, 4, DateTime.UtcNow.Month);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 278, 5, DateTime.UtcNow.Day);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 283, 5, DateTime.UtcNow.Hour);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 288, 6, DateTime.UtcNow.Minute);
            AISTransCoder.SetAisString(unpackedBytes, 302, 120, Destination);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 422, 1, 0);
            return unpackedBytes;
        }

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }

    // 5
    // Static and Voyage Related Data
    public class AIVDMSentense
    {
        private const short length = 424;

        private uint pType = 5;
        private uint pRepeat = 0;

        public uint MMSI;
        public uint IMOShipID;
        public string CallSign;
        public string VesselName;
        public int ShipType = 0;
        public string Destination = "";

        public static AIVDMSentense FromAIS(byte[] unpackedBytes)
        {
            AIVDMSentense res = new AIVDMSentense();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if (res.pType != 5) return null;

            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2); // 
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            res.IMOShipID = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 40, 30);
            res.CallSign = AISTransCoder.GetAisString(unpackedBytes, 70, 42);
            res.VesselName = AISTransCoder.GetAisString(unpackedBytes, 112, 120);
            res.ShipType = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 232, 8);
            res.Destination = AISTransCoder.GetAisString(unpackedBytes, 302, 120);

            return res;
        }

        public static AIVDMSentense FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public static AIVDMSentense FromBuddie(APRSData.Buddie buddie)
        {
            AIVDMSentense res = new AIVDMSentense();
            res.CallSign = res.VesselName = buddie.name;
            res.Destination = DateTime.Now.ToString("HHmmss ddMMyy");
            res.ShipType = 0;
            res.MMSI = res.IMOShipID = APRSData.Buddie.MMSI(buddie.name);
            return res;
        }

        public byte[] ToAIS()
        {
            byte[] unpackedBytes = new byte[54];
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 38, 2, 0);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 40, 30, (int)IMOShipID);
            AISTransCoder.SetAisString(unpackedBytes, 70, 42, CallSign);
            AISTransCoder.SetAisString(unpackedBytes, 112, 120, VesselName);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 232, 8, (int)ShipType);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 240, 9, 4); //A
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 249, 9, 1); //B
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 258, 6, 1); //C
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 264, 6, 2); //D
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 270, 4, 1); //PostFix
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 274, 4, DateTime.UtcNow.Month);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 278, 5, DateTime.UtcNow.Day);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 283, 5, DateTime.UtcNow.Hour);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 288, 6, DateTime.UtcNow.Minute);
            AISTransCoder.SetAisString(unpackedBytes, 302, 120, Destination);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 422, 1, 0);
            return unpackedBytes;
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS());
        }

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }

    // 14
    // SafetyRelatedBroadcastMessage
    public class SafetyRelatedBroadcastMessage
    {
        private uint pType = 14;
        private uint pRepeat = 0;

        public string Message = "PING";
        public uint MMSI = 0;

        public SafetyRelatedBroadcastMessage() { }
        public SafetyRelatedBroadcastMessage(string Message) { this.Message = Message; }
        public SafetyRelatedBroadcastMessage(string Message, uint MMSI) { this.Message = Message; this.MMSI = MMSI; }

        public byte[] ToAIS(string text)
        {
            string sftv = text;
            byte[] unpackedBytes = new byte[5 + (int)(sftv.Length / 8.0 * 6.0 + 1)];
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI); //MMSI
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 38, 2, 0);
            AISTransCoder.SetAisString(unpackedBytes, 40, sftv.Length * 6, sftv);
            return unpackedBytes;
        }

        public static SafetyRelatedBroadcastMessage FromAIS(byte[] unpackedBytes)
        {
            SafetyRelatedBroadcastMessage res = new SafetyRelatedBroadcastMessage();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if (res.pType != 14) return res;

            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2);
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            int strlen = (int)((unpackedBytes.Length - 5 - 1) * 8.0 / 6.0);
            res.Message = AISTransCoder.GetAisString(unpackedBytes, 40, strlen * 6);
            
            return res;
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS(Message));
        }

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }

    // 18 -- Green
    // Standard Class B CS Position Report
    public class CNBBsentense
    {
        private const byte length = 168;

        private uint pType = 18;
        private uint pRepeat = 0;

        public uint MMSI;
        public uint SOG; // speed
        public bool Accuracy;
        public double Longitude;
        public double Latitude;
        public double COG = 0; // course
        public ushort HDG = 0; // heading
        private uint TimeStamp = 60;

        public static CNBBsentense FromAIS(byte[] unpackedBytes)
        {
            CNBBsentense res = new CNBBsentense();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if (res.pType != 18) return null;

            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2); // 
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            res.SOG = (uint)(AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 46, 10) / 10 * 1.852);
            res.Accuracy = (byte)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 56, 1) == 1 ? true : false;
            res.Longitude = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 57, 28) / 600000.0;
            res.Latitude = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 85, 27) / 600000.0;
            res.COG = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 112, 12) / 10.0;
            res.HDG = (ushort)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 124, 9);
            res.TimeStamp = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 133, 6);
            return res;
        }

        public static CNBBsentense FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public static CNBBsentense FromBuddie(APRSData.Buddie buddie)
        {
            CNBBsentense res = new CNBBsentense();
            res.Accuracy = buddie.PositionIsValid;
            res.COG = res.HDG = (ushort)buddie.speed;
            res.Latitude = buddie.lat;
            res.Longitude = buddie.lon;
            res.SOG = (uint)buddie.speed;
            res.MMSI = APRSData.Buddie.MMSI(buddie.name);
            return res;
        }

        public byte[] ToAIS()
        {
            byte[] unpackedBytes = new byte[21];
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType); // type
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 46, 10, (int)(SOG / 1.852 * 10)); // speed            
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 56, 1, Accuracy ? 1 : 0);
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 57, 28, (int)(Longitude * 600000));
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 85, 27, (int)(Latitude * 600000));
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 112, 12, (int)(COG * 10.0));
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 124, 9, HDG);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 133, 6, 60);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 142, 1, 1);
            return unpackedBytes;
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS());
        }

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }

    // 19 -- Green
    // Extended Class B CS Position Report
    public class CNBBEsentense
    {
        private const short length = 312;

        private uint pType = 19;             
        private uint pRepeat = 0;

        public uint MMSI;
        public uint SOG; // speed
        public bool Accuracy;
        public double Longitude;
        public double Latitude;
        public double COG = 0; // course
        public ushort HDG = 0; // heading
        private uint Timestamp = 60;
        public string VesselName;
        public int ShipType = 0;

        public static CNBBEsentense FromAIS(byte[] unpackedBytes)
        {
            CNBBEsentense res = new CNBBEsentense();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if (res.pType != 19) return null;

            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2); // 
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            res.SOG = (uint)(AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 46, 10) / 10 * 1.852);
            res.Accuracy = (byte)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 56, 1) == 1 ? true : false;
            res.Longitude = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 57, 28) / 600000.0;
            res.Latitude = AISTransCoder.GetBitsAsSignedInt(unpackedBytes, 85, 27) / 600000.0;
            res.COG = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 112, 12) / 10.0;
            res.HDG = (ushort)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 124, 9);
            res.Timestamp = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 133, 6);
            res.VesselName = AISTransCoder.GetAisString(unpackedBytes, 143, 120);
            res.ShipType = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 263, 8);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 271, 9, 4); // A
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 280, 9, 1); // B
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 289, 6, 1); // C
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 295, 6, 2); // D
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 301, 4, 1);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 306, 6, 1);
            return res;
        }

        public static CNBBEsentense FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public static CNBBEsentense FromBuddie(APRSData.Buddie buddie)
        {
            CNBBEsentense res = new CNBBEsentense();
            res.Accuracy = buddie.PositionIsValid;
            res.COG = res.HDG = (ushort)buddie.course;
            res.Latitude = buddie.lat;
            res.Longitude = buddie.lon;
            res.SOG = (uint)buddie.speed;
            res.VesselName = buddie.name;
            res.MMSI = APRSData.Buddie.MMSI(buddie.name);
            return res;
        }

        public byte[] ToAIS()
        {
            byte[] unpackedBytes = new byte[39];

            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType); // type
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 46, 10, (int)(SOG / 1.852 * 10)); // speed            
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 56, 1, Accuracy ? 1 : 0);
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 57, 28, (int)(Longitude * 600000));
            AISTransCoder.SetBitsAsSignedInt(unpackedBytes, 85, 27, (int)(Latitude * 600000));
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 112, 12, (int)(COG * 10.0));
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 124, 9, HDG);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 133, 6, 60);
            AISTransCoder.SetAisString(unpackedBytes, 143, 120, VesselName);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 263, 8, ShipType);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 301, 4, 1);
            return unpackedBytes;
        }

        public override string ToString()
        {
            return AISTransCoder.EnpackAisToString(ToAIS());
        }

        public string ToPacketFrame()
        {
            string s = this.ToString();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string Frame { get { return this.ToString(); } }
        public string PacketFrame { get { return this.ToPacketFrame(); } }
    }

    // 24
    // Static Data Report
    public class StaticDataReport
    {
        private const int length = 168;

        private uint pType = 24;
        private uint pRepeat = 0;

        public uint MMSI;
        public string VesselName;
        public int ShipType = 0;
        public uint IMOShipID;
        public string CallSign;

        public static StaticDataReport FromAIS(byte[] unpackedBytes)
        {
            StaticDataReport res = new StaticDataReport();
            res.pType = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 0, 6);
            if (res.pType != 24) return res;

            res.pRepeat = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 6, 2);
            res.MMSI = (uint)AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 8, 30);
            res.VesselName = AISTransCoder.GetAisString(unpackedBytes, 40, 120);
            res.ShipType = AISTransCoder.GetBitsAsUnsignedInt(unpackedBytes, 40, 8);
            res.CallSign = AISTransCoder.GetAisString(unpackedBytes, 90, 42);
            return res;
        }

        public static StaticDataReport FromAIS(string ais)
        {
            byte[] unp = AISTransCoder.UnpackAisEncoding(ais);
            return FromAIS(unp);
        }

        public static StaticDataReport FromBuddie(APRSData.Buddie buddie)
        {
            StaticDataReport res = new StaticDataReport();
            res.VesselName = res.CallSign = buddie.name;
            res.MMSI = res.IMOShipID = APRSData.Buddie.MMSI(buddie.name);
            return res;
        }

        public override string ToString()
        {
            return ToStringA();
        }

        public byte[] ToAISa()
        {
            byte[] unpackedBytes = new byte[21];
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, (int)pType);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, (int)pRepeat);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 38, 2, 0); // partA
            AISTransCoder.SetAisString(unpackedBytes, 40, 120, VesselName);
            return unpackedBytes;
        }

        public string ToStringA()
        {
            return AISTransCoder.EnpackAisToString(ToAISa());
        }

        public byte[] ToAISb()
        {
            byte[] unpackedBytes = new byte[21];
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 0, 6, 24);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 6, 2, 0);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 8, 30, (int)MMSI);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 38, 2, 1); // partB            
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 40, 8, (int)ShipType);
            AISTransCoder.SetAisString(unpackedBytes, 90, 42, CallSign);
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 132, 9, 4); // A
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 141, 9, 1); // B
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 150, 6, 1); // C
            AISTransCoder.SetBitsAsUnsignedInt(unpackedBytes, 156, 6, 2); // D
            return unpackedBytes;
        }

        public string ToStringB()
        {
            return AISTransCoder.EnpackAisToString(ToAISb());
        }

        public string ToPacketFrameA()
        {
            string s = this.ToStringA();
            s = "!AIVDM,1,1,,A," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }

        public string ToPacketFrameB()
        {
            string s = this.ToStringA();
            s = "!AIVDM,1,1,,B," + s + ",0";
            s += "*" + AISTransCoder.Checksum(s);
            return s;
        }
    }
}
