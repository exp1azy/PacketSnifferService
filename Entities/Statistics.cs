namespace PacketSniffer.Entities
{
    internal class Statistics
    {
        public string IPAddress { get; set; }

        public string ProtocolToSniff { get; set; }

        public string ReceievedPackets { get; set; }

        public string DroppedPackets { get; set; }

        public string InterfaceDroppedPackets { get; set; }
    }
}
