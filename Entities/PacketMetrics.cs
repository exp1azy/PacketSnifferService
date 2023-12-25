namespace PacketSniffer.Entities
{
    internal class PacketMetrics
    {
        public string IPAddress { get; set; }

        public DateTime Ts { get; set; }

        public long Bps { get; set; }

        public long Pps { get; set; }

        public string Filter { get; set; }
    }
}
