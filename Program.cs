namespace PacketSniffer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = Host.CreateApplicationBuilder(args);
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "PacketSnifferService";
            });
            builder.Services.AddHostedService<PcapAgent>();

            var host = builder.Build();
            host.Run();
        }
    }
}