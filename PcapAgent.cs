using SharpPcap.LibPcap;
using SharpPcap.Statistics;
using StackExchange.Redis;
using System.Net.Sockets;
using System.Net;
using SharpPcap;
using PacketSniffer.Entities;
using Newtonsoft.Json;
using PacketSniffer.Resources;

namespace PacketSniffer
{
    internal sealed class PcapAgent : BackgroundService
    {
        private readonly IDatabase _redis;
        private readonly ILogger<PcapAgent> _logger;
        private readonly IConfiguration _config;

        private IPAddress? _localIP;
        private IPAddress? _virtualIP;

        private const string _networkAdapterPrefix = "Realtek";
        private const string _virtualNetworkAdapterPrefix = "TAP-Windows";
        private const string _localPrefix = "192.168";
        private const string _virtualPrefix = "10";

        public PcapAgent(ILogger<PcapAgent> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;

            while (true)
            {
                try
                {
                    var db = ConnectionMultiplexer.Connect(_config["RedisConnection"]!);
                    _redis = db.GetDatabase();
                    break;
                }
                catch
                {
                    _logger.LogError(Error.NoConnectionToRedis);
                    Task.Delay(10000).Wait();
                }
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var os = Environment.OSVersion;
            if (os.Platform != PlatformID.Win32NT)
            {
                _logger.LogError(Error.UnsupportedOS);
                Environment.Exit(1);
            }

            var devices = LibPcapLiveDeviceList.Instance;
            if (devices.Count < 1)
            {
                _logger.LogError(Error.NoDevicesWereFound);
                Environment.Exit(1);
            }

            _localIP = GetIPs().FirstOrDefault(addr => addr.ToString().StartsWith(_localPrefix));
            _virtualIP = GetIPs().FirstOrDefault(addr => addr.ToString().StartsWith(_virtualPrefix));

            int interfaceIndex = GetInterfaceIndex(devices, _networkAdapterPrefix);
            if (interfaceIndex == -1)
            {
                _logger.LogError(Error.NoInterfacesWereFound);
                Environment.Exit(1);
            }

            var localIPTask = ListenRequiredInterfaceAsync(devices, interfaceIndex, stoppingToken);

            while (_virtualIP == null || !stoppingToken.IsCancellationRequested)
            {
                _virtualIP = GetIPs().FirstOrDefault(addr => addr.ToString().StartsWith(_virtualPrefix));
                await Task.Delay(10000);
            }

            if (!stoppingToken.IsCancellationRequested)
            {
                interfaceIndex = GetInterfaceIndex(devices, _virtualNetworkAdapterPrefix);
                if (interfaceIndex == -1)
                {
                    _logger.LogError(Error.NoInterfacesWereFound);
                    Environment.Exit(1);
                }

                var virtualIPTask = ListenRequiredInterfaceAsync(devices, interfaceIndex, stoppingToken);

                await Task.WhenAll(localIPTask, virtualIPTask);
            }
        }

        private async Task ListenRequiredInterfaceAsync(LibPcapLiveDeviceList devices, int interfaceToSniff, CancellationToken stoppingToken)
        {
            var tcpTask = Task.Run(() => 
                StartCaptureUsingRequiredProtocolAsync(devices, interfaceToSniff, "tcp", stoppingToken));
            var udpTask = Task.Run(() => 
                StartCaptureUsingRequiredProtocolAsync(devices, interfaceToSniff, "udp", stoppingToken));

            await Task.WhenAll(tcpTask, udpTask);
        }

        private async Task StartCaptureUsingRequiredProtocolAsync(LibPcapLiveDeviceList devices, int interfaceToSniff, string filter, CancellationToken stoppingToken)
        {
            using (var device = new StatisticsDevice(devices[interfaceToSniff].Interface))
            {
                device.OnPcapStatistics += OnPcapStatistics;
                device.Open();

                device.Filter = filter;
                device.StartCapture();

                var ipAddress = device.Description.StartsWith(_networkAdapterPrefix) ? _localIP : _virtualIP;

                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(10000);

                    var statistics = new Statistics
                    {
                        IPAddress = ipAddress.ToString(),
                        ProtocolToSniff = filter,
                        ReceievedPackets = device.Statistics.ReceivedPackets.ToString(),
                        DroppedPackets = device.Statistics.DroppedPackets.ToString(),
                        InterfaceDroppedPackets = device.Statistics.InterfaceDroppedPackets.ToString()
                    };
                    string serializedStatistics = JsonConvert.SerializeObject(statistics);

                    await _redis.StreamAddAsync(Environment.MachineName,
                    [
                        new NameValueEntry("statistics", serializedStatistics)
                    ]);
                }
            }
        }

        private void OnPcapStatistics(object sender, StatisticsEventArgs e)
        {
            var bps = e.ReceivedBytes * 8;
            var pps = e.ReceivedPackets;
            var ts = e.Timeval.Date.ToLocalTime();
            var ipAddress = e.Device.Description.StartsWith(_networkAdapterPrefix) ? _localIP : _virtualIP;

            var pcapMetrics = new PacketMetrics
            {
                IPAddress = ipAddress.ToString(),
                Ts = ts,
                Bps = bps,
                Pps = pps,
                Filter = e.Device.Filter
            };
            string serializedPcapMetrics = JsonConvert.SerializeObject(pcapMetrics);

            _redis.StreamAddAsync(Environment.MachineName,
            [
                new NameValueEntry("metrics", serializedPcapMetrics)
            ]).Wait();
        }

        private int GetInterfaceIndex(LibPcapLiveDeviceList devices, string interfaceToSniff) =>
            devices.IndexOf(devices.First(d => d.Description.Contains(interfaceToSniff)));

        private IEnumerable<IPAddress> GetIPs() =>
            Dns.GetHostAddresses(Dns.GetHostName()).Where(addr => addr.AddressFamily == AddressFamily.InterNetwork);
    }
}

