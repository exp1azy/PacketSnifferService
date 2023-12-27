using SharpPcap.LibPcap;
using SharpPcap.Statistics;
using StackExchange.Redis;
using System.Net.Sockets;
using System.Net;
using SharpPcap;
using Newtonsoft.Json;
using PacketSniffer.Resources;
using System.Collections.Concurrent;

namespace PacketSniffer
{
    /// <summary>
    /// Класс-обработчик сетевого трафика.
    /// </summary>
    internal class PcapAgent : BackgroundService
    {
        private readonly IDatabase _db;
        private readonly ConnectionMultiplexer _connection;
        private readonly ILogger<PcapAgent> _logger;
        private readonly IConfiguration _config;
        private readonly int _maxQueueSize;

        private const string _rawPacketRedisKey = "raw_packets";
        private const string _statisticsRedisKey = "statistics";

        private IPAddress? _virtualIP;
        private ConcurrentQueue<StatisticsEventArgs> _statisticsQueue = new();
        private ConcurrentQueue<RawCapture> _rawPacketsQueue = new();

        /// <summary>
        /// Конструктор.
        /// </summary>
        /// <param name="logger">Логи.</param>
        /// <param name="config">Файл конфигурации.</param>
        public PcapAgent(ILogger<PcapAgent> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;

            while (true)
            {
                try
                {
                    _connection = ConnectionMultiplexer.Connect(_config["RedisConnection"]!);
                    _db = _connection.GetDatabase();
                    break;
                }
                catch
                {
                    _logger.LogError(Error.NoConnection);
                    Task.Delay(10000).Wait();
                }
            }

            if (int.TryParse(_config["MaxQueueSize"], out var maxQueueSize))
            {
                _maxQueueSize = maxQueueSize;
            }
            else
            {
                _logger.LogError(Error.FailedToReadQueuesSizeData);
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Входящий метод, получающий сетевые устройства и интерфейсы, по которым запускается прослушивание сетевого трафика.
        /// </summary>
        /// <param name="stoppingToken">Токен отмены.</param>
        /// <returns></returns>
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

            var networkConfig = _config.GetSection("Network");
            if (networkConfig == null || !networkConfig.GetChildren().Any())
            {
                _logger.LogError(Error.FailedToReadNetworkPrefixData);
                Environment.Exit(1);
            }

            int interfaceIndex = GetInterfaceIndex(devices, networkConfig["AdapterPrefix"]!);
            if (interfaceIndex == -1)
            {
                _logger.LogError(Error.NoSuchInterface, networkConfig["AdapterPrefix"]);
                Environment.Exit(1);
            }

            var localIPTask = ListenRequiredInterfaceAsync(devices, interfaceIndex, stoppingToken);

            while (_virtualIP == null)
            {
                try
                {
                    stoppingToken.ThrowIfCancellationRequested();

                    _virtualIP = GetIPs().FirstOrDefault(addr => addr.ToString().StartsWith(networkConfig["VirtualIpPrefix"]!));
                    await Task.Delay(2000);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            if (!stoppingToken.IsCancellationRequested)
            {
                interfaceIndex = GetInterfaceIndex(devices, networkConfig["VirtualAdapterPrefix"]!);
                if (interfaceIndex == -1)
                {
                    _logger.LogError(Error.NoSuchInterface, networkConfig["VirtualAdapterPrefix"]);
                    Environment.Exit(1);
                }

                var virtualIPTask = ListenRequiredInterfaceAsync(devices, interfaceIndex, stoppingToken);

                await Task.WhenAll(localIPTask, virtualIPTask);
            } 
            
            await _connection.CloseAsync();
        }

        /// <summary>
        /// Метод, запускающий в цикле таски, в которых происходит перехват пакетов, используя указанный протокол.
        /// </summary>
        /// <param name="devices">Устройства.</param>
        /// <param name="interfaceToSniff">Интерфейс, с которого происходит захват пакетов.</param>
        /// <param name="stoppingToken">Токен отмены.</param>
        /// <returns></returns>
        private async Task ListenRequiredInterfaceAsync(LibPcapLiveDeviceList devices, int interfaceToSniff, CancellationToken stoppingToken)
        {
            var tasks = new List<Task>();

            var filters = _config.GetSection("Filters").Get<List<string>>();
            if (filters == null || filters.Count == 0)
            {
                _logger.LogError(Error.FailedToReadProtocolsToCapture);
                Environment.Exit(1);
            }

            foreach (var filter in filters)
            {
                tasks.Add(Task.Run(() =>
                StartCaptureUsingRequiredProtocolAsync(devices, interfaceToSniff, filter, stoppingToken)));
            }

            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Метод, прослушивающий указанный интерфейс и собирающий как сами пакеты, так и статистику по ним.
        /// </summary>
        /// <param name="devices">Устройства.</param>
        /// <param name="interfaceToSniff">Интерфейс, с которого происходит захват пакетов.</param>
        /// <param name="filter">Протокол.</param>
        /// <param name="stoppingToken">Токен отмены.</param>
        /// <returns></returns>
        private async Task StartCaptureUsingRequiredProtocolAsync(LibPcapLiveDeviceList devices, int interfaceToSniff, string filter, CancellationToken stoppingToken)
        {
            using var statisticsDevice = new StatisticsDevice(devices[interfaceToSniff].Interface);
            using var device = devices[interfaceToSniff];

            statisticsDevice.OnPcapStatistics += Device_OnPcapStatistics;
            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);
                         
            statisticsDevice.Open();
            device.Open();

            statisticsDevice.Filter = filter;
            device.Filter = filter;

            statisticsDevice.StartCapture();
            device.StartCapture();

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(2000); 
            
            statisticsDevice.StopCapture();
            device.StopCapture();
        }

        /// <summary>
        /// Метод-обработчик события OnPacketArrival.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();

            if (_rawPacketsQueue.Count < _maxQueueSize)           
                _rawPacketsQueue.Enqueue(rawPacket);               
            else
                HandleRawPacketsQueueAsync().Wait();                        
        }

        /// <summary>
        /// Метод-обработчик события OnPcapStatistics.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Device_OnPcapStatistics(object sender, StatisticsEventArgs e)
        {          
            if (_statisticsQueue.Count < _maxQueueSize)          
                _statisticsQueue.Enqueue(e);          
            else          
                HandleStatisticsQueueAsync().Wait();           
        }

        /// <summary>
        /// Метод, необходимый для массовой загрузки в поток Redis из очереди _rawPacketsQueue.
        /// </summary>
        /// <returns></returns>
        private async Task HandleRawPacketsQueueAsync()
        {
            try
            {
                string serializedPacket = JsonConvert.SerializeObject(_rawPacketsQueue);
                await _db.StreamAddAsync(Environment.MachineName, [
                    new NameValueEntry(_rawPacketRedisKey, serializedPacket)
                ]);

                _rawPacketsQueue.Clear();
            }
            catch (Exception ex)
            {
                _logger.LogError(Error.Unexpected, ex.Message);
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Метод, необходимый для массовой загрузки в поток Redis из очереди _statisticsQueue.
        /// </summary>
        /// <returns></returns>
        private async Task HandleStatisticsQueueAsync()
        {
            try
            {
                string serializedStatistics = JsonConvert.SerializeObject(_statisticsQueue);
                await _db.StreamAddAsync(Environment.MachineName, [
                    new NameValueEntry(_statisticsRedisKey, serializedStatistics)
                ]);

                _statisticsQueue.Clear();
            }
            catch (Exception ex)
            {
                _logger.LogError(Error.Unexpected, ex.Message);
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Метод, необходимый для получения индекса запрашиваемого устройства.
        /// </summary>
        /// <param name="devices">Устройства.</param>
        /// <param name="interfaceToSniff">Интерфейс, необходимый для захвата пакетов.</param>
        /// <returns>Индекс устройства.</returns>
        private int GetInterfaceIndex(LibPcapLiveDeviceList devices, string interfaceToSniff) =>
            devices.IndexOf(devices.First(d => d.Description.Contains(interfaceToSniff)));

        /// <summary>
        /// Метод, необходимый для получения IPv4-адресов устройств данной машины.
        /// </summary>
        /// <returns>IPv4-адреса.</returns>
        private IEnumerable<IPAddress> GetIPs() =>
            Dns.GetHostAddresses(Dns.GetHostName()).Where(addr => addr.AddressFamily == AddressFamily.InterNetwork);
    }
}