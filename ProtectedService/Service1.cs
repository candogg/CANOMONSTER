using System;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;

namespace ProtectedService
{
    public partial class Service1 : ServiceBase
    {
        private readonly CancellationTokenSource cancellationToken;
        private Task protectionTask;

        public Service1()
        {
            InitializeComponent();

            cancellationToken = new CancellationTokenSource();
        }

        protected override void OnStart(string[] args)
        {
            protectionTask =  SelfProtectService();
        }

        protected override void OnStop()
        {
            cancellationToken.Cancel(false);

            try
            {
                Task.WhenAll(new Task[] { protectionTask }.Where(x => x != null)).GetAwaiter().GetResult();
            }
            catch (TaskCanceledException)
            { }
        }

        private Task SelfProtectService()
        {
            return Task.Run(async () =>
            {
                try
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        var isCritical = true;
                        var fileContent = string.Empty;

                        if (File.Exists("testparam.txt") && !string.IsNullOrEmpty(fileContent = File.ReadAllText("testparam.txt").Trim()))
                        {
                            isCritical = fileContent == "true";
                        }

                        if (!Services.CheckCriticalModeInternal() && isCritical)
                        {
                            Services.EnterCriticalModeInternal();
                        }
                        else
                        {
                            Services.ExitCriticalModeInternal();
                        }

                        await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken.Token);
                    }
                }
                catch (TaskCanceledException)
                { }
            }, cancellationToken.Token);
        }
    }
}
