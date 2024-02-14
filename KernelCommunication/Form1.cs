using System;
using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace KernelCommunication
{
    public partial class Form1 : Form
    {
        private readonly PipeSecurity pipeSecurity;
        private readonly string pipeName;

        public Form1()
        {
            InitializeComponent();

            pipeSecurity = new PipeSecurity();
            pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, System.Security.AccessControl.AccessControlType.Allow));

            pipeName = "MyServicePipeTest";
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Task.Run(() =>
            {
                while (true)
                {
                    GetMessageAndResponse();
                }
            });
        }

        private void GetMessageAndResponse()
        {
            try
            {
                using (var pipeServer = new NamedPipeServerStream(pipeName,
                   PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 1024, 1024, pipeSecurity))
                {
                    pipeServer.WaitForConnection();

                    var readBuffer = new byte[2048];
                    pipeServer.Read(readBuffer, 0, readBuffer.Length);

                    var message = Encoding.UTF8.GetString(readBuffer).TrimEnd((char)0).Trim();

                    Invoke((MethodInvoker)delegate
                    {
                        textBox1.Text = message;
                    });

                    pipeServer.Flush();
                    pipeServer.Close();
                }
            }
            catch (SocketException) { }
            catch (IOException) { }
            catch (Exception) { }
        }
    }
}
